from PYAS_Diagnostics import log_exception
import ctypes
import importlib.metadata
import logging
import os
import platform
import subprocess
import sys
import tempfile
import threading
import uuid
from PYAS_Diagnostics import configure_report_logging


def configure_startup_logging():
    return configure_report_logging()


def bootstrap_startup():
    log_path = configure_startup_logging()
    logger = logging.getLogger("PYAS.Startup")

    for stream in ("stdout", "stderr"):
        if getattr(sys, stream) is None:
            setattr(sys, stream, open(os.devnull, "w"))

    def exception_hook(exc_type, exc_value, traceback):
        logger.critical("Unhandled startup exception", exc_info=(exc_type, exc_value, traceback))

        if not any(
            arg in sys.argv
            for arg in ("-hide", "-h", "-quit", "-driver-unload", "-driver-uninstall")
        ):
            try:
                ctypes.windll.user32.MessageBoxW(
                    None,
                    f"PYAS failed to start.\n\n{exc_value}\n\nDiagnostic log: {log_path or 'unavailable'}",
                    "PYAS Security",
                    0x10,
                )
            except Exception:
                logger.exception("Could not display startup error")

    sys.excepthook = exception_hook
    threading.excepthook = lambda args: logger.error(
        "Unhandled thread exception: %s",
        args.thread.name,
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )
    logger.info(
        "Starting PYAS; Python=%s; platform=%s; frozen=%s; recovery=%s",
        sys.version.split()[0],
        platform.platform(),
        getattr(sys, "frozen", False),
        os.environ.get("PYAS_WEBVIEW_RECOVERY", "0"),
    )

    for package in ("pywebview", "pythonnet", "pyinstaller"):
        try:
            logger.info("Dependency %s=%s", package, importlib.metadata.version(package))
        except importlib.metadata.PackageNotFoundError:
            logger.info("Dependency metadata unavailable: %s", package)

    return log_path


def prepare_webview_profile(preferred_path):
    logger = logging.getLogger("PYAS.Startup")
    candidates = [preferred_path, os.path.join(tempfile.gettempdir(), "PYAS", "WebView2")]

    for path in dict.fromkeys(candidates):
        try:
            os.makedirs(path, exist_ok=True)

            with tempfile.TemporaryFile(dir=path) as probe:
                probe.write(b"PYAS")
                probe.flush()
                probe.seek(0)

                if probe.read() != b"PYAS":
                    raise OSError("Profile readback failed")

            logger.info("WebView2 profile ready: %s", path)
            return path
        except OSError:
            logger.exception("WebView2 profile is not writable: %s", path)

    raise OSError("No writable WebView2 user data folder is available")


def check_webview_dependencies(webview):
    from webview.util import interop_dll_path
    import sysconfig

    logger = logging.getLogger("PYAS.Startup")
    architecture = (
        "win-x86"
        if ctypes.sizeof(ctypes.c_void_p) == 4
        else ("win-arm64" if "arm64" in sysconfig.get_platform().lower() else "win-x64")
    )
    loader_directory = interop_dll_path(architecture)
    loader_path = os.path.join(loader_directory, "WebView2Loader.dll")
    loader = ctypes.WinDLL(loader_path)
    get_version = loader.GetAvailableCoreWebView2BrowserVersionString
    get_version.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    get_version.restype = ctypes.c_long
    version_pointer = ctypes.c_void_p()
    runtime_path = webview.settings.get("WEBVIEW2_RUNTIME_PATH") or None
    result = get_version(runtime_path, ctypes.byref(version_pointer))

    try:
        if result < 0 or not version_pointer.value:
            raise RuntimeError(
                f"WebView2 Runtime detection failed: HRESULT 0x{result & 0xFFFFFFFF:08X}"
            )

        version = ctypes.wstring_at(version_pointer)
        logger.info("WebView2 Runtime=%s; loader=%s", version, loader_path)
    finally:
        if version_pointer.value:
            ole32 = ctypes.WinDLL("ole32")
            ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
            ole32.CoTaskMemFree.restype = None
            ole32.CoTaskMemFree(version_pointer)

    os.environ["PATH"] = loader_directory + os.pathsep + os.environ.get("PATH", "")
    import clr

    clr.AddReference("System.Windows.Forms")

    for name in ("Microsoft.Web.WebView2.Core.dll", "Microsoft.Web.WebView2.WinForms.dll"):
        dll_path = interop_dll_path(name)
        clr.AddReference(dll_path)
        logger.info("WebView2 managed dependency loaded: %s", dll_path)

    return version


def wait_for_recovery_parent():
    parent = os.environ.pop("PYAS_WEBVIEW_RECOVERY_PARENT", None)

    if not parent:
        return

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(0x00100000, False, int(parent))

    if handle:
        try:
            if kernel32.WaitForSingleObject(handle, 10000) == 0x102:
                raise RuntimeError("Previous PYAS instance did not exit for WebView2 recovery")
        finally:
            kernel32.CloseHandle(handle)


def restart_with_new_webview_profile(profile_path, script_path):
    logger = logging.getLogger("PYAS.Startup")

    if os.environ.get("PYAS_WEBVIEW_RECOVERY") == "1":
        return False

    try:
        recovery_path = prepare_webview_profile(profile_path + "-Recovery-" + uuid.uuid4().hex)
        environment = os.environ.copy()
        environment.update(
            {
                "PYAS_WEBVIEW_RECOVERY": "1",
                "PYAS_WEBVIEW_PROFILE": recovery_path,
                "PYAS_WEBVIEW_RECOVERY_PARENT": str(os.getpid()),
                "PYINSTALLER_RESET_ENVIRONMENT": "1",
            }
        )
        command = [sys.executable]

        if not getattr(sys, "frozen", False):
            command.append(os.path.abspath(script_path))

        command.extend(sys.argv[1:])
        working_directory = (
            os.path.dirname(sys.executable)
            if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(script_path))
        )
        subprocess.Popen(
            command,
            env=environment,
            cwd=working_directory,
            creationflags=0x08000000,
            close_fds=True,
        )
        logger.warning("Restarting once with a new WebView2 profile: %s", recovery_path)
        return True
    except Exception:
        logger.exception("Could not restart for WebView2 profile recovery")
        return False
