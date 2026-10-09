import logging
import atexit
import json
import os
import sys
import tempfile
import threading
import time
import uuid
import weakref
from collections import OrderedDict
from PYAS_Storage import atomic_write_json
from PYAS_Version import VERSION

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
MAX_LOG_ENTRIES = 10000
BACKGROUND_DIAGNOSTIC_ACTIONS = frozenset(
    {
        "Scan Engine",
        "Scan Deferred",
        "Cloud API",
        "perform_cloud_scan",
        "repair_system_image",
        "repair_system_wallpaper",
        "protect_system_thread",
        "show_notification",
    }
)

_lock = threading.Lock()
_recent = OrderedDict()
_local = threading.local()


def create_log_entry(
    level,
    action,
    detail=None,
    code=None,
    pid=None,
    file_hash=None,
    source=None,
    target=None,
    operate=None,
    success=True,
    timestamp=None,
    ui_visible=None,
):
    timestamp = time.time() if timestamp is None else timestamp

    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
        "version": VERSION,
        "level": level,
        "action": action,
        "detail": detail,
        "code": code,
        "pid": pid,
        "hash": file_hash,
        "source": source,
        "target": target,
        "operate": operate,
        "success": success,
    }

    if ui_visible is not None:
        entry["ui_visible"] = bool(ui_visible)

    return entry


def is_ui_log_entry(entry):
    visibility = entry.get("ui_visible")

    if isinstance(visibility, bool):
        return visibility

    level = entry.get("level", "")

    if level in {"ERROR", "CRITICAL", "FATAL", "BLOCK", "SCAN"}:
        return True

    action = entry.get("action")

    if action in {"Exception", "Diagnostic"}:
        return False

    return not (
        level in {"WARN", "WARNING"}
        and entry.get("operate") is not True
        and action in BACKGROUND_DIAGNOSTIC_ACTIONS
    )


def report_log_path():
    for handler in logging.getLogger("PYAS").handlers:
        if isinstance(handler, ReportHandler):
            return handler.baseFilename

    return os.path.join(os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData"), "PYAS", "Report.json")


class ReportHandler(logging.Handler):
    def __init__(self, path):
        super().__init__()
        self.baseFilename = os.path.abspath(path)
        self.pending = []
        self.pending_lock = threading.RLock()
        self.application = None
        self.local = threading.local()
        self.setFormatter(logging.Formatter("%(message)s"))

    def handle(self, record):
        accepted = self.filter(record)

        if accepted:
            self.emit(record)

        return accepted

    def emit(self, record):
        if self._closed or getattr(self.local, "busy", False):
            return

        self.local.busy = True

        try:
            entry = create_log_entry(
                "WARN" if record.levelno == logging.WARNING else record.levelname,
                "Exception" if record.exc_info else "Diagnostic",
                detail=self.format(record),
                pid=record.process,
                source=record.name,
                success=record.levelno < logging.WARNING,
                timestamp=record.created,
                ui_visible=record.levelno >= logging.ERROR,
            )
            application = self.application() if self.application else None

            if application is not None:
                application._append_log_entry(entry)

                if record.levelno >= logging.ERROR:
                    application.flush_logs_now()
            else:
                with self.pending_lock:
                    application = self.application() if self.application else None

                    if application is None:
                        self.pending.append(entry)
                        del self.pending[:-MAX_LOG_ENTRIES]

                        if record.levelno >= logging.ERROR:
                            self._flush_pending()

                if application is not None:
                    application._append_log_entry(entry)
        except Exception:
            pass
        finally:
            self.local.busy = False

    def _flush_pending(self):
        if not self.pending:
            return True

        try:
            existing = []

            if os.path.exists(self.baseFilename):
                with open(self.baseFilename, "r", encoding="utf-8") as stream:
                    existing = json.load(stream)

                if not isinstance(existing, list):
                    return False

            identifiers = {entry.get("id") for entry in existing if isinstance(entry, dict)}
            merged = existing + [entry for entry in self.pending if entry["id"] not in identifiers]
            atomic_write_json(self.baseFilename, merged[-MAX_LOG_ENTRIES:])
            return True
        except Exception:
            return False

    def flush(self):
        if self._closed or getattr(self.local, "busy", False):
            return

        self.local.busy = True

        try:
            application = self.application() if self.application else None

            if application is not None:
                application.flush_logs_now()
            else:
                with self.pending_lock:
                    self._flush_pending()
        except Exception:
            pass
        finally:
            self.local.busy = False

    def bind(self, application):
        with application.lock_logs:
            with self.pending_lock:
                identifiers = {entry.get("id") for entry in application.logs_data}

                for entry in self.pending:
                    if entry["id"] not in identifiers:
                        application._append_log_entry(entry)

                self.pending.clear()
                self.application = weakref.ref(application)


def configure_report_logging():
    logger = logging.getLogger("PYAS")

    for handler in logger.handlers:
        if isinstance(handler, ReportHandler):
            return handler.baseFilename

    directories = [os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData"), tempfile.gettempdir()]

    for directory in directories:
        try:
            path = os.path.join(directory, "PYAS", "Report.json")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            descriptor, probe = tempfile.mkstemp(prefix=".pyas-log-", dir=os.path.dirname(path))
            os.close(descriptor)
            os.unlink(probe)
            handler = ReportHandler(path)

            for name in ("PYAS", "pywebview"):
                target = logging.getLogger(name)
                target.setLevel(logging.DEBUG)
                target.addHandler(handler)
                target.propagate = False

            atexit.register(handler.flush)
            return handler.baseFilename
        except OSError:
            continue

    logger.addHandler(logging.NullHandler())
    return None


def bind_report_logging(application):
    for handler in logging.getLogger("PYAS").handlers:
        if isinstance(handler, ReportHandler):
            handler.bind(application)


def log_exception(context, level=logging.WARNING):
    exc_info = sys.exc_info()

    if exc_info[0] is None:
        return

    _local.exceptions = getattr(_local, "exceptions", 0) + 1
    key = (context, exc_info[0])
    now = time.monotonic()

    try:
        with _lock:
            previous, suppressed = _recent.pop(key, (float("-inf"), 0))

            if now - previous < 30:
                _recent[key] = (previous, suppressed + 1)
                return

            _recent[key] = (now, 0)

            while len(_recent) > 128:
                _recent.popitem(last=False)

        logging.getLogger("PYAS.Exception").log(
            level, "context=%s; suppressed=%d", context, suppressed, exc_info=exc_info
        )
    except Exception:
        return


def observe_future(future, context):
    def completed(result):
        if result.cancelled():
            return

        try:
            result.result()
        except Exception:
            log_exception(context)

    future.add_done_callback(completed)
    return future


def exception_sequence():
    return getattr(_local, "exceptions", 0)
