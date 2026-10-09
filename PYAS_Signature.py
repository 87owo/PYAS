from PYAS_Diagnostics import log_exception
import os
import ctypes
import ctypes.wintypes
from PYAS_WinAPI import GUID, WINTRUST_DATA, WINTRUST_DATA_UNION, WINTRUST_FILE_INFO


class SignatureScanner:
    def __init__(self):
        self.verify = GUID(
            0x00AAC56B,
            0xCD44,
            0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
        )

    def init_windll(self, path):
        for name in path:
            try:
                setattr(self, name.lower(), ctypes.WinDLL(name, use_last_error=True))
            except Exception:
                log_exception("PYAS_Signature.SignatureScanner.init_windll:14")
                pass

        try:
            self.WinVerifyTrust = self.wintrust.WinVerifyTrust
            self.WinVerifyTrust.restype = ctypes.wintypes.LONG
            self.WinVerifyTrust.argtypes = [
                ctypes.wintypes.HWND,
                ctypes.POINTER(GUID),
                ctypes.c_void_p,
            ]
        except Exception:
            log_exception("PYAS_Signature.SignatureScanner.init_windll:21")
            pass

    def sign_verify(self, file_path):
        if os.name != "nt":
            return False

        try:
            fi = WINTRUST_FILE_INFO()
            fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            fi.pcwszFilePath = os.path.abspath(file_path)
            fi.hFile = None
            fi.pgKnownSubject = None

            wt_union = WINTRUST_DATA_UNION()
            wt_union.pFile = ctypes.pointer(fi)

            td = WINTRUST_DATA()
            td.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            td.pPolicyCallbackData = None
            td.pSIPClientData = None
            td.dwUIChoice = 2
            td.fdwRevocationChecks = 0
            td.dwUnionChoice = 1
            td.u = wt_union
            td.dwStateAction = 0
            td.hWVTStateData = None
            td.pwszURLReference = None
            td.dwProvFlags = 0
            td.dwUIContext = 0
            td.pSignatureSettings = None

            return self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(td)) == 0
        except Exception:
            log_exception("PYAS_Signature.SignatureScanner.sign_verify:55")
            return False
