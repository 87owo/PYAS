import os, sys, ctypes, threading
import webview, platform

from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

class WindowAPI:
    def __init__(self):
        self._window = None

    def set_window(self, window):
        self._window = window

    def minimize(self):
        if self._window:
            self._window.minimize()

    def close(self):
        if self._window:
            self._window.destroy()

def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

class NoCacheRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=get_base_path(), **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.path = '/templates/index.html'
        return super().do_GET()

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Expires", "0")
        self.send_header("Pragma", "no-cache")
        super().end_headers()

def start_api():
    TCPServer.allow_reuse_address = True
    with TCPServer(("127.0.0.1", 8000), NoCacheRequestHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    if platform.system() == "Windows":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    api_thread = threading.Thread(target=start_api, daemon=True)
    api_thread.start()

    js_api = WindowAPI()
    
    window = webview.create_window(
        title="PYAS Security",
        url="http://127.0.0.1:8000/",
        width=950,
        height=650,
        frameless=True,
        easy_drag=False,
        js_api=js_api,
        background_color='#e0e0e0'
    )
    
    js_api.set_window(window)
    webview.start()
