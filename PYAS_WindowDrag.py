import logging


def enable_native_drag(window):
    control = window.native.webview
    logger = logging.getLogger("PYAS.UI")

    def configure(sender, event):
        if event is not None and not event.IsSuccess:
            return
        try:
            sender.CoreWebView2.Settings.IsNonClientRegionSupportEnabled = True
            logger.info("WebView2 native window dragging enabled")
        except Exception:
            logger.exception("Could not enable WebView2 native window dragging")

    if control.CoreWebView2 is not None:
        configure(control, None)
    else:
        control.CoreWebView2InitializationCompleted += configure
