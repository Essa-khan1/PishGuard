"""
PhishGuard - desktop launcher.

Runs the Flask server in a background thread and shows it in a native window
(pywebview) so it feels like an installed program. build.bat packages this
file into PhishGuard.exe.
"""
import threading
import time
import urllib.request

import webview

from app import app as flask_app

HOST, PORT = "127.0.0.1", 5000


def run_server():
    # reloader must be off: it spawns a 2nd process, which breaks a one-file .exe
    flask_app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


def wait_until_up(timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(f"http://{HOST}:{PORT}/", timeout=1)
            return
        except Exception:
            time.sleep(0.2)


def main():
    threading.Thread(target=run_server, daemon=True).start()
    wait_until_up()
    webview.create_window("PhishGuard - Phishing URL Detector", f"http://{HOST}:{PORT}",
                          width=1280, height=820, min_size=(1000, 650))
    webview.start()


if __name__ == "__main__":
    main()
