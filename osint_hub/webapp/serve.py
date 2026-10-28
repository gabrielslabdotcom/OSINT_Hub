"""Launch uvicorn for `osint-hub web`."""

from __future__ import annotations

import threading
import webbrowser


def run_server(host: str = "127.0.0.1", port: int = 8741, *, open_browser: bool = False) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            "Web extras are not installed. Run: pip install -e '.[web]'"
        ) from exc

    url = f"http://{host}:{port}"
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    uvicorn.run(
        "osint_hub.webapp.app:app",
        host=host,
        port=port,
        log_level="info",
        reload=False,
    )
