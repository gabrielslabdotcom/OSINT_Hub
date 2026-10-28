"""Launch uvicorn for `osint-hub web`."""

from __future__ import annotations

import os
import threading
import webbrowser

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def run_server(
    host: str = "127.0.0.1",
    port: int = 8741,
    *,
    open_browser: bool = False,
    allow_remote: bool = False,
) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            "Web extras are not installed. Run: pip install -e '.[web]'"
        ) from exc

    if allow_remote:
        os.environ["OSINT_HUB_ALLOW_REMOTE"] = "1"
    elif host not in LOOPBACK_HOSTS:
        raise RuntimeError(
            "Refusing to bind beyond localhost. Pass --allow-remote if you intend to expose this console."
        )

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
