"""Console entrypoint — delegates to the real `avmp.console.Console` / API.

    python services/console/main.py           # start read-only API (127.0.0.1:8443)
    python -m avmp serve --port 8443           # equivalent
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.api import serve  # noqa: E402
from avmp.console import Console  # noqa: E402

__all__ = ["Console"]


def main() -> int:
    console = Console()
    httpd = serve(console, host="127.0.0.1", port=8443)
    print("SentinelFix Console API on http://127.0.0.1:8443 (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
