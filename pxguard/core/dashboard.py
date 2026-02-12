"""
PXGuard - Live CLI dashboard for file integrity monitoring.

Displays real-time summary of scan results and overall status.
Uses ANSI escape sequences for in-place refresh. Extensible for
future metrics and configurable refresh.
"""

import sys
from typing import Literal

# ANSI escape sequences
_CLEAR_SCREEN = "\033[2J"
_CURSOR_HOME = "\033[H"
_RESET = "\033[0m"
# Status colors
_COLOR_OK = "\033[32m"       # Green
_COLOR_WARNING = "\033[33m"  # Yellow
_COLOR_CRITICAL = "\033[31m" # Red

Status = Literal["OK", "WARNING", "CRITICAL"]


class Dashboard:
    """
    Live CLI dashboard for FIM monitor. Refreshes in place after each scan.
    """

    def __init__(self, stream=None):
        self._stream = stream or sys.stderr
        self._scanned: int = 0
        self._modified: int = 0
        self._deleted: int = 0
        self._created: int = 0
        self._status: Status = "OK"
        self._iteration: int = 0

    def update(
        self,
        scanned: int,
        modified: int,
        deleted: int,
        created: int,
        status: Status,
    ) -> None:
        """Update dashboard metrics and iteration count."""
        self._scanned = scanned
        self._modified = modified
        self._deleted = deleted
        self._created = created
        self._status = status
        self._iteration += 1

    def _status_color(self) -> str:
        if self._status == "CRITICAL":
            return _COLOR_CRITICAL
        if self._status == "WARNING":
            return _COLOR_WARNING
        return _COLOR_OK

    def render(self) -> None:
        """Clear terminal area and redraw dashboard with current metrics."""
        lines = [
            "",
            "==============================",
            " FILE INTEGRITY MONITOR",
            "==============================",
            f" Scanned files: {self._scanned}",
            f" Modified: {self._modified}",
            f" Deleted: {self._deleted}",
            f" Created: {self._created}",
            f" Status: {self._status_color()}{self._status}{_RESET}",
            "==============================",
            "",
        ]
        block = "\n".join(lines)
        try:
            if self._stream.isatty():
                self._stream.write(_CLEAR_SCREEN + _CURSOR_HOME + block)
            else:
                self._stream.write(block)
            self._stream.flush()
        except (OSError, UnicodeEncodeError):
            pass
