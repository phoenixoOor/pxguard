"""
PXGuard - Alert management and structured logging.

Uses colorama for cross-platform (Linux/Windows) colored console alerts.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

from pxguard.core.models import FIMEvent, Severity

logger = logging.getLogger(__name__)

# Lazy init of colorama (once per process)
_colorama_init_done = False


def _ensure_colorama() -> None:
    global _colorama_init_done
    if not _colorama_init_done:
        try:
            import colorama
            colorama.init(autoreset=True)
            _colorama_init_done = True
        except ImportError:
            _colorama_init_done = True  # avoid retry


def colored_alert(message: str, level: str) -> None:
    """
    Print an alert message in color to stderr. Safe on Linux and Windows.

    level: "CRITICAL" (red), "WARNING" (yellow), "INFO" or "OK" (green).
    """
    _ensure_colorama()
    try:
        from colorama import Fore
        level_upper = level.upper()
        if level_upper == "CRITICAL":
            prefix = Fore.RED
        elif level_upper == "WARNING":
            prefix = Fore.YELLOW
        else:
            prefix = Fore.GREEN  # INFO, OK, or default
        print(f"{prefix}{message}", file=sys.stderr)
    except ImportError:
        print(message, file=sys.stderr)


class AlertManager:
    """
    Writes structured JSON alerts to a log file and optionally
    prints colored alerts to console.
    """

    def __init__(
        self,
        log_path: Path,
        console_alerts: bool = True,
        min_severity: Severity = Severity.INFO,
    ) -> None:
        self.log_path = Path(log_path)
        self.console_alerts = console_alerts
        self._min_severity = min_severity
        self._file_logger: Optional[logging.FileHandler] = None
        self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _severity_level(self, severity: Severity) -> int:
        order = (Severity.INFO, Severity.WARNING, Severity.CRITICAL)
        try:
            return order.index(severity)
        except ValueError:
            return 0

    def _should_log(self, severity: Severity) -> bool:
        return self._severity_level(severity) >= self._severity_level(self._min_severity)

    def _format_alert(self, event: FIMEvent) -> dict:
        from datetime import datetime, timezone

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event.event_type.value,
            "file_path": event.file_path,
            "severity": event.severity.value,
            **({"old_path": event.old_path} if event.old_path else {}),
            **({"metadata": event.metadata} if event.metadata else {}),
        }

    def emit(self, event: FIMEvent) -> None:
        """Write one FIM event as JSON to log file and optionally to console."""
        if not self._should_log(event.severity):
            return
        record = self._format_alert(event)
        line = json.dumps(record) + "\n"
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError as e:
            logger.exception("Failed to write alert to %s: %s", self.log_path, e)
        if self.console_alerts:
            msg = f"[{event.severity.value}] {event.event_type.value}: {event.file_path}"
            colored_alert(msg, event.severity.value)

    def emit_batch(self, events: list[FIMEvent]) -> None:
        """Emit multiple events in order."""
        for event in events:
            self.emit(event)
