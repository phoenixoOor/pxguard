"""
PXGuard - Alert management and structured logging.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

from core.models import FIMEvent, Severity

logger = logging.getLogger(__name__)

# ANSI codes for colored console output
COLORS = {
    "INFO": "\033[36m",     # Cyan
    "WARNING": "\033[33m",  # Yellow
    "CRITICAL": "\033[31m", # Red
    "RESET": "\033[0m",
}


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
            color = COLORS.get(event.severity.value, COLORS["RESET"])
            reset = COLORS["RESET"]
            print(f"{color}[{event.severity.value}] {event.event_type.value}: {event.file_path}{reset}", file=sys.stderr)

    def emit_batch(self, events: list[FIMEvent]) -> None:
        """Emit multiple events in order."""
        for event in events:
            self.emit(event)
