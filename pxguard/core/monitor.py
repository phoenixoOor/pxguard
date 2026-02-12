"""
PXGuard - Monitoring engine.

Orchestrates periodic scanning, comparison, threshold checks, and alerting.
"""

import logging
import time
from pathlib import Path
from typing import Any, Callable, Optional

from pxguard.core.alerts import AlertManager
from pxguard.core.comparator import BaselineComparator
from pxguard.core.dashboard import Dashboard
from pxguard.core.models import EventType, Severity
from pxguard.core.scanner import DirectoryScanner
from pxguard.core.thresholds import ThresholdConfig, ThresholdTracker

logger = logging.getLogger(__name__)


class FileMonitor:
    """
    Main FIM monitoring loop: load baseline, rescan at interval,
    compare, apply threshold escalation, and emit alerts.
    """

    def __init__(
        self,
        config: dict[str, Any],
        dry_run: bool = False,
        stop_event: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.config = config
        self.dry_run = dry_run
        self.stop_event = stop_event or (lambda: False)
        root = config["project_root"]
        dirs = config["directories"]

        self.scanner = DirectoryScanner(exclude_patterns=config["exclude_patterns"])
        self.comparator = BaselineComparator(scanner=self.scanner)
        self.alert_manager = AlertManager(
            log_path=config["alert_log_path"],
            console_alerts=config["console_alerts"],
            min_severity=Severity(config.get("min_severity", "INFO")),
        )
        cooldown = config.get("threshold_cooldown_seconds") or config["threshold_time_window_seconds"]
        self.threshold_tracker = ThresholdTracker(
            ThresholdConfig(
                change_count=config["threshold_change_count"],
                time_window_seconds=config["threshold_time_window_seconds"],
                cooldown_seconds=cooldown,
            )
        )
        self.baseline_path = Path(config["baseline_path"])
        self.scan_interval = config["scan_interval"]
        self._root = root
        self._dirs = dirs

    def run_once(self) -> tuple[list, int]:
        """Perform one compare cycle; return (list of FIMEvent emitted, scanned file count)."""
        baseline = self.comparator.load_baseline(self.baseline_path)
        if not baseline:
            logger.warning("Empty or missing baseline; skipping compare cycle.")
            return [], 0
        current = self.scanner.scan_directories(self._dirs, self._root)
        events = self.comparator.compare(baseline, current)
        events = self.threshold_tracker.record_and_escalate(events)
        if not self.dry_run:
            self.alert_manager.emit_batch(events)
        return events, len(current)

    def run(self) -> None:
        """Run monitoring loop until stop_event is True."""
        logger.info(
            "Starting PXGuard monitor (interval=%ds, dry_run=%s)",
            self.scan_interval,
            self.dry_run,
        )
        dashboard = Dashboard()
        while not self.stop_event():
            try:
                events, scanned = self.run_once()
                modified = sum(1 for e in events if e.event_type == EventType.MODIFIED)
                deleted = sum(1 for e in events if e.event_type == EventType.DELETED)
                created = sum(1 for e in events if e.event_type == EventType.CREATED)
                if any(e.severity == Severity.CRITICAL for e in events):
                    status: str = "CRITICAL"
                elif any(e.severity == Severity.WARNING for e in events):
                    status = "WARNING"
                else:
                    status = "OK"
                dashboard.update(
                    scanned=scanned,
                    modified=modified,
                    deleted=deleted,
                    created=created,
                    status=status,
                )
                dashboard.render()
            except Exception as e:
                logger.exception("Monitor cycle failed: %s", e)
            for _ in range(self.scan_interval):
                if self.stop_event():
                    break
                time.sleep(1)
        logger.info("PXGuard monitor stopped.")
