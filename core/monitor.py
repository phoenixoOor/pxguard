"""
PXGuard - Monitoring engine.

Orchestrates periodic scanning, comparison, threshold checks, and alerting.
"""

import logging
import time
from pathlib import Path
from typing import Any, Callable, Optional

from core.alerts import AlertManager
from core.comparator import BaselineComparator
from core.models import Severity
from core.scanner import DirectoryScanner
from core.thresholds import ThresholdConfig, ThresholdTracker

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
        self.threshold_tracker = ThresholdTracker(
            ThresholdConfig(
                change_count=config["threshold_change_count"],
                time_window_seconds=config["threshold_time_window_seconds"],
            )
        )
        self.baseline_path = Path(config["baseline_path"])
        self.scan_interval = config["scan_interval"]
        self._root = root
        self._dirs = dirs

    def run_once(self) -> list:
        """Perform one compare cycle; return list of FIMEvent emitted."""
        baseline = self.comparator.load_baseline(self.baseline_path)
        if not baseline:
            logger.warning("Empty or missing baseline; skipping compare cycle.")
            return []
        current = self.scanner.scan_directories(self._dirs, self._root)
        events = self.comparator.compare(baseline, current)
        events = self.threshold_tracker.record_and_escalate(events)
        if not self.dry_run:
            self.alert_manager.emit_batch(events)
        return events

    def run(self) -> None:
        """Run monitoring loop until stop_event is True."""
        logger.info("Starting PXGuard monitor (interval=%ds, dry_run=%s)", self.scan_interval, self.dry_run)
        while not self.stop_event():
            try:
                self.run_once()
            except Exception as e:
                logger.exception("Monitor cycle failed: %s", e)
            for _ in range(self.scan_interval):
                if self.stop_event():
                    break
                time.sleep(1)
        logger.info("PXGuard monitor stopped.")
