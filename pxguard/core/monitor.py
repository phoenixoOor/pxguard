"""
PXGuard - Monitoring engine.

Orchestrates periodic scanning, comparison, threshold checks, and alerting.
Supports optional rich-based interactive dashboard (config: dashboard.interactive).
"""

import contextlib
import logging
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

from pxguard.core.alerts import AlertManager
from pxguard.core.comparator import BaselineComparator
from pxguard.core.dashboard import Dashboard
from pxguard.core.graph import ChangeGraph, TerminalGraph
from pxguard.core.models import EventType, Severity
from pxguard.core.scanner import DirectoryScanner
from pxguard.core.thresholds import ThresholdConfig, ThresholdTracker

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def _suppress_stderr_logging():
    """Context manager that suppresses logging to stderr so Rich Live in-place updates are not corrupted."""
    stderr_handlers = [
        h for h in logging.root.handlers
        if getattr(h, "stream", None) is sys.stderr
    ]
    flag = [True]

    class _Filter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return not flag[0]

    added: list[tuple[logging.Handler, logging.Filter]] = []
    for h in stderr_handlers:
        f = _Filter()
        h.addFilter(f)
        added.append((h, f))
    try:
        yield
    finally:
        flag[0] = False
        for h, f in added:
            h.removeFilter(f)


def _use_rich_dashboard(config: dict[str, Any]) -> bool:
    """True if interactive rich dashboard should be used (config + TTY + rich available)."""
    if not config.get("dashboard_interactive", True):
        return False
    if not sys.stderr.isatty():
        return False
    try:
        from pxguard.core.rich_dashboard import RICH_AVAILABLE
        return bool(RICH_AVAILABLE)
    except Exception:
        return False


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
        use_rich = _use_rich_dashboard(config)
        console_alerts = config.get("console_alerts", True) and not use_rich
        self.alert_manager = AlertManager(
            log_path=config["alert_log_path"],
            console_alerts=console_alerts,
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
        change_graph = ChangeGraph()
        use_rich = _use_rich_dashboard(self.config)
        try:
            if use_rich:
                self._run_with_rich_dashboard(change_graph)
            else:
                self._run_with_plain_dashboard(change_graph)
        finally:
            graph_save_path = None if self.dry_run else Path(self.config["alert_log_path"]).parent / "change_graph.png"
            change_graph.plot(save_path=graph_save_path)
        logger.info("PXGuard monitor stopped.")

    def _run_with_rich_dashboard(self, change_graph: ChangeGraph) -> None:
        """Monitor loop with rich Live dashboard (summary + graph + logs)."""
        from pxguard.core.rich_dashboard import RichDashboard, create_live_dashboard

        threshold = self.config["threshold_change_count"]
        history_size = self.config.get("dashboard_history_size", 30)
        rich_dash = RichDashboard(threshold=threshold, history_size=history_size)
        live = create_live_dashboard(rich_dash, refresh_per_second=4.0)
        if live is None:
            self._run_with_plain_dashboard(change_graph)
            return
        with _suppress_stderr_logging(), live:
            live.update(rich_dash.get_renderable(), refresh=True)
            while not self.stop_event():
                try:
                    events, scanned = self.run_once()
                    modified = sum(1 for e in events if e.event_type == EventType.MODIFIED)
                    deleted = sum(1 for e in events if e.event_type == EventType.DELETED)
                    created = sum(1 for e in events if e.event_type == EventType.CREATED)
                    change_graph.add(modified + deleted + created)
                    if any(e.severity == Severity.CRITICAL for e in events):
                        status: str = "CRITICAL"
                    elif any(e.severity == Severity.WARNING for e in events):
                        status = "WARNING"
                    else:
                        status = "OK"
                    threshold_exceeded = any(
                        e.severity == Severity.CRITICAL and e.metadata.get("threshold_exceeded")
                        for e in events
                    )
                    rich_dash.add_scan(
                        scanned=scanned,
                        modified=modified,
                        deleted=deleted,
                        created=created,
                        status=status,
                        threshold_exceeded=threshold_exceeded,
                    )
                    for e in events:
                        msg = f"{e.event_type.value}: {e.file_path}"
                        rich_dash.add_log(msg, e.severity.value)
                    live.update(rich_dash.get_renderable(), refresh=True)
                except Exception as e:
                    logger.exception("Monitor cycle failed: %s", e)
                    rich_dash.add_log(f"Error: {e}", "CRITICAL")
                    live.update(rich_dash.get_renderable(), refresh=True)
                for _ in range(self.scan_interval):
                    if self.stop_event():
                        break
                    time.sleep(1)

    def _run_with_plain_dashboard(self, change_graph: ChangeGraph) -> None:
        """Monitor loop with plain dashboard and terminal graph."""
        dashboard = Dashboard()
        terminal_graph = TerminalGraph(
            threshold=self.config["threshold_change_count"],
            stream=sys.stderr,
        )
        while not self.stop_event():
            try:
                events, scanned = self.run_once()
                modified = sum(1 for e in events if e.event_type == EventType.MODIFIED)
                deleted = sum(1 for e in events if e.event_type == EventType.DELETED)
                created = sum(1 for e in events if e.event_type == EventType.CREATED)
                change_count = modified + deleted + created
                change_graph.add(change_count)
                terminal_graph.update(change_count)
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
                terminal_graph.render()
            except Exception as e:
                logger.exception("Monitor cycle failed: %s", e)
            for _ in range(self.scan_interval):
                if self.stop_event():
                    break
                time.sleep(1)
