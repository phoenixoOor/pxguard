"""
PXGuard - Monitoring engine.

Orchestrates periodic scanning, comparison, threshold checks, and alerting.
Supports optional rich-based interactive dashboard, process tracking (psutil),
optional watchdog, interactive graph export, and session report.
"""

import contextlib
import logging
import os
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

from pxguard.core.alerts import AlertManager
from pxguard.core.anomaly_engine import AnomalyConfig, AnomalyEngine
from pxguard.core.comparator import BaselineComparator
from pxguard.core.dashboard import Dashboard
from pxguard.core.graph import ChangeGraph, TerminalGraph
from pxguard.core.models import EventType, Severity
from pxguard.core.report import write_session_report
from pxguard.core.report_engine import generate_security_report
from pxguard.core.scanner import DirectoryScanner
from pxguard.core.thresholds import ThresholdConfig, ThresholdTracker

logger = logging.getLogger(__name__)


@lru_cache(maxsize=128)
def _resolve_pid_name_cached(normalized_path: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Resolve (pid, process_name) for a process that has the file open.
    Called only when a file change event exists; cached to avoid re-iterating on same path.
    """
    try:
        import psutil
    except ImportError:
        return None, None
    path = Path(normalized_path)
    if not path.is_absolute():
        try:
            path = path.resolve()
        except (OSError, RuntimeError):
            return None, None
    try:
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                for f in proc.open_files():
                    try:
                        if Path(f.path).resolve() == path:
                            return (
                                proc.info["pid"],
                                (proc.info.get("name") or "?")[:24],
                            )
                    except (OSError, RuntimeError):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logger.debug("Process resolve failed for %s: %s", normalized_path, e)
    return None, None


def _resolve_source_process(file_path: str, self_pid: Optional[int] = None) -> str:
    """
    Return source string for dashboard: 0xPID [name], 0xPID [SELF], or 0x???? [UNKNOWN].
    Search runs only when file was changed/created (call site); cache avoids stutter.
    """
    try:
        normalized = str(Path(file_path).resolve())
    except (OSError, RuntimeError):
        normalized = file_path
    pid, name = _resolve_pid_name_cached(normalized)
    if pid is None:
        return "0x???? [UNKNOWN]"
    if self_pid is not None and pid == self_pid:
        return "0x%X [SELF]" % pid
    return "0x%X [%s]" % (pid, (name or "?")[:20])


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
        self._session_total_scans = 0
        self._session_max_changes = 0
        self._session_peak_iteration: Optional[int] = None
        self._session_peak_timestamp: Optional[float] = None
        self._session_final_status = "OK"
        anomaly_cooldown = config.get("anomaly_cooldown_seconds", 300.0)
        self.anomaly_engine = AnomalyEngine(
            AnomalyConfig(
                static_threshold=config["threshold_change_count"],
                cooldown_seconds=anomaly_cooldown,
            )
        )

    def run_once(self) -> tuple[list, int, bool]:
        """
        Perform one compare cycle.
        Returns (list of FIMEvent, scanned file count, has_baseline).
        When baseline is missing/empty, still scans to get file count and returns has_baseline=False.
        """
        baseline = self.comparator.load_baseline(self.baseline_path)
        current = self.scanner.scan_directories(self._dirs, self._root)
        scanned = len(current)
        if not baseline:
            logger.warning("Empty or missing baseline; run 'pxguard init' to create one.")
            return [], scanned, False
        events = self.comparator.compare(baseline, current)
        events = self.threshold_tracker.record_and_escalate(events)
        if not self.dry_run:
            self.alert_manager.emit_batch(events)
        return events, scanned, True

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
            log_dir = Path(self.config["alert_log_path"]).parent
            if not self.dry_run:
                graph_fmt = self.config.get("graph_format", "html")
                change_graph.export(
                    save_dir=log_dir,
                    format=graph_fmt,
                    threshold=self.config["threshold_change_count"],
                )
                report_path = self.config.get("report_summary_path") or Path(self.config["alert_log_path"]).parent / "report_summary.txt"
                write_session_report(
                    report_path=Path(report_path),
                    total_scans=self._session_total_scans,
                    max_changes=self._session_max_changes,
                    peak_iteration=self._session_peak_iteration,
                    peak_timestamp=self._session_peak_timestamp,
                    final_status=self._session_final_status,
                )
        logger.info("PXGuard monitor stopped.")

    def _run_with_rich_dashboard(self, change_graph: ChangeGraph) -> None:
        """Monitor loop with rich Live dashboard (summary + graph + logs). Optional watchdog."""
        from pxguard.core.rich_dashboard import RichDashboard, create_live_dashboard

        threshold = self.config["threshold_change_count"]
        history_size = self.config.get("dashboard_history_size", 60)
        rich_dash = RichDashboard(threshold=threshold, history_size=history_size)
        live = create_live_dashboard(rich_dash, refresh_per_second=4.0)
        if live is None:
            self._run_with_plain_dashboard(change_graph)
            return
        watchdog_trigger: Optional[Any] = None
        observer: Optional[Any] = None
        if self.config.get("watchdog_enabled", False):
            try:
                from pxguard.core.watchdog_handler import (
                    DebouncedScanTrigger,
                    FIMEventHandler,
                    start_watchdog_observer,
                    WATCHDOG_AVAILABLE,
                )
                if WATCHDOG_AVAILABLE:
                    debounce = self.config.get("watchdog_debounce_seconds", 2.0)
                    watchdog_trigger = DebouncedScanTrigger(debounce_seconds=debounce)
                    allowed = set(Path(d).resolve() for d in self.config["directories"])
                    handler = FIMEventHandler(
                        on_pending_scan=watchdog_trigger.set_pending,
                        debounce_seconds=debounce,
                        allowed_paths=allowed,
                    )
                    observer = start_watchdog_observer(
                        self.config["directories"],
                        handler,
                        recursive=True,
                    )
            except Exception as e:
                logger.warning("Watchdog not started: %s", e)
        last_scan_time = 0.0
        with _suppress_stderr_logging(), live:
            live.update(rich_dash.get_renderable(), refresh=True)
            while not self.stop_event():
                now = time.monotonic()
                do_scan = False
                if watchdog_trigger and watchdog_trigger.should_run_scan():
                    do_scan = True
                    watchdog_trigger.clear_pending()
                elif (now - last_scan_time) >= self.scan_interval:
                    do_scan = True
                if do_scan:
                    try:
                        events, scanned, has_baseline = self.run_once()
                        modified = sum(1 for e in events if e.event_type == EventType.MODIFIED)
                        deleted = sum(1 for e in events if e.event_type == EventType.DELETED)
                        created = sum(1 for e in events if e.event_type == EventType.CREATED)
                        total = modified + deleted + created
                        change_graph.add(
                            created=created,
                            modified=modified,
                            deleted=deleted,
                            timestamp=time.time(),
                        )
                        self._session_total_scans += 1
                        if total > self._session_max_changes:
                            self._session_max_changes = total
                            self._session_peak_iteration = self._session_total_scans
                            self._session_peak_timestamp = time.time()
                        anomaly_result = self.anomaly_engine.evaluate(total, created, modified, deleted)
                        if not has_baseline:
                            status = "OK"
                            self._session_final_status = "WARNING"
                        else:
                            status = self.anomaly_engine.threat_level_for_dashboard()
                            self._session_final_status = status
                        threshold_exceeded = (
                            any(e.severity == Severity.CRITICAL and e.metadata.get("threshold_exceeded") for e in events)
                            or anomaly_result.static_exceeded
                        )
                        if anomaly_result.is_anomaly and change_graph.has_data():
                            log_dir = Path(self.config["alert_log_path"]).parent
                            ts = time.time()
                            ts_str = time.strftime("%Y%m%d_%H%M%S", time.gmtime(ts))
                            report_path = log_dir / ("security_report_%s.txt" % ts_str)
                            it, cr, md, dl = change_graph.get_series()
                            totals_list = [a + b + c for a, b, c in zip(cr, md, dl)]
                            avg_baseline = sum(totals_list) / len(totals_list) if totals_list else 0
                            generate_security_report(
                                report_path,
                                timestamp=ts,
                                total_scans=self._session_total_scans,
                                peak_change_count=self._session_max_changes,
                                peak_timestamp=self._session_peak_timestamp,
                                average_baseline=avg_baseline,
                                threshold=self.config["threshold_change_count"],
                                final_status=status,
                                affected_files_count=total,
                                anomaly_state=anomaly_result.state,
                            )
                            from pxguard.core.graph_engine import export_security_graph
                            spike_idx = [len(it) - 1] if anomaly_result.spike_detected or anomaly_result.static_exceeded else []
                            _html_p, png_p = export_security_graph(
                                log_dir, it, cr, md, dl,
                                self.config["threshold_change_count"],
                                timestamp=ts,
                                spike_indices=spike_idx,
                            )
                            if self.config.get("email_alerts_enabled", False):
                                from pxguard.core.email_engine import send_alert_email
                                body = (
                                    "PXGuard detected anomalous file activity.\n\n"
                                    "Total scans: %d\nPeak changes: %d\nStatus: %s\nAnomaly state: %s\n\n"
                                    "See attached report and graph."
                                ) % (self._session_total_scans, self._session_max_changes, status, anomaly_result.state)
                                attachments = [report_path]
                                if png_p:
                                    attachments.append(png_p)
                                send_alert_email(body_text=body, attachment_paths=attachments)
                        rich_dash.update(
                            scanned=scanned,
                            created=created,
                            modified=modified,
                            deleted=deleted,
                            status=status,
                            threshold_exceeded=threshold_exceeded,
                            no_baseline=not has_baseline,
                        )
                        for e in events:
                            msg = f"{e.event_type.value}: {e.file_path}"
                            source = _resolve_source_process(e.file_path, self_pid=os.getpid())
                            rich_dash.add_log(msg, e.severity.value, source=source)
                        live.update(rich_dash.get_renderable(), refresh=True)
                        last_scan_time = now
                    except Exception as e:
                        logger.exception("Monitor cycle failed: %s", e)
                        rich_dash.add_log(f"Error: {e}", "CRITICAL")
                        live.update(rich_dash.get_renderable(), refresh=True)
                for _ in range(self.scan_interval):
                    if self.stop_event():
                        break
                    time.sleep(1)
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=5.0)
            except Exception:
                pass

    def _run_with_plain_dashboard(self, change_graph: ChangeGraph) -> None:
        """Monitor loop with plain dashboard and terminal graph. Optional watchdog."""
        dashboard = Dashboard()
        terminal_graph = TerminalGraph(
            threshold=self.config["threshold_change_count"],
            stream=sys.stderr,
        )
        watchdog_trigger: Optional[Any] = None
        observer: Optional[Any] = None
        if self.config.get("watchdog_enabled", False):
            try:
                from pxguard.core.watchdog_handler import (
                    DebouncedScanTrigger,
                    FIMEventHandler,
                    start_watchdog_observer,
                    WATCHDOG_AVAILABLE,
                )
                if WATCHDOG_AVAILABLE:
                    debounce = self.config.get("watchdog_debounce_seconds", 2.0)
                    watchdog_trigger = DebouncedScanTrigger(debounce_seconds=debounce)
                    allowed = set(Path(d).resolve() for d in self.config["directories"])
                    handler = FIMEventHandler(
                        on_pending_scan=watchdog_trigger.set_pending,
                        debounce_seconds=debounce,
                        allowed_paths=allowed,
                    )
                    observer = start_watchdog_observer(
                        self.config["directories"],
                        handler,
                        recursive=True,
                    )
            except Exception as e:
                logger.warning("Watchdog not started: %s", e)
        last_scan_time = 0.0
        while not self.stop_event():
            now = time.monotonic()
            do_scan = False
            if watchdog_trigger and watchdog_trigger.should_run_scan():
                do_scan = True
                watchdog_trigger.clear_pending()
            elif (now - last_scan_time) >= self.scan_interval:
                do_scan = True
            if do_scan:
                try:
                    events, scanned, has_baseline = self.run_once()
                    modified = sum(1 for e in events if e.event_type == EventType.MODIFIED)
                    deleted = sum(1 for e in events if e.event_type == EventType.DELETED)
                    created = sum(1 for e in events if e.event_type == EventType.CREATED)
                    change_count = modified + deleted + created
                    change_graph.add(
                        created=created,
                        modified=modified,
                        deleted=deleted,
                        timestamp=time.time(),
                    )
                    self._session_total_scans += 1
                    if change_count > self._session_max_changes:
                        self._session_max_changes = change_count
                        self._session_peak_iteration = self._session_total_scans
                        self._session_peak_timestamp = time.time()
                    anomaly_result = self.anomaly_engine.evaluate(change_count, created, modified, deleted)
                    if not has_baseline:
                        status = "WARNING"
                    else:
                        status = self.anomaly_engine.threat_level_for_dashboard()
                    self._session_final_status = status
                    if anomaly_result.is_anomaly and change_graph.has_data():
                        log_dir = Path(self.config["alert_log_path"]).parent
                        ts = time.time()
                        ts_str = time.strftime("%Y%m%d_%H%M%S", time.gmtime(ts))
                        report_path = log_dir / ("security_report_%s.txt" % ts_str)
                        it, cr, md, dl = change_graph.get_series()
                        totals_list = [a + b + c for a, b, c in zip(cr, md, dl)]
                        avg_baseline = sum(totals_list) / len(totals_list) if totals_list else 0
                        generate_security_report(
                            report_path,
                            timestamp=ts,
                            total_scans=self._session_total_scans,
                            peak_change_count=self._session_max_changes,
                            peak_timestamp=self._session_peak_timestamp,
                            average_baseline=avg_baseline,
                            threshold=self.config["threshold_change_count"],
                            final_status=status,
                            affected_files_count=change_count,
                            anomaly_state=anomaly_result.state,
                        )
                        from pxguard.core.graph_engine import export_security_graph
                        spike_idx = [len(it) - 1] if anomaly_result.spike_detected or anomaly_result.static_exceeded else []
                        _html_p, png_p = export_security_graph(
                            log_dir, it, cr, md, dl,
                            self.config["threshold_change_count"],
                            timestamp=ts,
                            spike_indices=spike_idx,
                        )
                        if self.config.get("email_alerts_enabled", False):
                            from pxguard.core.email_engine import send_alert_email
                            body = (
                                "PXGuard detected anomalous file activity.\n\n"
                                "Total scans: %d\nPeak changes: %d\nStatus: %s\nAnomaly state: %s\n\n"
                                "See attached report and graph."
                            ) % (self._session_total_scans, self._session_max_changes, status, anomaly_result.state)
                            attachments = [report_path]
                            if png_p:
                                attachments.append(png_p)
                            send_alert_email(body_text=body, attachment_paths=attachments)
                    terminal_graph.update(change_count)
                    dashboard.update(
                        scanned=scanned,
                        modified=modified,
                        deleted=deleted,
                        created=created,
                        status=status,
                    )
                    dashboard.render()
                    terminal_graph.render()
                    last_scan_time = now
                except Exception as e:
                    logger.exception("Monitor cycle failed: %s", e)
            for _ in range(self.scan_interval):
                if self.stop_event():
                    break
                time.sleep(1)
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=5.0)
            except Exception:
                pass
