"""
PXGuard - Monitoring engine.

Pipeline:  monitoring → process_resolver → analyzer → reaction_engine → alert_service

Orchestrates periodic scanning, comparison, threshold checks, process
resolution, automated reaction (on CRITICAL), and alerting/email.
"""

import contextlib
import logging
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

from pxguard.core.alerts import AlertManager
from pxguard.core.anomaly_engine import AnomalyConfig, AnomalyEngine
from pxguard.core.comparator import BaselineComparator
from pxguard.core.dashboard import Dashboard
from pxguard.core.graph import ChangeGraph, TerminalGraph
from pxguard.core.models import EventType, Severity
from pxguard.core.process_resolver import ProcessResolver, ProcessInfo, UNKNOWN_PROCESS
from pxguard.core.reaction_engine import ReactionEngine
from pxguard.core.report import write_session_report
from pxguard.core.report_engine import generate_security_report
from pxguard.core.scanner import DirectoryScanner
from pxguard.core.thresholds import ThresholdConfig, ThresholdTracker

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def _suppress_stderr_logging():
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
    if not config.get("dashboard_interactive", True):
        return False
    if not sys.stderr.isatty():
        return False
    try:
        from pxguard.core.rich_dashboard import RICH_AVAILABLE
        return bool(RICH_AVAILABLE)
    except Exception:
        return False


def _init_notifier(config: dict[str, Any]) -> Optional[Any]:
    """
    Create and verify IncidentNotifier when email is enabled.
    Performs SMTP health check (connect + TLS + login).
    Returns notifier instance or None.
    """
    if not config.get("email_alerts_enabled", False):
        return None
    from pxguard.core.notifier import IncidentNotifier
    notifier = IncidentNotifier(config)
    if not notifier.is_configured:
        logger.warning("[EMAIL] Email alerts enabled but SMTP is not fully configured — skipping")
        return None
    notifier.verify_smtp()
    return notifier


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
        self._resolver = ProcessResolver()
        self._reaction = ReactionEngine(
            enabled=config.get("reaction_enabled", False),
        )
        self._notifier = _init_notifier(config)

    def run_once(self) -> tuple[list, int, bool]:
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

    def _resolve_process(self, file_path: str) -> ProcessInfo:
        """Resolve the process holding a file open."""
        return self._resolver.resolve(file_path)

    def _resolve_all_events(self, events: list) -> list[tuple]:
        """
        Pipeline stage: process_resolver.
        Returns list of (event, ProcessInfo) tuples.
        Only resolves for MODIFIED/CREATED; others get UNKNOWN_PROCESS.
        """
        resolved = []
        for e in events:
            if e.event_type in (EventType.MODIFIED, EventType.CREATED):
                proc_info = self._resolve_process(e.file_path)
            else:
                proc_info = UNKNOWN_PROCESS
            resolved.append((e, proc_info))
        return resolved

    def _react_to_events(self, resolved_events: list[tuple]) -> list:
        """
        Pipeline stage: reaction_engine.
        Evaluates each CRITICAL event and triggers automated response.
        Returns list of ReactionRecords.
        """
        records = []
        for e, proc_info in resolved_events:
            if e.severity == Severity.CRITICAL and proc_info.resolved:
                rec = self._reaction.react(
                    file_path=e.file_path,
                    severity=e.severity.value,
                    process_info=proc_info,
                )
                if rec is not None:
                    records.append(rec)
        return records

    def _generate_incident_artifacts(
        self,
        change_graph: ChangeGraph,
        status: str,
        anomaly_result: Any,
        total: int,
    ) -> Tuple[Optional[Path], Optional[Path]]:
        """Generate report .txt and graph PNG/HTML. Returns (report_path, png_path)."""
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
        return report_path, png_p

    def _send_incident_email(
        self,
        report_path: Path,
        png_p: Optional[Path],
        status: str,
        anomaly_result: Any,
        created: int,
        modified: int,
        deleted: int,
        total: int,
        events: Optional[list] = None,
        rich_dash: Optional[Any] = None,
        reaction_records: Optional[list] = None,
    ) -> None:
        """Send incident email via notifier. Log warning on failure, push to dashboard."""
        if not self._notifier:
            return
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        changed_files = []
        if events:
            for e in events:
                changed_files.append({
                    "event": e.event_type.value,
                    "path": str(e.file_path),
                })
        reaction_data = []
        if reaction_records:
            for r in reaction_records:
                reaction_data.append(r.to_dict())
        ok = self._notifier.send_incident(
            report_path=report_path,
            chart_path=png_p,
            severity=status,
            created=created,
            modified=modified,
            deleted=deleted,
            total=total,
            threshold=self.config["threshold_change_count"],
            cooldown_seconds=int(self.config.get("anomaly_cooldown_seconds", 300)),
            timestamp_str=ts_str,
            anomaly_state=anomaly_result.state,
            total_scans=self._session_total_scans,
            peak_changes=self._session_max_changes,
            changed_files=changed_files,
            reaction_actions=reaction_data,
        )
        if not ok and rich_dash is not None:
            try:
                rich_dash.add_log("Email alert failed — check SMTP settings", "WARNING")
            except Exception:
                pass

    def run(self) -> None:
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

                        resolved_events = self._resolve_all_events(events)

                        reaction_records = self._react_to_events(resolved_events)
                        for rec in reaction_records:
                            if rec.success:
                                rich_dash.add_log(
                                    "[REACTION] %s pid=%d %s" % (rec.action, rec.pid, rec.process_name),
                                    "WARNING",
                                    source="%d [%s]" % (rec.pid, rec.process_name),
                                )

                        if anomaly_result.is_anomaly and change_graph.has_data():
                            report_path, png_p = self._generate_incident_artifacts(
                                change_graph, status, anomaly_result, total,
                            )
                            self._send_incident_email(
                                report_path, png_p, status, anomaly_result,
                                created, modified, deleted, total,
                                events=events, rich_dash=rich_dash,
                                reaction_records=reaction_records,
                            )

                        rich_dash.update(
                            scanned=scanned,
                            created=created,
                            modified=modified,
                            deleted=deleted,
                            status=status,
                            threshold_exceeded=threshold_exceeded,
                            no_baseline=not has_baseline,
                        )
                        for e, proc_info in resolved_events:
                            msg = f"{e.event_type.value}: {e.file_path}"
                            source = proc_info.format_source()
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

                    resolved_events = self._resolve_all_events(events)
                    reaction_records = self._react_to_events(resolved_events)

                    if anomaly_result.is_anomaly and change_graph.has_data():
                        report_path, png_p = self._generate_incident_artifacts(
                            change_graph, status, anomaly_result, change_count,
                        )
                        self._send_incident_email(
                            report_path, png_p, status, anomaly_result,
                            created, modified, deleted, change_count,
                            events=events,
                            reaction_records=reaction_records,
                        )
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
