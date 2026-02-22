"""
PXGuard - Single professional Rich CLI dashboard (Cyber Security / Hacker Terminal style).

Layout (rich.layout.Layout): top 12 rows — Threat Summary (ratio=1) | Activity Monitor (ratio=2);
bottom — Recent Alerts full height. SOURCE column dim yellow; tactical beep on first CRITICAL;
breathing graph (idle 3 scans reduces Y scale).
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Optional

try:
    from rich.console import Group, RenderableType
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box as rich_box

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Live = None
    Panel = None
    Table = None
    Text = None
    Group = None
    Layout = None
    rich_box = None
    RenderableType = Any

Status = Literal["OK", "WARNING", "CRITICAL"]
SeverityStr = Literal["INFO", "WARNING", "CRITICAL"]

# Activity Monitor: last N scans, CyberActivityGraph (cyber/hacker style), fixed height
GRAPH_WINDOW_SIZE = 60
GRAPH_HEIGHT_ROWS = 8
GRAPH_WIDTH_DEFAULT = 60


@dataclass
class ScanRecord:
    """One scan result; real metrics only."""

    iteration: int
    scanned: int
    modified: int
    deleted: int
    created: int
    status: Status
    threshold_exceeded: bool
    no_baseline: bool = False

    @property
    def total_changes(self) -> int:
        return self.created + self.modified + self.deleted


@dataclass
class LogRecord:
    """One alert line with timestamp and optional process source."""

    message: str
    severity: SeverityStr
    timestamp: Optional[datetime] = None
    source: str = "[UNKNOWN_PROCESS]"

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


def _style_status(s: Status) -> str:
    if s == "CRITICAL":
        return "bold red"
    if s == "WARNING":
        return "bold yellow"
    return "bold green"


def _style_severity(s: SeverityStr) -> str:
    if s == "CRITICAL":
        return "red"
    if s == "WARNING":
        return "yellow"
    return "cyan"


class RichDashboard:
    """
    Single UI layer: Threat Summary, Activity Monitor (CyberActivityGraph, 60 scans),
    Recent Alerts. All data from monitor; no simulation.
    """

    def __init__(
        self,
        threshold: int,
        history_size: int = 60,
        console: Optional[Any] = None,
    ) -> None:
        if not RICH_AVAILABLE:
            raise RuntimeError("rich is required for RichDashboard; install with: pip install rich")
        self._threshold = max(1, threshold)
        self._history_size = max(GRAPH_WINDOW_SIZE, min(100, history_size))
        self._console = console
        self._scan_history: deque[ScanRecord] = deque(maxlen=self._history_size)
        self._log_history: deque[LogRecord] = deque(maxlen=self._history_size)
        self._iteration = 0
        self._was_critical = False
        self._display_peak = 0.0

    def update(
        self,
        *,
        scanned: int,
        created: int,
        modified: int,
        deleted: int,
        status: Status,
        threshold_exceeded: bool = False,
        no_baseline: bool = False,
    ) -> None:
        """
        Single entry point: push real metrics from monitor after each scan.
        No fake values. System beep once on first transition to CRITICAL.
        """
        self._iteration += 1
        if status == "CRITICAL" and not self._was_critical:
            self._was_critical = True
            try:
                print("\a", end="", flush=True)
            except Exception:
                pass
        elif status != "CRITICAL":
            self._was_critical = False
        self._scan_history.append(
            ScanRecord(
                iteration=self._iteration,
                scanned=scanned,
                modified=modified,
                deleted=deleted,
                created=created,
                status=status,
                threshold_exceeded=threshold_exceeded,
                no_baseline=no_baseline,
            )
        )

    def add_log(
        self,
        message: str,
        severity: SeverityStr = "INFO",
        source: Optional[str] = None,
    ) -> None:
        """Append one alert line. source: e.g. '0x1234 [python]' or '0x???? [UNKNOWN]'."""
        self._log_history.append(
            LogRecord(
                message=message,
                severity=severity,
                source=source or "0x???? [UNKNOWN]",
            )
        )

    def _threat_meter_bar(self, total_changes: int, width: int = 16) -> Text:
        """Horizontal threat meter [██████░░░░░░░░░░] pct%."""
        if self._threshold <= 0:
            pct = 0
        else:
            pct = min(100, int(100 * total_changes / self._threshold))
        filled = min(width, int(round((pct / 100) * width)))
        bar = "█" * filled + "░" * (width - filled)
        if pct >= 100 or total_changes >= self._threshold:
            style = "bold red"
        elif pct >= 50:
            style = "bold yellow"
        else:
            style = "bold green"
        return Text(f"[{bar}] {pct}%", style=style)

    def _make_threat_summary_panel(self) -> Panel:
        """Threat Summary: scanned, C/M/D, total, threshold, threat level, threat meter."""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="dim")
        table.add_column()
        if not self._scan_history:
            table.add_row("Total scanned", "—")
            table.add_row("Created", "—")
            table.add_row("Modified", "—")
            table.add_row("Deleted", "—")
            table.add_row("Total changes", "—")
            table.add_row("Threshold", str(self._threshold))
            table.add_row("Threat level", Text("OK", style="bold green"))
            table.add_row("Threat meter", self._threat_meter_bar(0))
        else:
            r = self._scan_history[-1]
            total = r.total_changes
            table.add_row("Total scanned", str(r.scanned))
            table.add_row("Created", str(r.created))
            table.add_row("Modified", str(r.modified))
            table.add_row("Deleted", str(r.deleted))
            table.add_row("Total changes", str(total))
            table.add_row("Threshold", str(self._threshold))
            if r.no_baseline:
                table.add_row("Threat level", Text("No baseline — run 'pxguard init'", style="bold yellow"))
            else:
                table.add_row("Threat level", Text(r.status, style=_style_status(r.status)))
            table.add_row("Threat meter", self._threat_meter_bar(total))
        hint = Text()
        hint.append(" ", style="dim")
        hint.append("●", style="bold green")
        hint.append(" OK  ", style="dim")
        hint.append("●", style="bold yellow")
        hint.append(" WARN  ", style="dim")
        hint.append("●", style="bold red")
        hint.append(" CRIT", style="dim")
        return Panel(
            Group(table, hint),
            title="[bold] Threat Summary [/]",
            border_style="cyan",
            box=rich_box.ROUNDED,
            padding=(0, 1),
        )

    def _make_graph_panel(self) -> Panel:
        """
        Activity Monitor: CyberActivityGraph — bottom-up bars, vertical gradient, scanline gaps,
        threshold overlay, [ DATA_STREAM ] green/red, color legend.
        Graph width ~0.6 of console so Layout blocks do not overlap.
        """
        from pxguard.core.graph_engine import CyberActivityGraph

        try:
            console_width = self._console.width if self._console else None
        except Exception:
            console_width = None
        total_width = console_width or 80
        graph_width = max(20, int(total_width * 0.6))

        history_data = [r.total_changes for r in self._scan_history]
        is_critical = bool(self._scan_history and self._scan_history[-1].threshold_exceeded)
        last_3 = history_data[-3:] if len(history_data) >= 3 else []
        idle_scans = 3 if (len(last_3) == 3 and all(x == 0 for x in last_3)) else 0
        recent_peak_raw = max(history_data) if history_data else 0
        if idle_scans >= 3 and self._display_peak > 0:
            self._display_peak = max(self._threshold, self._display_peak * 0.85)
        else:
            self._display_peak = max(self._display_peak, float(recent_peak_raw))
        recent_peak = self._display_peak
        body = CyberActivityGraph(
            history_data=history_data,
            threshold=self._threshold,
            width=graph_width,
            height=GRAPH_HEIGHT_ROWS,
            is_critical=is_critical,
            idle_scans=idle_scans,
            recent_peak=float(recent_peak),
        )

        if self._scan_history:
            r = self._scan_history[-1]
            subtitle = Text(
                " Current: %d  |  Threshold: %d  " % (r.total_changes, self._threshold),
                style="dim",
            )
        else:
            subtitle = Text(" Current: —  |  Threshold: %d  " % self._threshold, style="dim")

        title_render: Any
        if is_critical:
            title_render = Text()
            title_render.append(" ", style="bold")
            title_render.append("Activity Monitor  ", style="bold")
            title_render.append("!! SYSTEM COMPROMISED !!", style="blink bold red")
        else:
            title_render = "[bold] Activity Monitor [/]"

        return Panel(
            body,
            title=title_render,
            subtitle=subtitle,
            border_style="bold red" if is_critical else "bright_black",
            box=rich_box.ROUNDED,
            padding=(0, 1),
        )

    def _make_alerts_panel(self) -> Panel:
        """Recent Alerts: Time, Severity, SOURCE [PID/PROC] (dim yellow), Message; last 10 only."""
        table = Table(show_header=True, box=rich_box.SIMPLE if rich_box else None, padding=(0, 1))
        table.add_column("Time", width=10)
        table.add_column("Severity", width=8)
        table.add_column("SOURCE", width=18, style="dim yellow")
        table.add_column("Message", overflow="fold")
        recent = list(self._log_history)[-10:]
        if recent:
            for rec in recent:
                row_style = _style_severity(rec.severity)
                ts = rec.timestamp.strftime("%H:%M:%S") if rec.timestamp else "—"
                source_text = Text(rec.source, style="dim yellow")
                table.add_row(
                    Text(ts, style=row_style),
                    Text(rec.severity, style=row_style),
                    source_text,
                    Text(rec.message, style=row_style),
                )
        else:
            table.add_row(
                Text("—", style="dim"),
                Text("—", style="dim"),
                Text("—", style="dim"),
                Text("No alerts yet", style="dim"),
            )
        return Panel(
            table,
            title="[bold] Recent Alerts [/]",
            border_style="magenta",
            box=rich_box.ROUNDED,
            padding=(0, 1),
        )

    def get_renderable(self) -> RenderableType:
        """
        Layout: top block 12 rows — Summary (ratio=1) | Activity Monitor (ratio=2);
        bottom block — Recent Alerts on remaining height. Panels rendered once in their slots.
        """
        if not RICH_AVAILABLE or Layout is None:
            return Group(
                self._make_threat_summary_panel(),
                self._make_graph_panel(),
                self._make_alerts_panel(),
            )
        top = Layout(size=12)
        top.split_row(
            Layout(self._make_threat_summary_panel(), ratio=1),
            Layout(self._make_graph_panel(), ratio=2),
        )
        root = Layout()
        root.split_column(top, Layout(self._make_alerts_panel(), ratio=1))
        return root


def create_live_dashboard(
    dashboard: RichDashboard,
    console: Optional[Any] = None,
    refresh_per_second: float = 4.0,
) -> Optional[Any]:
    """
    Create Rich Live instance. Use only live.update(dashboard.get_renderable(), refresh=True).
    Single Live; no flicker; smooth refresh every scan.
    """
    if not RICH_AVAILABLE or Live is None:
        return None
    return Live(
        dashboard.get_renderable(),
        console=console,
        refresh_per_second=refresh_per_second,
        auto_refresh=False,
        transient=False,
    )
