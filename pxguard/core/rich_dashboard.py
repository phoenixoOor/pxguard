"""
PXGuard - Single professional Rich CLI dashboard (htop-style).

Layout: Threat Summary | Activity Monitor (Braille real-time graph, Y-axis, threshold) | Recent Alerts.
Uses real monitor metrics only; no simulated data. Single Live instance.
"""

from collections import deque
from dataclasses import dataclass
from typing import Any, Literal, Optional

try:
    from rich.console import Group, RenderableType
    from rich.live import Live
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
    rich_box = None
    RenderableType = Any

Status = Literal["OK", "WARNING", "CRITICAL"]
SeverityStr = Literal["INFO", "WARNING", "CRITICAL"]

# Activity Monitor: last N scans, Braille graph, fixed height
GRAPH_WINDOW_SIZE = 60
GRAPH_HEIGHT_BRAILLE = 8
GRAPH_WIDTH_BRAILLE_DEFAULT = 60


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
    """One alert line."""

    message: str
    severity: SeverityStr


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
    return "green"


class RichDashboard:
    """
    Single UI layer: Threat Summary, Activity Monitor (Braille graph, 60 scans),
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
        No fake values.
        """
        self._iteration += 1
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

    def add_log(self, message: str, severity: SeverityStr = "INFO") -> None:
        """Append one alert line."""
        self._log_history.append(LogRecord(message=message, severity=severity))

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
        return Panel(
            table,
            title="[bold] Threat Summary [/]",
            border_style="cyan",
            box=rich_box.ROUNDED,
            padding=(0, 1),
        )

    def _make_graph_panel(self) -> Panel:
        """
        Activity Monitor: Braille real-time graph, Y-axis, threshold line,
        color zones (green / yellow / red). Fixed height; width from terminal.
        """
        from pxguard.core.graph_engine import build_activity_monitor_renderable

        try:
            console_width = self._console.width if self._console else None
        except Exception:
            console_width = None
        width_braille = (
            max(20, (console_width or 80) - 20) // 2
        ) if console_width else GRAPH_WIDTH_BRAILLE_DEFAULT

        records = list(self._scan_history)[-GRAPH_WINDOW_SIZE:]
        totals = [r.total_changes for r in records]
        body = build_activity_monitor_renderable(
            totals,
            self._threshold,
            width_braille=width_braille,
            height_braille=GRAPH_HEIGHT_BRAILLE,
        )
        if body is None:
            body = Text("— graph unavailable —", style="dim")

        # Subtitle: current change rate and threshold
        if self._scan_history:
            r = self._scan_history[-1]
            subtitle = Text(
                " Current: %d changes  |  Threshold: %d  " % (r.total_changes, self._threshold),
                style="dim",
            )
        else:
            subtitle = Text(" Current: —  |  Threshold: %d  " % self._threshold, style="dim")

        return Panel(
            body,
            title="[bold] Activity Monitor [/]",
            subtitle=subtitle,
            border_style="bold red" if (self._scan_history and self._scan_history[-1].threshold_exceeded) else "bright_black",
            box=rich_box.ROUNDED,
            padding=(0, 1),
        )

    def _make_alerts_panel(self) -> Panel:
        """Recent Alerts."""
        table = Table(show_header=True, box=rich_box.SIMPLE if rich_box else None, padding=(0, 1))
        table.add_column("Severity", width=8)
        table.add_column("Message", overflow="fold")
        recent = list(self._log_history)[-self._history_size:]
        if recent:
            for rec in recent:
                table.add_row(Text(rec.severity, style=_style_severity(rec.severity)), rec.message)
        else:
            table.add_row(Text("—", style="dim"), Text("No alerts yet", style="dim"))
        return Panel(
            table,
            title="[bold] Recent Alerts [/]",
            border_style="magenta",
            box=rich_box.ROUNDED,
            padding=(0, 1),
        )

    def get_renderable(self) -> RenderableType:
        """Single renderable for Live.update(). No duplicate panels."""
        return Group(
            self._make_threat_summary_panel(),
            self._make_graph_panel(),
            self._make_alerts_panel(),
        )


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
