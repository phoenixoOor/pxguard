"""
PXGuard - Rich-based interactive CLI dashboard.

Live summary, sliding graph of changes, and colored log panel.
Uses rich Live for smooth updates without screen flicker.
"""

from collections import deque
from dataclasses import dataclass
from typing import Any, Literal, Optional

# Optional rich import; fallback if not installed
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


@dataclass
class ScanRecord:
    """One scan iteration record for history."""

    iteration: int
    scanned: int
    modified: int
    deleted: int
    created: int
    status: Status
    threshold_exceeded: bool


@dataclass
class LogRecord:
    """One log line for the dashboard."""

    message: str
    severity: SeverityStr


def _style_status(status: Status) -> str:
    if status == "CRITICAL":
        return "bold red"
    if status == "WARNING":
        return "bold yellow"
    return "bold green"


def _style_severity(severity: SeverityStr) -> str:
    if severity == "CRITICAL":
        return "red"
    if severity == "WARNING":
        return "yellow"
    return "green"


class RichDashboard:
    """
    Interactive dashboard: summary panel, sliding graph, log panel.
    Uses rich Live for flicker-free updates. Limited to last N scans/logs.
    """

    def __init__(
        self,
        threshold: int,
        history_size: int = 30,
        console: Optional[Any] = None,
    ) -> None:
        if not RICH_AVAILABLE:
            raise RuntimeError("rich is required for RichDashboard; install with: pip install rich")
        self._threshold = max(1, threshold)
        self._history_size = max(10, min(100, history_size))
        self._console = console
        self._scan_history: deque[ScanRecord] = deque(maxlen=self._history_size)
        self._log_history: deque[LogRecord] = deque(maxlen=self._history_size)
        self._iteration = 0

    def add_scan(
        self,
        scanned: int,
        modified: int,
        deleted: int,
        created: int,
        status: Status,
        threshold_exceeded: bool = False,
    ) -> None:
        """Append one scan result to history (sliding window)."""
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
            )
        )

    def add_log(self, message: str, severity: SeverityStr = "INFO") -> None:
        """Append one log line to history (sliding window)."""
        self._log_history.append(LogRecord(message=message, severity=severity))

    def _make_summary_panel(self) -> Panel:
        """Top panel: Scanned, Modified, Created, Deleted, Status with colors."""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="dim")
        table.add_column()
        if not self._scan_history:
            table.add_row("Scanned", "—")
            table.add_row("Modified", "—")
            table.add_row("Created", "—")
            table.add_row("Deleted", "—")
            table.add_row("Status", "[bold green]OK[/]")
        else:
            r = self._scan_history[-1]
            table.add_row("Scanned", str(r.scanned))
            table.add_row("Modified", str(r.modified))
            table.add_row("Created", str(r.created))
            table.add_row("Deleted", str(r.deleted))
            table.add_row("Status", Text(r.status, style=_style_status(r.status)))
        return Panel(
            table,
            title="[bold]FILE INTEGRITY MONITOR[/]",
            border_style="cyan",
            padding=(0, 1),
        )

    def _make_graph_panel(self) -> Panel:
        """Middle panel: sliding ASCII graph of Created/Modified/Deleted + threshold."""
        if not self._scan_history:
            return Panel(Text("— waiting for scans —", style="dim"), title="Changes (last N scans)", border_style="blue")
        records = list(self._scan_history)[-self._history_size:]
        max_val = 1
        for r in records:
            total = r.modified + r.deleted + r.created
            if total > max_val:
                max_val = total
        if self._threshold > max_val:
            max_val = self._threshold
        bar_width = 12
        table = Table(show_header=True, box=rich_box.SIMPLE if rich_box else None, padding=(0, 0))
        table.add_column("Iter", style="dim", width=5)
        table.add_column("Created", style="green", width=bar_width)
        table.add_column("Modified", style="yellow", width=bar_width)
        table.add_column("Deleted", style="red", width=bar_width)
        table.add_column("Total", width=6)
        table.add_column("Threshold", style="dim", width=4)
        for r in records:
            c_bar = self._bar(r.created, max_val, bar_width)
            m_bar = self._bar(r.modified, max_val, bar_width)
            d_bar = self._bar(r.deleted, max_val, bar_width)
            total = r.modified + r.deleted + r.created
            total_style = "red" if r.threshold_exceeded else ("yellow" if total >= self._threshold // 2 else "green")
            table.add_row(
                str(r.iteration),
                c_bar,
                m_bar,
                d_bar,
                Text(str(total), style=total_style),
                str(self._threshold),
            )
        return Panel(table, title="Changes per scan (green=Created, yellow=Modified, red=Deleted)", border_style="blue", padding=(0, 1))

    def _bar(self, value: int, max_val: int, width: int) -> Text:
        """One horizontal bar (block chars) for value."""
        if max_val <= 0:
            n = 0
        else:
            n = int(round((value / max_val) * width))
        n = max(0, min(width, n))
        return Text("█" * n + "░" * (width - n))

    def _make_log_panel(self) -> Panel:
        """Bottom panel: last N log lines with severity colors."""
        table = Table(show_header=True, box=rich_box.SIMPLE if rich_box else None, padding=(0, 1))
        table.add_column("Severity", width=8)
        table.add_column("Message", overflow="fold")
        for rec in list(self._log_history)[-self._history_size:]:
            table.add_row(Text(rec.severity, style=_style_severity(rec.severity)), rec.message)
        if not self._log_history:
            table.add_row(Text("—", style="dim"), Text("No alerts yet", style="dim"))
        return Panel(table, title="Recent alerts", border_style="magenta", padding=(0, 1))

    def get_renderable(self) -> RenderableType:
        """Single renderable: one summary panel, one graph panel, one log panel. Use only with Live.update()."""
        return Group(
            self._make_summary_panel(),
            self._make_graph_panel(),
            self._make_log_panel(),
        )


def create_live_dashboard(
    dashboard: RichDashboard,
    console: Optional[Any] = None,
    refresh_per_second: float = 4.0,
):
    """
    Context manager for Rich Live that displays the dashboard.
    Use only Live.update(dashboard.get_renderable(), refresh=True) to render; no console.print.
    auto_refresh=False so the display updates only when you call update(), avoiding duplicate panels.
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


# ---------------------------------------------------------------------------
# Example: run with  python -m pxguard.core.rich_dashboard
# Shows correct usage: only live.update() for rendering, no duplicate panels.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import time
    if not RICH_AVAILABLE:
        raise SystemExit("rich is required: pip install rich")
    from rich.console import Console
    console = Console()
    dash = RichDashboard(threshold=10, history_size=10, console=console)
    live = create_live_dashboard(dash, console=console, refresh_per_second=4.0)
    if live is None:
        raise SystemExit("Live not available")
    with live:
        live.update(dash.get_renderable(), refresh=True)  # initial: "Waiting for scans..."
        for i in range(1, 6):
            time.sleep(1)
            dash.add_scan(scanned=100 + i * 10, modified=i, deleted=0, created=1, status="OK", threshold_exceeded=False)
            dash.add_log(f"Scan {i} completed", "INFO")
            live.update(dash.get_renderable(), refresh=True)  # only place we update the display
    console.print("[green]Done.[/]")
