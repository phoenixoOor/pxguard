"""
PXGuard - Real-time and interactive graphs of file changes per scan.

- TerminalGraph: live terminal plot (plotext or ASCII), color-coded by severity.
- ChangeGraph: records Created/Modified/Deleted per scan; exports interactive
  Plotly HTML (dark theme) or static matplotlib PNG.
"""

import logging
import sys
import time
from pathlib import Path
from typing import Literal, Optional

logger = logging.getLogger(__name__)

# Maximum number of points to show in terminal graph (scrolls visually)
TERMINAL_GRAPH_MAX_POINTS = 60

# Default filenames
DEFAULT_GRAPH_FILENAME = "change_graph.png"
DEFAULT_GRAPH_HTML_FILENAME = "change_graph.html"

# Dark theme colors (cyber-security style)
PLOTLY_DARK_LAYOUT = {
    "paper_bgcolor": "#0d1117",
    "plot_bgcolor": "#161b22",
    "font": {"color": "#c9d1d9", "family": "Consolas, monospace"},
    "title": {"font": {"size": 18}, "x": 0.5, "xanchor": "center"},
    "xaxis": {
        "gridcolor": "#30363d",
        "zerolinecolor": "#30363d",
        "showgrid": True,
    },
    "yaxis": {
        "gridcolor": "#30363d",
        "zerolinecolor": "#30363d",
        "showgrid": True,
        "autorange": True,
    },
    "legend": {
        "bgcolor": "rgba(22,27,34,0.9)",
        "bordercolor": "#30363d",
        "font": {"color": "#c9d1d9"},
    },
    "margin": {"t": 60, "r": 40, "b": 50, "l": 60},
}


class TerminalGraph:
    """
    Real-time terminal-based graph of file changes per scan iteration.
    Cybersecurity-style: green (normal), yellow (moderate), red (critical/threshold).
    Uses plotext when available, otherwise ASCII bar fallback.
    """

    def __init__(self, threshold: int, stream=None) -> None:
        self._threshold = max(1, threshold)
        self._moderate = max(1, self._threshold // 2)
        self._stream = stream or sys.stderr
        self._iterations: list[int] = []
        self._counts: list[int] = []

    def update(self, change_count: int) -> None:
        """Record change count for the current iteration (appends next iteration index)."""
        self._iterations.append(len(self._iterations) + 1)
        self._counts.append(change_count)
        if len(self._iterations) > TERMINAL_GRAPH_MAX_POINTS:
            self._iterations = self._iterations[-TERMINAL_GRAPH_MAX_POINTS:]
            self._counts = self._counts[-TERMINAL_GRAPH_MAX_POINTS:]

    def _split_by_severity(self) -> tuple[list[int], list[int], list[int], list[int], list[int], list[int]]:
        """Return (x_green, y_green, x_yellow, y_yellow, x_red, y_red)."""
        x_g, y_g = [], []
        x_y, y_y = [], []
        x_r, y_r = [], []
        for i, c in zip(self._iterations, self._counts):
            if c >= self._threshold:
                x_r.append(i)
                y_r.append(c)
            elif c >= self._moderate:
                x_y.append(i)
                y_y.append(c)
            else:
                x_g.append(i)
                y_g.append(c)
        return x_g, y_g, x_y, y_y, x_r, y_r

    def _render_plotext(self) -> str:
        """Build plotext graph and return as string."""
        try:
            import plotext as plt
        except ImportError:
            return ""
        plt.clear_figure()
        plt.plotsize(80, 12)
        plt.title("File changes per scan (green=normal, yellow=moderate, red=critical)")
        x_g, y_g, x_y, y_y, x_r, y_r = self._split_by_severity()
        if x_g:
            plt.plot(x_g, y_g, color="green")
        if x_y:
            plt.plot(x_y, y_y, color="yellow")
        if x_r:
            plt.plot(x_r, y_r, color="red")
        plt.xlabel("Scan iteration")
        plt.ylabel("Changes")
        try:
            return plt.build()
        except AttributeError:
            return ""

    def _render_ascii(self) -> str:
        """Fallback: ASCII bar chart of recent counts."""
        if not self._counts:
            return ""
        recent = self._counts[-20:]
        lines = ["--- File changes (last %d scans) ---" % len(self._counts)]
        max_c = max(self._counts) or 1
        width = 40
        start_i = max(1, len(self._counts) - len(recent) + 1)
        for i, c in enumerate(recent, start=start_i):
            bar_len = int((c / max_c) * width) if max_c else 0
            bar = "#" * bar_len
            if c >= self._threshold:
                seg = " [CRITICAL]"
            elif c >= self._moderate:
                seg = " [moderate]"
            else:
                seg = ""
            lines.append("  %3d | %s %s%s" % (i, bar, c, seg))
        lines.append("  " + "-" * (width + 12))
        return "\n".join(lines) + "\n"

    def render(self) -> None:
        """Draw the terminal graph below the dashboard (no clear; appends to stream)."""
        if not self._iterations:
            return
        out = self._render_plotext()
        if not out:
            out = self._render_ascii()
        try:
            self._stream.write(out)
            self._stream.flush()
        except (OSError, UnicodeEncodeError):
            pass


class ChangeGraph:
    """
    Records Created/Modified/Deleted (and optional timestamp) per scan iteration.
    Used for interactive Plotly HTML graph and static matplotlib PNG; data matches
    dashboard scan history (no placeholders or dummy values).
    """

    def __init__(self) -> None:
        self._iterations: list[int] = []
        self._created: list[int] = []
        self._modified: list[int] = []
        self._deleted: list[int] = []
        self._timestamps: list[float] = []

    def add(
        self,
        created: int = 0,
        modified: int = 0,
        deleted: int = 0,
        timestamp: Optional[float] = None,
    ) -> None:
        """Record one scan iteration: created/modified/deleted counts; optional timestamp for report."""
        n = len(self._iterations) + 1
        self._iterations.append(n)
        self._created.append(created)
        self._modified.append(modified)
        self._deleted.append(deleted)
        self._timestamps.append(timestamp if timestamp is not None else time.time())

    @property
    def _change_counts(self) -> list[int]:
        """Total changes per scan (created + modified + deleted)."""
        return [c + m + d for c, m, d in zip(self._created, self._modified, self._deleted)]

    def has_data(self) -> bool:
        """True if at least one scan has been recorded."""
        return len(self._iterations) > 0

    def get_series(self) -> tuple[list[int], list[int], list[int], list[int]]:
        """Return (iterations, created, modified, deleted) for report/graph export."""
        return (
            list(self._iterations),
            list(self._created),
            list(self._modified),
            list(self._deleted),
        )

    def _build_matplotlib_figure(self):
        """Build dark-theme matplotlib figure with 4 lines. Caller must set backend (e.g. Agg)."""
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(10, 5))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#161b22")
        ax.tick_params(colors="#c9d1d9")
        ax.xaxis.label.set_color("#c9d1d9")
        ax.yaxis.label.set_color("#c9d1d9")
        ax.title.set_color("#c9d1d9")
        ax.spines["bottom"].set_color("#30363d")
        ax.spines["top"].set_color("#30363d")
        ax.spines["left"].set_color("#30363d")
        ax.spines["right"].set_color("#30363d")
        ax.grid(True, alpha=0.3, color="#30363d")
        x = self._iterations
        ax.plot(x, self._created, color="#3fb950", linewidth=2, label="Created")
        ax.plot(x, self._modified, color="#d29922", linewidth=2, label="Modified")
        ax.plot(x, self._deleted, color="#f85149", linewidth=2, label="Deleted")
        ax.plot(x, self._change_counts, color="#ffffff", linewidth=2.5, linestyle="-", label="Total")
        ax.set_xlabel("Scan iteration")
        ax.set_ylabel("Number of changes")
        ax.set_title("PXGuard — File changes per scan")
        ax.legend(loc="upper right", facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")
        fig.tight_layout()
        return fig, ax

    def _export_plotly_html(self, save_path: Path, threshold: int) -> bool:
        """Export interactive Plotly graph (dark theme) to HTML. Returns True if saved."""
        try:
            import plotly.graph_objects as go
        except ImportError:
            logger.debug("Plotly not available; use format='png' or install plotly")
            return False
        x = self._iterations
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=x, y=self._created, mode="lines+markers", name="Created",
                                 line=dict(color="#3fb950", width=2)))
        fig.add_trace(go.Scatter(x=x, y=self._modified, mode="lines+markers", name="Modified",
                                 line=dict(color="#d29922", width=2)))
        fig.add_trace(go.Scatter(x=x, y=self._deleted, mode="lines+markers", name="Deleted",
                                 line=dict(color="#f85149", width=2)))
        fig.add_trace(go.Scatter(x=x, y=self._change_counts, mode="lines+markers", name="Total",
                                 line=dict(color="#ffffff", width=2.5)))
        layout = dict(PLOTLY_DARK_LAYOUT)
        layout["title"] = {"text": "PXGuard — File changes per scan", **PLOTLY_DARK_LAYOUT["title"]}
        layout["xaxis"]["title"] = "Scan iteration"
        layout["yaxis"]["title"] = "Number of changes"
        fig.update_layout(**layout)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        fig.write_html(str(save_path), config={"displayModeBar": True, "responsive": True})
        logger.info("Interactive change graph saved to %s", save_path)
        return True

    def export(
        self,
        save_dir: Path,
        format: Literal["html", "png"] = "html",
        threshold: int = 10,
    ) -> None:
        """
        Export graph from real scan history to file.
        - format "html": Plotly interactive (change_graph.html), dark theme, 4 lines, auto-scale.
        - format "png": matplotlib static (change_graph.png), same style.
        Uses only actual data from add(); no placeholders or dummy values.
        """
        if not self.has_data():
            logger.info("No change data to plot; skipping graph save.")
            return
        save_dir = Path(save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        if format == "html":
            path = save_dir / DEFAULT_GRAPH_HTML_FILENAME
            if not self._export_plotly_html(path, threshold):
                path = save_dir / DEFAULT_GRAPH_FILENAME
                self._export_png(path)
        else:
            path = save_dir / DEFAULT_GRAPH_FILENAME
            self._export_png(path)

    def _export_png(self, save_path: Path) -> None:
        """Export static PNG via matplotlib (dark theme, 4 lines)."""
        if not save_path:
            return
        save_path = Path(save_path)
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            fig, ax = self._build_matplotlib_figure()
            save_path.parent.mkdir(parents=True, exist_ok=True)
            fig.savefig(save_path, dpi=150, facecolor="#0d1117", edgecolor="none")
            logger.info("Change graph saved to %s", save_path)
            plt.close(fig)
        except ImportError as e:
            logger.warning("matplotlib not available; skipping graph: %s", e)
        except Exception as e:
            logger.warning("Failed to save change graph: %s", e, exc_info=True)

    def plot(self, save_path: Optional[Path] = None) -> None:
        """
        Legacy: build graph and save to PNG when save_path is given.
        Prefer export(save_dir, format="html") for interactive graph.
        """
        if not self.has_data():
            logger.info("No change data to plot; skipping graph save.")
            return
        save_path = Path(save_path) if save_path else None
        if not save_path:
            return
        self._export_png(save_path)
