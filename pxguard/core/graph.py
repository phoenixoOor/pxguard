"""
PXGuard - Real-time graph of file changes per scan iteration.

- TerminalGraph: live terminal plot (plotext or ASCII fallback), color-coded by severity.
- ChangeGraph: matplotlib graph on monitor completion or PNG save in headless.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Maximum number of points to show in terminal graph (scrolls visually)
TERMINAL_GRAPH_MAX_POINTS = 60

# Default filename when saving in headless mode
DEFAULT_GRAPH_FILENAME = "change_graph.png"


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
        # Keep a sliding window for display
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
    Records file change count per scan iteration and plots a graph
    (iteration on x-axis, number of changes on y-axis).
    """

    def __init__(self) -> None:
        self._change_counts: list[int] = []

    def add(self, change_count: int) -> None:
        """Record the total number of file changes for one scan iteration."""
        self._change_counts.append(change_count)

    def _build_figure(self):
        """Build and return (fig, ax) with standard layout. Caller must use a backend first."""
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(10, 5))
        iterations = list(range(1, len(self._change_counts) + 1))
        ax.plot(iterations, self._change_counts, color="red", linewidth=2, label="File changes")
        ax.set_xlabel("Scan iteration")
        ax.set_ylabel("Number of changes (created + modified + deleted)")
        ax.set_title("PXGuard — File changes per scan")
        ax.grid(True, alpha=0.3)
        ax.legend(loc="upper right")
        fig.tight_layout()
        return fig, ax

    def plot(self, save_path: Optional[Path] = None) -> None:
        """
        Display a graph of changes over time, or save to PNG if GUI unavailable.

        Try interactive display (TkAgg). If tkinter is missing or display fails,
        fall back to headless mode and save graph to save_path (e.g. logs/change_graph.png).
        """
        if not self._change_counts:
            logger.debug("No change data to plot")
            return
        save_path = Path(save_path) if save_path else None

        # Prefer interactive display on Linux/Windows when display is available
        try:
            import matplotlib
            matplotlib.use("TkAgg")
            import matplotlib.pyplot as plt
            fig, ax = self._build_figure()
            plt.show()
            plt.close(fig)
            return
        except ImportError as e:
            logger.debug("TkAgg/matplotlib GUI not available: %s; trying headless save", e)
        except Exception as e:
            logger.debug("GUI display failed: %s; falling back to headless save", e)

        # Headless: use Agg backend and save to PNG
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            fig, ax = self._build_figure()
            if save_path:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                fig.savefig(save_path, dpi=150)
                logger.info("Change graph saved to %s", save_path)
            plt.close(fig)
        except ImportError as e:
            logger.warning("matplotlib not available; skipping graph: %s", e)
        except Exception as e:
            logger.warning("Failed to save change graph: %s", e)
