"""
PXGuard - Graph utilities: CyberActivityGraph (cyber/hacker terminal), Braille graph, HTML/PNG export.

- CyberActivityGraph: matrix grid (dim cyan ·/+), cyber symbols ░▒▓█, bright_cyan/magenta/bright_red+blink,
  laser threshold line, Y-axis in hex (0x0 / LVL), [ DATA_STREAM: ACTIVE ] indicator. Empty → NO_THREATS_DETECTED.
- Braille real-time graph: smooth curve, Y-axis, threshold.
- export_security_graph: Plotly/PNG for security reports.
"""

import logging
import time
from pathlib import Path
from typing import Any, List, Optional, Sequence

logger = logging.getLogger(__name__)

# Cyber / Hacker terminal style
CYBER_BLOCKS = ("\u2591", "\u2592", "\u2593", "\u2588")  # ░ ▒ ▓ █ (light→solid)
CYBER_GRID_CHAR = "\u00B7"   # · dim grid (radar)
CYBER_GRID_ALT = "+"        # optional + for grid
THRESHOLD_CHAR = "\u2550"   # ═ double line (laser)
THRESHOLD_CHAR_ALT = "\u2500"  # ─

# Braille: 2 cols x 4 rows per character. Dot bits 1..8 -> bit index 0..7.
# Layout: (row,col) in cell -> dot number 1..8
_BRAILLE_DOT_MAP = {(0, 0): 0, (0, 1): 3, (1, 0): 1, (1, 1): 4, (2, 0): 2, (2, 1): 5, (3, 0): 6, (3, 1): 7}
_BRAILLE_BASE = 0x2800


def _pixel_to_braille(pixels: list[list[bool]]) -> list[list[str]]:
    """Convert 2D pixel grid (row-major, row 0 = top) to Braille characters. Each 4x2 block -> one char."""
    if not pixels or not pixels[0]:
        return []
    h, w = len(pixels), len(pixels[0])
    br_h = (h + 3) // 4
    br_w = (w + 1) // 2
    out: list[list[str]] = [[chr(_BRAILLE_BASE) for _ in range(br_w)] for _ in range(br_h)]
    for py in range(h):
        for px in range(w):
            if not pixels[py][px]:
                continue
            br_y, br_x = py // 4, px // 2
            if br_y >= br_h or br_x >= br_w:
                continue
            local_y, local_x = py % 4, px % 2
            bit_idx = _BRAILLE_DOT_MAP.get((local_y, local_x), 0)
            code = ord(out[br_y][br_x]) - _BRAILLE_BASE
            code |= 1 << bit_idx
            out[br_y][br_x] = chr(_BRAILLE_BASE + code)
    return out


def _draw_line(pixels: list[list[bool]], x0: float, y0: float, x1: float, y1: float) -> None:
    """Bresenham-like: set pixels on line from (x0,y0) to (x1,y1). y top=0."""
    h, w = len(pixels), len(pixels[0])
    steps = max(int(abs(x1 - x0)), int(abs(y1 - y0)), 1)
    for i in range(steps + 1):
        t = i / steps
        x = x0 + t * (x1 - x0)
        y = y0 + t * (y1 - y0)
        ix, iy = int(round(x)), int(round(y))
        if 0 <= ix < w and 0 <= iy < h:
            pixels[iy][ix] = True


def render_braille_graph(
    values: list[int],
    threshold: int,
    width_braille: int = 60,
    height_braille: int = 8,
) -> tuple[list[str], list[tuple[str, float]], float, list[float]]:
    """
    Render Total Changes curve as Braille graph with threshold line.
    Returns (braille_rows, y_axis_labels, max_value, col_values).
    - braille_rows: list of strings, one per Braille row.
    - y_axis_labels: list of (label_str, value) for Y-axis.
    - max_value: scale used for Y.
    - col_values: per-Braille-column max value for color zones.
    """
    if not values:
        return [], [("0", 0.0)], 1.0, []
    n = len(values)
    max_val = max(max(values), int(threshold * 1.5), 1)
    max_val_f = float(max_val)
    h_px = height_braille * 4
    w_px = width_braille * 2
    pixels: list[list[bool]] = [[False] * w_px for _ in range(h_px)]

    def y_to_px(v: float) -> float:
        return (1.0 - v / max_val_f) * (h_px - 1)

    def x_to_px(i: int) -> float:
        if n <= 1:
            return w_px / 2
        return (i / (n - 1)) * (w_px - 1)

    # Curve: line between consecutive points
    for i in range(n - 1):
        x0, x1 = x_to_px(i), x_to_px(i + 1)
        y0, y1 = y_to_px(float(values[i])), y_to_px(float(values[i + 1]))
        _draw_line(pixels, x0, y0, x1, y1)
    if n == 1:
        py = int(round(y_to_px(float(values[0]))))
        px = int(round(x_to_px(0)))
        if 0 <= py < h_px and 0 <= px < w_px:
            pixels[py][px] = True

    # Threshold: horizontal dashed line
    thr_y = y_to_px(float(threshold))
    thr_px = int(round(thr_y))
    if 0 <= thr_px < h_px:
        for col in range(0, w_px, 2):
            pixels[thr_px][col] = True

    braille_cells = _pixel_to_braille(pixels)
    braille_rows = ["".join(row) for row in braille_cells]

    # Per-column max value for color zones (one value per Braille column = 2 px)
    n_br_cols = len(braille_cells[0]) if braille_cells else 0
    col_values: list[float] = []
    for br_col in range(n_br_cols):
        px_start = br_col * 2
        px_end = min(px_start + 2, w_px)
        i0 = int((px_start / (w_px - 1)) * (n - 1)) if w_px > 1 else 0
        i1 = int((px_end / (w_px - 1)) * (n - 1)) if w_px > 1 else n - 1
        i1 = min(i1 + 1, n)
        seg = values[i0:i1] if i0 < i1 else [values[-1]] if values else [0]
        col_values.append(max(seg) if seg else 0)
    if not col_values and values:
        col_values = [float(max(values))]

    y_labels: list[tuple[str, float]] = []
    for i in range(5):
        v = (max_val * i) / 4
        y_labels.append((str(int(v)), v))
    y_labels.reverse()
    return braille_rows, y_labels, max_val_f, col_values


def _zone_style_for_value(value: float, threshold: int) -> str:
    """Green (normal), yellow (near threshold), red (critical)."""
    if threshold <= 0:
        return "green"
    pct = value / threshold
    if pct >= 1.0:
        return "bold red"
    if pct >= 0.8:
        return "yellow"
    return "green"


def _cyber_zone_style(value: float, threshold: int) -> str:
    """Cyberpunk: safe=bright_cyan, near threshold=vivid_magenta, critical=bold bright_red blink."""
    if threshold <= 0:
        return "bright_cyan"
    pct = value / threshold
    if pct >= 1.0:
        return "bold bright_red blink"
    if pct >= 0.5:
        return "magenta"
    return "bright_cyan"


def _cyber_block_for_ratio(ratio: float) -> str:
    """Map 0..1 to ░ ▒ ▓ █ (higher = denser)."""
    if ratio <= 0:
        return CYBER_BLOCKS[0]
    idx = min(3, max(0, int(ratio * 4) if ratio < 1.0 else 3))
    return CYBER_BLOCKS[idx]


class CyberActivityGraph:
    """
    Cyber Security / Hacker Terminal style graph: matrix grid (dim cyan ·),
    data as ░▒▓█, safe=bright_cyan, near threshold=magenta, critical=bold bright_red blink.
    Threshold line ═ bright red (laser). Y-axis 0x0 / LVL:MAX. [ DATA_STREAM: ACTIVE ].
    Empty state: grid + NO_THREATS_DETECTED.
    """

    def __init__(
        self,
        history_data: List[int],
        threshold: int,
        width: int = 60,
        height: int = 8,
        label_width: int = 8,
    ) -> None:
        self.history_data = list(history_data) if history_data else []
        self.threshold = max(1, threshold)
        self.width = max(1, width)
        self.height = max(2, height)
        self.label_width = max(4, label_width)

    def __rich_console__(self, console: Any, options: Any) -> Any:
        from rich.console import Group
        from rich.text import Text

        w = self.width
        h = self.height
        thr = self.threshold
        grid_style = "dim cyan"
        data = self.history_data

        # Right-align: last w values; pad left with 0
        if len(data) >= w:
            values = data[-w:]
        else:
            values = [0] * (w - len(data)) + data

        has_data = any(v > 0 for v in values)
        max_val = max(max(values), thr, 1)
        max_val_f = float(max_val)

        # 1) Matrix grid background: dim cyan · (or +)
        grid_chars: List[List[str]] = [[CYBER_GRID_CHAR] * w for _ in range(h)]
        grid_styles: List[List[str]] = [[grid_style] * w for _ in range(h)]

        thr_row: Optional[int] = None
        if max_val_f > 0 and thr <= max_val:
            r = (h - 1) * (1.0 - thr / max_val_f)
            thr_row = max(0, min(h - 1, int(round(r))))

        if has_data:
            for col, v in enumerate(values):
                if v <= 0:
                    continue
                bar_ratio = v / max_val_f
                n_fill = max(0, min(h, int(round(bar_ratio * h))))
                if n_fill == 0 and v > 0:
                    n_fill = 1
                zone_style = _cyber_zone_style(float(v), thr)
                for i in range(n_fill):
                    row = h - 1 - i
                    if 0 <= row < h:
                        if thr_row is not None and row == thr_row:
                            grid_chars[row][col] = THRESHOLD_CHAR
                            grid_styles[row][col] = "bold red"
                        else:
                            # Density: bottom cells lighter, top denser
                            cell_ratio = (i + 1) / n_fill if n_fill else 1.0
                            grid_chars[row][col] = _cyber_block_for_ratio(cell_ratio)
                            grid_styles[row][col] = zone_style
            if thr_row is not None:
                for col in range(w):
                    if grid_chars[thr_row][col] == CYBER_GRID_CHAR:
                        grid_chars[thr_row][col] = THRESHOLD_CHAR
                        grid_styles[thr_row][col] = "bold red"
        else:
            # Empty: show threshold line only
            if thr_row is not None:
                for col in range(w):
                    grid_chars[thr_row][col] = THRESHOLD_CHAR
                    grid_styles[thr_row][col] = "bold red"

        max_label = "0x%X" % int(max_val) if max_val < 256 else "LVL:%d" % int(max_val)
        zero_label = "0x0"
        label_w = max(self.label_width, len(max_label), len(zero_label))

        lines: List[Any] = []
        # Top indicator
        top_line = Text()
        top_line.append(" " * label_w, style="dim")
        top_line.append("\u2502", style=grid_style)
        top_line.append(" [ DATA_STREAM: ACTIVE ] " if has_data else " [ SCANNING... ] ", style="dim cyan")
        lines.append(top_line)

        for row in range(h):
            t = Text()
            if row == 0:
                t.append(max_label.rjust(label_w), style="dim cyan")
            elif row == h - 1:
                t.append(zero_label.rjust(label_w), style="dim cyan")
            else:
                t.append(" " * label_w, style="dim")
            t.append("\u2502", style="bright_black")
            for col in range(w):
                ch = grid_chars[row][col]
                st = grid_styles[row][col] or grid_style
                t.append(ch, style=st)
            lines.append(t)

        if not has_data:
            no_threat = Text()
            no_threat.append(" " * label_w + " \u2502 ", style="dim")
            no_threat.append("NO_THREATS_DETECTED", style="dim cyan")
            lines.append(no_threat)

        yield Group(*lines)


def build_activity_monitor_renderable(
    values: list[int],
    threshold: int,
    width_braille: int = 60,
    height_braille: int = 8,
):
    """
    Build a Rich renderable for the Activity Monitor: CyberActivityGraph (cyber/hacker terminal style).
    Returns CyberActivityGraph or Group for use in Panel.
    """
    try:
        from rich.console import Group
        from rich.text import Text
    except ImportError:
        return None
    if not values:
        return CyberActivityGraph(history_data=[], threshold=threshold, width=max(1, width_braille), height=max(2, height_braille))
    return CyberActivityGraph(
        history_data=values,
        threshold=threshold,
        width=max(1, width_braille),
        height=max(2, height_braille),
        label_width=8,
    )

_PLOTLY_LAYOUT = {
    "paper_color": "#0d1117",
    "plot_color": "#161b22",
    "font": {"color": "#c9d1d9", "family": "Consolas, monospace"},
    "title": {"font": {"size": 18}, "x": 0.5, "anchor": "center"},
    "axis": {"grid color": "#30363d", "decolorizing": "#30363d", "show grid": True, "title": "Scan iteration"},
    "yaxis": {"grid color": "#30363d", "decolorizing": "#30363d", "show grid": True, "auto range": True, "title": "Number of changes"},
    "legend": {"color": "rgba(22,27,34,0.9)", "border color": "#30363d", "font": {"color": "#c9d1d9"}},
    "margin": {"t": 60, "r": 40, "b": 50, "l": 60},
}


def export_security_graph(
    save_dir: Path,
    iterations: Sequence[int],
    created: Sequence[int],
    modified: Sequence[int],
    deleted: Sequence[int],
    threshold: int,
    timestamp: Optional[float] = None,
    spike_indices: Optional[list[int]] = None,
) -> tuple[Optional[Path], Optional[Path]]:
    """
    Export Plotly HTML and PNG for security report. Returns (html_path, png_path).
    """
    if not iterations or len(iterations) != len(created) or len(iterations) != len(modified) or len(iterations) != len(deleted):
        logger.debug("Invalid data for security graph; skipping.")
        return None, None
    ts = timestamp or time.time()
    ts_str = time.strftime("%Y%m%d_%H%M%S", time.gmtime(ts))
    save_dir = Path(save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    html_path: Optional[Path] = save_dir / ("security_report_%s.html" % ts_str)
    png_path: Optional[Path] = save_dir / ("security_report_%s.png" % ts_str)
    totals = [c + m + d for c, m, d in zip(created, modified, deleted)]
    spike_indices = spike_indices or []

    try:
        import plotly.graph_objects as go
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=list(iterations), y=list(created), mode="lines+markers", name="Created", line=dict(color="#3fb950", width=2)))
        fig.add_trace(go.Scatter(x=list(iterations), y=list(modified), mode="lines+markers", name="Modified", line=dict(color="#d29922", width=2)))
        fig.add_trace(go.Scatter(x=list(iterations), y=list(deleted), mode="lines+markers", name="Deleted", line=dict(color="#f85149", width=2)))
        fig.add_trace(go.Scatter(x=list(iterations), y=totals, mode="lines+markers", name="Total", line=dict(color="#ffffff", width=2.5)))
        fig.add_hline(y=threshold, line_dash="dash", line_color="#f85149", annotation_text="Threshold", annotation_font_color="#c9d1d9")
        if spike_indices:
            spike_x = [iterations[i] for i in spike_indices if 0 <= i < len(iterations)]
            spike_y = [totals[i] for i in spike_indices if 0 <= i < len(totals)]
            if spike_x and spike_y:
                fig.add_trace(go.Scatter(x=spike_x, y=spike_y, mode="markers", name="Spike", marker=dict(symbol="diamond", size=14, color="#ff6b6b", line=dict(width=2))))
        layout = dict(_PLOTLY_LAYOUT)
        layout["title"] = {"text": "PXGuard Security Report — File changes", **_PLOTLY_LAYOUT["title"]}
        fig.update_layout(**layout)
        fig.write_html(str(html_path), config={"displayModeBar": True, "responsive": True})
        logger.info("Security report HTML saved to %s", html_path)
    except ImportError:
        logger.debug("Plotly not available; skipping HTML export.")
        html_path = None
    except Exception as e:
        logger.warning("Failed to save security report HTML: %s", e)
        html_path = None

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(10, 5))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#161b22")
        ax.tick_params(colors="#c9d1d9")
        ax.xaxis.label.set_color("#c9d1d9")
        ax.yaxis.label.set_color("#c9d1d9")
        ax.title.set_color("#c9d1d9")
        for spine in ax.spines.values():
            spine.set_color("#30363d")
        ax.grid(True, alpha=0.3, color="#30363d")
        x = list(iterations)
        ax.plot(x, list(created), color="#3fb950", linewidth=2, label="Created")
        ax.plot(x, list(modified), color="#d29922", linewidth=2, label="Modified")
        ax.plot(x, list(deleted), color="#f85149", linewidth=2, label="Deleted")
        ax.plot(x, totals, color="#ffffff", linewidth=2.5, label="Total")
        ax.axhline(y=threshold, color="#f85149", linestyle="--", alpha=0.8, label="Threshold")
        if spike_indices:
            sx = [iterations[i] for i in spike_indices if 0 <= i < len(iterations)]
            sy = [totals[i] for i in spike_indices if 0 <= i < len(totals)]
            if sx and sy:
                ax.scatter(sx, sy, marker="D", s=80, color="#ff6b6b", zorder=5, label="Spike")
        ax.set_xlabel("Scan iteration")
        ax.set_ylabel("Number of changes")
        ax.set_title("PXGuard Security Report — File changes per scan")
        ax.legend(loc="upper right", facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")
        fig.tight_layout()
        fig.savefig(png_path, dpi=150, facecolor="#0d1117", edgecolor="none")
        plt.close(fig)
        logger.info("Security report PNG saved to %s", png_path)
    except ImportError as e:
        logger.warning("matplotlib not available; skipping PNG: %s", e)
        png_path = None
    except Exception as e:
        logger.warning("Failed to save security report PNG: %s", e, exc_info=True)
        png_path = None

    return html_path, png_path
