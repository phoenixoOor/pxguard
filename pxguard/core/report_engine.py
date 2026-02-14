"""
PXGuard - Executive security report generator.

Generates structured security_report_<timestamp>.txt with professional
formatting. Used on anomaly and optionally at session end.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _ts_string(t: Optional[float]) -> str:
    """Format Unix timestamp to UTC string."""
    if t is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError):
        return str(t)


def generate_security_report(
    report_path: Path,
    *,
    timestamp: Optional[float] = None,
    total_scans: int = 0,
    peak_change_count: int = 0,
    peak_timestamp: Optional[float] = None,
    average_baseline: Optional[float] = None,
    threshold: int = 0,
    final_status: str = "OK",
    affected_files_count: int = 0,
    anomaly_state: Optional[str] = None,
) -> Path:
    """
    Write PXGuard Security Incident Report to report_path.
    All fields are optional; missing values shown as N/A.
    Returns the path written.
    """
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    ts = timestamp or (datetime.now(timezone.utc).timestamp() if timestamp is None else 0)
    report_ts = _ts_string(ts) if ts else _ts_string(datetime.now(timezone.utc).timestamp())
    avg_str = f"{average_baseline:.1f}" if average_baseline is not None else "N/A"
    lines = [
        "PXGuard Security Incident Report",
        "---------------------------------",
        "",
        f"Timestamp:              {report_ts}",
        f"Total scans:            {total_scans}",
        f"Peak change count:      {peak_change_count}",
        f"Peak timestamp:         {_ts_string(peak_timestamp)}",
        f"Average baseline:       {avg_str}",
        f"Threshold:              {threshold}",
        f"Final status:           {final_status}",
        f"Affected files count:   {affected_files_count}",
        "",
    ]
    if anomaly_state:
        lines.append(f"Anomaly state:          {anomaly_state}")
        lines.append("")
    lines.append("---------------------------------")
    content = "\n".join(lines) + "\n"
    report_path.write_text(content, encoding="utf-8")
    logger.info("Security report saved to %s", report_path)
    return report_path
