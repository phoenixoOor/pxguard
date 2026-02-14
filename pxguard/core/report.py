"""
PXGuard - Session summary report (email-ready).

Generates a short professional summary after each monitoring session and
saves to logs/report_summary.txt.
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def write_session_report(
    report_path: Path,
    total_scans: int,
    max_changes: int,
    peak_iteration: Optional[int],
    peak_timestamp: Optional[float],
    final_status: str,
) -> None:
    """
    Write a clean, professional session summary to report_path.

    Args:
        report_path: Path to report_summary.txt (e.g. logs/report_summary.txt).
        total_scans: Number of scan cycles completed.
        max_changes: Maximum change count in a single scan.
        peak_iteration: Scan iteration at which max_changes occurred (1-based).
        peak_timestamp: Unix timestamp of peak (for display).
        final_status: OK, WARNING, or CRITICAL.
    """
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import datetime
        peak_ts_str = "N/A"
        if peak_timestamp is not None:
            try:
                dt = datetime.datetime.fromtimestamp(peak_timestamp, tz=datetime.timezone.utc)
                peak_ts_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (OSError, ValueError):
                peak_ts_str = str(peak_timestamp)
        peak_iter_str = str(peak_iteration) if peak_iteration is not None else "N/A"
        lines = [
            "=" * 60,
            "PXGuard — File Integrity Monitoring — Session Summary",
            "=" * 60,
            "",
            f"  Total scans:        {total_scans}",
            f"  Max changes (single scan): {max_changes}",
            f"  Peak at iteration:  {peak_iter_str}",
            f"  Timestamp of peak:   {peak_ts_str}",
            f"  Final status:       {final_status}",
            "",
            "=" * 60,
        ]
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info("Session report saved to %s", report_path)
    except OSError as e:
        logger.warning("Failed to write session report to %s: %s", report_path, e)
