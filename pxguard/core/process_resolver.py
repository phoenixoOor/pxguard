"""
PXGuard - Resolve which process has a file open (lsof-style via psutil).

Used to show SOURCE [PID/PROC] in Recent Alerts when a file change is detected.
"""

import logging
import os
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

_PSUTIL_AVAILABLE: Optional[bool] = None


def _have_psutil() -> bool:
    global _PSUTIL_AVAILABLE
    if _PSUTIL_AVAILABLE is not None:
        return _PSUTIL_AVAILABLE
    try:
        import psutil
        _PSUTIL_AVAILABLE = True
    except ImportError:
        _PSUTIL_AVAILABLE = False
    return _PSUTIL_AVAILABLE


def resolve_process_for_file(file_path: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Try to find a process that has the given file open (read or write).
    Returns (pid, process_name) or (None, None) if not found or on error.
    """
    if not _have_psutil():
        return None, None
    try:
        import psutil
    except ImportError:
        return None, None
    path = Path(file_path).resolve()
    try:
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                open_files = proc.open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            for f in open_files:
                try:
                    if Path(f.path).resolve() == path:
                        return proc.info["pid"], (proc.info.get("name") or "?")[:24]
                except (OSError, RuntimeError):
                    continue
    except Exception as e:
        logger.debug("Process resolve failed for %s: %s", file_path, e)
    return None, None


def format_source(file_path: str, self_pid: Optional[int] = None) -> str:
    """
    Return a string like "0x1234 [procname]" or "0x???? [UNKNOWN]".
    If self_pid is set and the resolved PID equals it, return "0xPID [SELF]".
    """
    pid, name = resolve_process_for_file(file_path)
    if pid is None:
        return "0x???? [UNKNOWN]"
    if self_pid is not None and pid == self_pid:
        return "0x%X [SELF]" % pid
    return "0x%X [%s]" % (pid, (name or "?")[:20])
