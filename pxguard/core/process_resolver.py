"""
PXGuard - Process resolver.

Identifies which process is responsible for a file event using psutil.
Returns rich ProcessInfo (pid, name, exe, username, ppid) or a safe fallback.
Handles AccessDenied, NoSuchProcess, and missing psutil gracefully.
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    _PSUTIL_AVAILABLE = False


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """Resolved process identity for a file event."""

    pid: Optional[int] = None
    name: Optional[str] = None
    exe: Optional[str] = None
    username: Optional[str] = None
    ppid: Optional[int] = None
    is_self: bool = False

    @property
    def resolved(self) -> bool:
        return self.pid is not None

    def format_source(self) -> str:
        """
        Dashboard-friendly string.
        Resolved  → 'PID [process_name]'
        Self      → 'PID [SELF]'
        Unknown   → '[UNKNOWN_PROCESS]'
        """
        if not self.resolved:
            return "[UNKNOWN_PROCESS]"
        if self.is_self:
            return "%d [SELF]" % self.pid
        label = self.name or "?"
        return "%d [%s]" % (self.pid, label[:24])

    def format_detail(self) -> str:
        """Full detail line for logs and reports."""
        if not self.resolved:
            return "[UNKNOWN_PROCESS]"
        parts = ["pid=%d" % self.pid]
        if self.name:
            parts.append("name=%s" % self.name)
        if self.exe:
            parts.append("exe=%s" % self.exe)
        if self.username:
            parts.append("user=%s" % self.username)
        if self.ppid is not None:
            parts.append("ppid=%d" % self.ppid)
        if self.is_self:
            parts.append("SELF")
        return " ".join(parts)

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "username": self.username,
            "ppid": self.ppid,
            "is_self": self.is_self,
        }


UNKNOWN_PROCESS = ProcessInfo()


class ProcessResolver:
    """
    Resolves which process has a given file path open.
    Call resolve() only for MODIFIED/CREATED events to avoid performance impact.
    """

    def __init__(self, self_pid: Optional[int] = None) -> None:
        self._self_pid = self_pid if self_pid is not None else os.getpid()

    @staticmethod
    def available() -> bool:
        return _PSUTIL_AVAILABLE

    def resolve(self, file_path: str) -> ProcessInfo:
        """
        Find the process that has file_path open.
        Returns ProcessInfo with full details, or UNKNOWN_PROCESS on failure.
        Never raises — all psutil errors are caught and logged.
        """
        if not _PSUTIL_AVAILABLE:
            return UNKNOWN_PROCESS

        try:
            target = Path(file_path).resolve()
        except (OSError, RuntimeError):
            return UNKNOWN_PROCESS

        try:
            for proc in psutil.process_iter(["pid", "name", "open_files"]):
                try:
                    open_files = proc.open_files()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except OSError:
                    continue

                for f in open_files:
                    try:
                        if Path(f.path).resolve() == target:
                            return self._build_info(proc)
                    except (OSError, RuntimeError):
                        continue
        except Exception as e:
            logger.debug("[RESOLVER] Failed for %s: %s", file_path, e)

        return UNKNOWN_PROCESS

    def _build_info(self, proc: "psutil.Process") -> ProcessInfo:
        """Extract full details from a psutil.Process, tolerating partial failures."""
        pid = None
        name = None
        exe = None
        username = None
        ppid = None

        try:
            pid = proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return UNKNOWN_PROCESS

        try:
            name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        try:
            exe = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        try:
            username = proc.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        try:
            ppid = proc.ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        is_self = pid == self._self_pid

        return ProcessInfo(
            pid=pid,
            name=name,
            exe=exe,
            username=username,
            ppid=ppid,
            is_self=is_self,
        )
