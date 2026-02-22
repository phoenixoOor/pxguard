"""
PXGuard - Reaction engine.

Automated response to CRITICAL severity file events:
  - Terminate the responsible process (if resolved and not SELF)
  - Log all actions taken
  - Collect action records for inclusion in email reports

Handles AccessDenied, NoSuchProcess, and race conditions gracefully.
"""

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from pxguard.core.process_resolver import ProcessInfo, UNKNOWN_PROCESS

logger = logging.getLogger(__name__)

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    _PSUTIL_AVAILABLE = False


@dataclass
class ReactionRecord:
    """One automated response action."""

    timestamp: float
    pid: int
    process_name: str
    exe: str
    file_path: str
    action: str
    success: bool
    detail: str = ""

    def format_log(self) -> str:
        status = "OK" if self.success else "FAILED"
        return (
            "[REACTION] %s pid=%d name=%s exe=%s file=%s — %s"
            % (self.action, self.pid, self.process_name, self.exe, self.file_path, status)
        )

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "pid": self.pid,
            "process_name": self.process_name,
            "exe": self.exe,
            "file_path": self.file_path,
            "action": self.action,
            "success": self.success,
            "detail": self.detail,
        }


_PROTECTED_NAMES = frozenset({
    "systemd", "init", "kernel", "kthreadd", "sshd", "login",
    "dbus-daemon", "NetworkManager", "udevd", "journald",
})


class ReactionEngine:
    """
    Automated incident response.
    On CRITICAL events with a resolved process:
      1. Attempt to terminate the process (SIGTERM → SIGKILL fallback)
      2. Log the action
      3. Store the ReactionRecord for email/report inclusion
    Protected system processes and SELF are never terminated.
    """

    def __init__(self, *, enabled: bool = False, self_pid: Optional[int] = None) -> None:
        self._enabled = enabled and _PSUTIL_AVAILABLE
        self._self_pid = self_pid if self_pid is not None else os.getpid()
        self._actions: list[ReactionRecord] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def actions(self) -> list[ReactionRecord]:
        return list(self._actions)

    def clear_actions(self) -> None:
        self._actions.clear()

    def react(
        self,
        file_path: str,
        severity: str,
        process_info: ProcessInfo,
    ) -> Optional[ReactionRecord]:
        """
        Evaluate whether to take action. Only acts on CRITICAL with a resolved process.
        Returns ReactionRecord if action was attempted, None otherwise.
        """
        if not self._enabled:
            return None
        if severity != "CRITICAL":
            return None
        if not process_info.resolved:
            logger.debug("[REACTION] No process resolved for %s — skipping", file_path)
            return None
        if process_info.is_self:
            logger.debug("[REACTION] Skipping SELF process (pid=%d)", process_info.pid)
            return None
        if process_info.pid == self._self_pid:
            return None

        if process_info.name and process_info.name.lower() in _PROTECTED_NAMES:
            record = ReactionRecord(
                timestamp=time.time(),
                pid=process_info.pid,
                process_name=process_info.name or "?",
                exe=process_info.exe or "?",
                file_path=file_path,
                action="SKIPPED_PROTECTED",
                success=False,
                detail="System process '%s' is protected" % process_info.name,
            )
            logger.warning(record.format_log())
            self._actions.append(record)
            return record

        return self._terminate(file_path, process_info)

    def _terminate(self, file_path: str, info: ProcessInfo) -> ReactionRecord:
        """Attempt SIGTERM then SIGKILL if needed."""
        if psutil is None:
            record = ReactionRecord(
                timestamp=time.time(),
                pid=info.pid or 0,
                process_name=info.name or "?",
                exe=info.exe or "?",
                file_path=file_path,
                action="TERMINATE",
                success=False,
                detail="psutil not available",
            )
            self._actions.append(record)
            return record

        try:
            proc = psutil.Process(info.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            record = ReactionRecord(
                timestamp=time.time(),
                pid=info.pid,
                process_name=info.name or "?",
                exe=info.exe or "?",
                file_path=file_path,
                action="TERMINATE",
                success=False,
                detail="Process gone or access denied: %s" % e,
            )
            logger.warning(record.format_log())
            self._actions.append(record)
            return record

        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
                record = ReactionRecord(
                    timestamp=time.time(),
                    pid=info.pid,
                    process_name=info.name or "?",
                    exe=info.exe or "?",
                    file_path=file_path,
                    action="TERMINATED",
                    success=True,
                    detail="Process terminated with SIGTERM",
                )
                logger.warning(record.format_log())
                self._actions.append(record)
                return record
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
                record = ReactionRecord(
                    timestamp=time.time(),
                    pid=info.pid,
                    process_name=info.name or "?",
                    exe=info.exe or "?",
                    file_path=file_path,
                    action="KILLED",
                    success=True,
                    detail="Process killed with SIGKILL after SIGTERM timeout",
                )
                logger.warning(record.format_log())
                self._actions.append(record)
                return record
        except psutil.NoSuchProcess:
            record = ReactionRecord(
                timestamp=time.time(),
                pid=info.pid,
                process_name=info.name or "?",
                exe=info.exe or "?",
                file_path=file_path,
                action="TERMINATED",
                success=True,
                detail="Process already exited",
            )
            logger.info(record.format_log())
            self._actions.append(record)
            return record
        except psutil.AccessDenied as e:
            record = ReactionRecord(
                timestamp=time.time(),
                pid=info.pid,
                process_name=info.name or "?",
                exe=info.exe or "?",
                file_path=file_path,
                action="TERMINATE",
                success=False,
                detail="Access denied: %s" % e,
            )
            logger.warning(record.format_log())
            self._actions.append(record)
            return record
        except Exception as e:
            record = ReactionRecord(
                timestamp=time.time(),
                pid=info.pid,
                process_name=info.name or "?",
                exe=info.exe or "?",
                file_path=file_path,
                action="TERMINATE",
                success=False,
                detail="Unexpected error: %s" % e,
            )
            logger.warning(record.format_log())
            self._actions.append(record)
            return record
