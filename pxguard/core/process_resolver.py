"""
PXGuard - Multi-strategy process resolver.

Since PXGuard uses polling-based scanning (not real-time inotify), the
writing process typically closes the file handle before the next scan
detects the change.  A single open_files() check therefore fails for
the vast majority of events.

This resolver applies three strategies in a single process-table scan:

  1. open_files  — process currently has the file open  (definitive)
  2. cmdline     — file path or parent directory in the command line
  3. CWD         — process working directory is near the file

resolve_batch() iterates the process table ONCE for all target files,
making it efficient even when dozens of files change per scan cycle.

All psutil errors (AccessDenied, NoSuchProcess, ZombieProcess) are
caught per-process so a single protected process never crashes the scan.
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
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False

# ---------------------------------------------------------------------------
#  Scoring constants
# ---------------------------------------------------------------------------
_SCORE_FILE_OPEN = 100
_SCORE_CMDLINE_FILE = 50
_SCORE_CMDLINE_DIR = 30
_SCORE_CWD_EXACT = 25
_SCORE_CWD_NEAR = 10
_SCORE_CWD_ANCESTOR = 4

_MIN_CONFIDENCE = 8
_SHELL_PENALTY = 0.4
_IDE_PENALTY = 0.3

# Shells get heavily penalised on heuristic matches because every
# interactive shell shares the user's project directory as CWD.
_SHELLS = frozenset({
    "bash", "sh", "zsh", "fish", "csh", "tcsh", "dash", "ksh",
})

# IDEs / editors / embedded browsers — they always have CWD in the
# project root but rarely are the actual file-modification source.
# open_files match (score 100) is NOT penalised, only heuristics.
_IDE_NAMES = frozenset({
    "cursor", "code", "code-oss", "codium",
    "cef_server",
    "pycharm", "idea", "webstorm", "goland", "clion", "rider",
    "phpstorm", "rubymine", "datagrip", "dataspell",
    "sublime_text", "atom",
})

# System daemons that never modify user files — skip entirely.
_IGNORE_NAMES = frozenset({
    "systemd", "init", "kernel", "kthreadd",
    "sshd", "login", "getty", "agetty",
    "dbus-daemon", "networkmanager", "udevd",
    "systemd-journald", "systemd-logind", "systemd-udevd",
    "systemd-resolved", "systemd-timesyncd",
    "polkitd", "accounts-daemon",
    "gdm", "gdm-session-worker", "lightdm",
    "xorg", "xwayland",
    "pipewire", "pulseaudio", "wireplumber",
    "snapd", "packagekitd",
    "at-spi-bus-launcher", "at-spi2-registryd",
})

# Max open-file descriptors before we skip the expensive open_files() call.
_MAX_FDS_FOR_OPEN_FILES = 500


# ---------------------------------------------------------------------------
#  Data classes
# ---------------------------------------------------------------------------
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
        Resolved  -> 'PID [process_name]'
        Self      -> 'PID [SELF]'
        Owner     -> '[user: name]'       (process exited, fs owner known)
        Unknown   -> '[UNKNOWN_PROCESS]'
        """
        if not self.resolved:
            if self.username:
                return "[user: %s]" % self.username
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


@dataclass
class _Target:
    """Pre-computed paths for a single target file."""
    original: str
    resolved_str: str
    parent_str: str


# ---------------------------------------------------------------------------
#  Resolver
# ---------------------------------------------------------------------------
class ProcessResolver:
    """
    Multi-strategy process resolver.

    resolve()       — single file  (delegates to resolve_batch)
    resolve_batch() — N files in one process-table scan
    """

    def __init__(self, self_pid: Optional[int] = None) -> None:
        self._self_pid = self_pid if self_pid is not None else os.getpid()

    @staticmethod
    def available() -> bool:
        return _PSUTIL_AVAILABLE

    # -- public API ---------------------------------------------------------

    def resolve(self, file_path: str) -> ProcessInfo:
        """Resolve a single file. Convenience wrapper around resolve_batch."""
        results = self.resolve_batch([file_path])
        return results.get(file_path, UNKNOWN_PROCESS)

    def resolve_batch(self, file_paths: list[str]) -> dict[str, ProcessInfo]:
        """
        Resolve processes for multiple files in one process-table scan.

        Iterates psutil.process_iter() exactly once.  For each process
        three strategies are evaluated against every target file:

          1. open_files  — definitive match  (score 100)
          2. cmdline     — strong heuristic  (score 30-50)
          3. CWD         — moderate heuristic (score 5-25)

        Shell processes (bash, zsh, …) receive a score penalty to avoid
        false attribution when the user's terminal shares the project CWD.
        """
        if not _PSUTIL_AVAILABLE or not file_paths:
            return {fp: UNKNOWN_PROCESS for fp in file_paths}

        # Pre-compute targets
        targets: dict[str, _Target] = {}
        for fp in file_paths:
            try:
                resolved = Path(fp).resolve()
                targets[fp] = _Target(
                    original=fp,
                    resolved_str=str(resolved),
                    parent_str=str(resolved.parent),
                )
            except (OSError, RuntimeError):
                pass

        if not targets:
            return {fp: UNKNOWN_PROCESS for fp in file_paths}

        # best[fp] = (score, psutil.Process)
        best: dict[str, tuple[float, "psutil.Process"]] = {}

        try:
            self._scan_processes(targets, best)
        except Exception as exc:
            logger.debug("[RESOLVER] Process scan failed: %s", exc)

        # Build final results (with file-owner fallback)
        results: dict[str, ProcessInfo] = {}
        for fp in file_paths:
            entry = best.get(fp)
            if entry and entry[0] >= _MIN_CONFIDENCE:
                results[fp] = self._build_info(entry[1])
            else:
                t = targets.get(fp)
                results[fp] = self._fallback_owner(t) if t else UNKNOWN_PROCESS
        return results

    # -- internals ----------------------------------------------------------

    def _scan_processes(
        self,
        targets: dict[str, _Target],
        best: dict[str, tuple[float, "psutil.Process"]],
    ) -> None:
        """Single pass over the process table."""
        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.info["pid"]
            if pid == self._self_pid or pid <= 2:
                continue

            raw_name = proc.info.get("name") or ""

            # Skip kernel threads ([kworker/…], [migration/…], …)
            if raw_name.startswith("[") and raw_name.endswith("]"):
                continue

            name_lower = raw_name.lower()
            if name_lower in _IGNORE_NAMES:
                continue

            is_shell = name_lower in _SHELLS
            is_ide = name_lower in _IDE_NAMES
            if is_shell:
                multiplier = _SHELL_PENALTY
            elif is_ide:
                multiplier = _IDE_PENALTY
            else:
                multiplier = 1.0

            recency = self._recency_bonus(proc) if multiplier >= 1.0 else 0.0

            self._strategy_open_files(proc, targets, best)
            self._strategy_cmdline(proc, targets, best, multiplier, recency)
            self._strategy_cwd(proc, targets, best, multiplier, recency)

    def _strategy_open_files(
        self,
        proc: "psutil.Process",
        targets: dict[str, _Target],
        best: dict[str, tuple[float, "psutil.Process"]],
    ) -> None:
        """Strategy 1: exact file-handle match (definitive)."""
        try:
            if hasattr(proc, "num_fds"):
                try:
                    if proc.num_fds() > _MAX_FDS_FOR_OPEN_FILES:
                        return
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess, OSError):
                    pass

            for f in proc.open_files():
                try:
                    f_str = str(Path(f.path).resolve())
                    for fp, t in targets.items():
                        if f_str == t.resolved_str:
                            best[fp] = (_SCORE_FILE_OPEN, proc)
                except (OSError, RuntimeError):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess, OSError):
            pass

    @staticmethod
    def _recency_bonus(proc: "psutil.Process") -> float:
        """
        Recently created processes are more likely to be the file modifier.
        Gives a score boost so a fresh 'rm' or script outranks a long-running
        background process that happens to share the same CWD.
        """
        try:
            import time
            age = time.time() - proc.create_time()
            if age < 30:
                return 4.0
            if age < 120:
                return 2.0
            return 0.0
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess, OSError):
            return 0.0

    def _strategy_cmdline(
        self,
        proc: "psutil.Process",
        targets: dict[str, _Target],
        best: dict[str, tuple[float, "psutil.Process"]],
        multiplier: float,
        recency: float = 0.0,
    ) -> None:
        """Strategy 2: file or directory path appears in the command line."""
        try:
            cmdline = proc.cmdline()
            if not cmdline:
                return
            cmd_str = " ".join(cmdline)
            for fp, t in targets.items():
                cur = best.get(fp, (0, None))[0]
                if cur >= _SCORE_FILE_OPEN:
                    continue
                score = 0.0
                if t.resolved_str in cmd_str:
                    score = _SCORE_CMDLINE_FILE * multiplier + recency
                elif t.parent_str in cmd_str:
                    score = _SCORE_CMDLINE_DIR * multiplier + recency
                if score > cur:
                    best[fp] = (score, proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess, OSError):
            pass

    def _strategy_cwd(
        self,
        proc: "psutil.Process",
        targets: dict[str, _Target],
        best: dict[str, tuple[float, "psutil.Process"]],
        multiplier: float,
        recency: float = 0.0,
    ) -> None:
        """Strategy 3: process CWD is at or near the file's directory."""
        try:
            cwd_str = str(Path(proc.cwd()).resolve())
            for fp, t in targets.items():
                cur = best.get(fp, (0, None))[0]
                if cur >= _SCORE_CMDLINE_DIR:
                    continue
                score = 0.0
                if cwd_str == t.parent_str:
                    score = _SCORE_CWD_EXACT * multiplier + recency
                elif t.parent_str.startswith(cwd_str + os.sep):
                    depth = t.parent_str[len(cwd_str):].count(os.sep)
                    if depth <= 3:
                        score = _SCORE_CWD_NEAR * multiplier + recency
                    else:
                        score = _SCORE_CWD_ANCESTOR * multiplier + recency
                if score > cur:
                    best[fp] = (score, proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess, OSError):
            pass

    def _build_info(self, proc: "psutil.Process") -> ProcessInfo:
        """Extract full details from a psutil.Process, tolerating partial failures."""
        try:
            pid = proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return UNKNOWN_PROCESS

        name = None
        exe = None
        username = None
        ppid = None

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

        return ProcessInfo(
            pid=pid,
            name=name,
            exe=exe,
            username=username,
            ppid=ppid,
            is_self=(pid == self._self_pid),
        )

    @staticmethod
    def _fallback_owner(target: _Target) -> ProcessInfo:
        """
        Last resort: identify the filesystem user who owns the parent
        directory.  Returns ProcessInfo with pid=None (not 'resolved'
        for reaction purposes) but username set for display.
        """
        try:
            import pwd
            stat = os.stat(target.parent_str)
            pw = pwd.getpwuid(stat.st_uid)
            return ProcessInfo(username=pw.pw_name)
        except Exception:
            return UNKNOWN_PROCESS
