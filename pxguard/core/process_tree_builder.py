"""
PXGuard - Process tree builder.

Constructs the full parent chain (child → … → init) for a given PID.
Used for forensic analysis and suspicious-parent detection.

Depth is capped at MAX_DEPTH (10) to prevent infinite loops from
circular ppid references.  Every psutil call is individually wrapped
so a single AccessDenied or NoSuchProcess never crashes the walk.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

MAX_DEPTH = 10

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False

_PSUTIL_ERRORS = (
    (psutil.NoSuchProcess if psutil else Exception),
    (psutil.AccessDenied if psutil else Exception),
    (psutil.ZombieProcess if psutil else Exception),
    OSError,
)


@dataclass(frozen=True, slots=True)
class TreeNode:
    """One process in the parent chain."""

    pid: int
    name: str
    exe: str
    username: str
    cmdline: str

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "username": self.username,
            "cmdline": self.cmdline,
        }


@dataclass
class ProcessTree:
    """
    Ordered parent chain: nodes[0] is the target process,
    nodes[-1] is the topmost ancestor reached (ideally init/PID 1).
    """

    nodes: list[TreeNode] = field(default_factory=list)

    @property
    def depth(self) -> int:
        return len(self.nodes)

    @property
    def empty(self) -> bool:
        return len(self.nodes) == 0

    @property
    def root(self) -> Optional[TreeNode]:
        return self.nodes[-1] if self.nodes else None

    def format_tree(self) -> str:
        """
        Indented tree for logs / plain-text reports.

        Example:
            pid=1234 [python3] exe=/usr/bin/python3 user=phoenix
            └─ pid=1100 [bash] exe=/usr/bin/bash user=phoenix
               └─ pid=1050 [sshd] exe=/usr/sbin/sshd user=root
                  └─ pid=1 [systemd] exe=/lib/systemd/systemd user=root
        """
        if not self.nodes:
            return "[empty tree]"
        lines: list[str] = []
        for i, node in enumerate(self.nodes):
            prefix = "   " * i + ("\u2514\u2500 " if i > 0 else "")
            lines.append(
                "%spid=%d [%s] exe=%s user=%s"
                % (prefix, node.pid, node.name, node.exe, node.username)
            )
        return "\n".join(lines)

    def format_oneline(self) -> str:
        """Compact single-line: 'python3(1234) → bash(1100) → sshd(1050) → systemd(1)'."""
        if not self.nodes:
            return "[empty]"
        return " \u2192 ".join(
            "%s(%d)" % (n.name, n.pid) for n in self.nodes
        )

    def to_list(self) -> list[dict]:
        return [n.to_dict() for n in self.nodes]


EMPTY_TREE = ProcessTree()


class ProcessTreeBuilder:
    """
    Builds the parent chain for a PID.
    Walks ppid → ppid until PID 0/1 or MAX_DEPTH is reached.
    """

    def __init__(self, self_pid: Optional[int] = None) -> None:
        self._self_pid = self_pid if self_pid is not None else os.getpid()

    @staticmethod
    def available() -> bool:
        return _PSUTIL_AVAILABLE

    def build(self, pid: int) -> ProcessTree:
        """
        Build the parent chain starting from *pid*.
        Returns EMPTY_TREE if psutil is missing or the process is gone.
        Never raises.
        """
        if not _PSUTIL_AVAILABLE or pid is None:
            return EMPTY_TREE

        nodes: list[TreeNode] = []
        visited: set[int] = set()
        current_pid = pid

        for _ in range(MAX_DEPTH):
            if current_pid in visited or current_pid < 0:
                break
            visited.add(current_pid)

            node = self._snapshot(current_pid)
            if node is None:
                break
            nodes.append(node)

            if current_pid <= 1:
                break

            next_pid = self._get_ppid(current_pid)
            if next_pid is None or next_pid == current_pid:
                break
            current_pid = next_pid

        return ProcessTree(nodes=nodes)

    def build_from_info(self, pid: Optional[int], ppid: Optional[int]) -> ProcessTree:
        """
        Build tree starting from a resolved ProcessInfo.
        Uses pid as the starting point.
        """
        if pid is None:
            return EMPTY_TREE
        return self.build(pid)

    @staticmethod
    def _snapshot(pid: int) -> Optional[TreeNode]:
        """Capture a point-in-time snapshot of a single process."""
        try:
            proc = psutil.Process(pid)
        except _PSUTIL_ERRORS:
            return None

        name = "?"
        exe = "?"
        username = "?"
        cmdline = ""

        try:
            name = proc.name() or "?"
        except _PSUTIL_ERRORS:
            pass
        try:
            exe = proc.exe() or "?"
        except _PSUTIL_ERRORS:
            pass
        try:
            username = proc.username() or "?"
        except _PSUTIL_ERRORS:
            pass
        try:
            parts = proc.cmdline()
            cmdline = " ".join(parts)[:200] if parts else ""
        except _PSUTIL_ERRORS:
            pass

        return TreeNode(
            pid=pid,
            name=name,
            exe=exe,
            username=username,
            cmdline=cmdline,
        )

    @staticmethod
    def _get_ppid(pid: int) -> Optional[int]:
        try:
            return psutil.Process(pid).ppid()
        except _PSUTIL_ERRORS:
            return None
