"""
PXGuard - Suspicious parent detection.

Analyzes a ProcessTree for indicators that the responsible process
(or one of its ancestors) is suspicious:

  - Known offensive tool names (ncat, socat, meterpreter, …)
  - Executable running from /tmp or /dev/shm  (common malware staging)
  - Executable running from a user's home directory under unusual names
  - Interpreters (python, perl, ruby) spawned by a network listener
  - Mismatched username (child runs as root, parent as non-root or vice versa)

When any rule fires, the analyzer returns a ParentAnalysis with
escalate_to_critical=True so the monitor can upgrade the event severity.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from pxguard.core.process_tree_builder import ProcessTree, TreeNode, EMPTY_TREE

logger = logging.getLogger(__name__)

# ── detection rules ────────────────────────────────────────────────────────

_SUSPICIOUS_NAMES = frozenset({
    "ncat", "nc", "netcat", "socat",
    "nmap", "masscan", "zmap",
    "meterpreter", "msfconsole", "msfvenom",
    "reverse_tcp", "bind_tcp",
    "mimikatz", "lazagne", "crackmapexec",
    "chisel", "ligolo", "plink",
    "xmrig", "minerd", "cpuminer",
    "cryptolocker", "wannacry", "locky",
    "cobalt", "beacon",
})

_SUSPICIOUS_EXE_PREFIXES = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
)

_NETWORK_LISTENERS = frozenset({
    "ncat", "nc", "netcat", "socat",
    "sshd", "telnetd", "inetd", "xinetd",
    "nginx", "apache2", "httpd", "lighttpd",
})

_INTERPRETERS = frozenset({
    "python", "python2", "python3",
    "python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13",
    "perl", "ruby", "node", "php", "lua",
})

_HOME_EXCEPTIONS = frozenset({
    "bash", "sh", "zsh", "fish",
    "vim", "nvim", "nano", "emacs",
    "git", "ssh", "scp", "rsync",
    "python", "python3", "node", "ruby", "perl",
    "code", "cursor", "pycharm",
})


# ── result ─────────────────────────────────────────────────────────────────

@dataclass
class ParentAnalysis:
    """Result of analyzing one process tree."""

    suspicious: bool = False
    escalate_to_critical: bool = False
    reasons: list[str] = field(default_factory=list)
    flagged_nodes: list[dict] = field(default_factory=list)

    def format_log(self) -> str:
        if not self.suspicious:
            return "[PARENT_OK]"
        return "[SUSPICIOUS_PARENT] %s" % "; ".join(self.reasons)

    def to_dict(self) -> dict:
        return {
            "suspicious": self.suspicious,
            "escalate_to_critical": self.escalate_to_critical,
            "reasons": self.reasons,
            "flagged_nodes": self.flagged_nodes,
        }


CLEAN_ANALYSIS = ParentAnalysis()


# ── analyzer ───────────────────────────────────────────────────────────────

class ParentAnalyzer:
    """
    Stateless analyzer: takes a ProcessTree, returns ParentAnalysis.
    Each rule method appends to reasons/flagged_nodes if triggered.
    """

    def analyze(self, tree: ProcessTree) -> ParentAnalysis:
        """
        Run all detection rules against every node in the tree.
        Returns CLEAN_ANALYSIS if nothing is suspicious.
        """
        if tree.empty:
            return CLEAN_ANALYSIS

        reasons: list[str] = []
        flagged: list[dict] = []

        for node in tree.nodes:
            self._check_suspicious_name(node, reasons, flagged)
            self._check_tmp_exe(node, reasons, flagged)
            self._check_home_exe(node, reasons, flagged)

        self._check_interpreter_from_listener(tree, reasons, flagged)
        self._check_username_mismatch(tree, reasons, flagged)

        if not reasons:
            return CLEAN_ANALYSIS

        return ParentAnalysis(
            suspicious=True,
            escalate_to_critical=True,
            reasons=reasons,
            flagged_nodes=flagged,
        )

    # ── individual rules ───────────────────────────────────────────────────

    @staticmethod
    def _check_suspicious_name(
        node: TreeNode,
        reasons: list[str],
        flagged: list[dict],
    ) -> None:
        name_lower = node.name.lower()
        if name_lower in _SUSPICIOUS_NAMES:
            reasons.append(
                "Suspicious process '%s' (pid=%d) in parent chain" % (node.name, node.pid)
            )
            flagged.append(node.to_dict())

    @staticmethod
    def _check_tmp_exe(
        node: TreeNode,
        reasons: list[str],
        flagged: list[dict],
    ) -> None:
        exe = node.exe
        if exe == "?":
            return
        for prefix in _SUSPICIOUS_EXE_PREFIXES:
            if exe.startswith(prefix):
                reasons.append(
                    "Process '%s' (pid=%d) running from %s" % (node.name, node.pid, prefix.rstrip("/"))
                )
                flagged.append(node.to_dict())
                return

    @staticmethod
    def _check_home_exe(
        node: TreeNode,
        reasons: list[str],
        flagged: list[dict],
    ) -> None:
        exe = node.exe
        if exe == "?" or not exe.startswith("/home/"):
            return
        name_lower = node.name.lower()
        if name_lower in _HOME_EXCEPTIONS:
            return
        reasons.append(
            "Uncommon process '%s' (pid=%d) running from /home" % (node.name, node.pid)
        )
        flagged.append(node.to_dict())

    @staticmethod
    def _check_interpreter_from_listener(
        tree: ProcessTree,
        reasons: list[str],
        flagged: list[dict],
    ) -> None:
        """Interpreter → network listener pattern (reverse shell indicator)."""
        if tree.depth < 2:
            return
        for i in range(tree.depth - 1):
            child = tree.nodes[i]
            parent = tree.nodes[i + 1]
            child_name = child.name.lower()
            parent_name = parent.name.lower()
            if child_name in _INTERPRETERS and parent_name in _NETWORK_LISTENERS:
                reasons.append(
                    "Interpreter '%s' (pid=%d) spawned by network listener '%s' (pid=%d)"
                    % (child.name, child.pid, parent.name, parent.pid)
                )
                flagged.append(child.to_dict())
                flagged.append(parent.to_dict())

    @staticmethod
    def _check_username_mismatch(
        tree: ProcessTree,
        reasons: list[str],
        flagged: list[dict],
    ) -> None:
        """Child runs as root but parent is non-root (privilege escalation indicator)."""
        if tree.depth < 2:
            return
        child = tree.nodes[0]
        parent = tree.nodes[1]
        if child.username == "?" or parent.username == "?":
            return
        if child.username == "root" and parent.username != "root":
            reasons.append(
                "Privilege escalation: '%s' (pid=%d, root) spawned by '%s' (pid=%d, %s)"
                % (child.name, child.pid, parent.name, parent.pid, parent.username)
            )
            flagged.append(child.to_dict())
            flagged.append(parent.to_dict())
