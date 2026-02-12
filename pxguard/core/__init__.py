"""
PXGuard - File Integrity Monitoring Core Module.

Provides hashing, scanning, comparison, alerting, and threshold detection
for production-style FIM on Linux.
"""

from pxguard.core.alerts import AlertManager
from pxguard.core.comparator import BaselineComparator
from pxguard.core.dashboard import Dashboard
from pxguard.core.graph import ChangeGraph, TerminalGraph
from pxguard.core.hashing import HashEngine
from pxguard.core.rich_dashboard import RichDashboard
from pxguard.core.scanner import DirectoryScanner
from pxguard.core.thresholds import ThresholdTracker

__all__ = [
    "AlertManager",
    "BaselineComparator",
    "ChangeGraph",
    "Dashboard",
    "HashEngine",
    "DirectoryScanner",
    "TerminalGraph",
    "ThresholdTracker",
    "RichDashboard",
]
