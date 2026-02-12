"""
PXGuard - File Integrity Monitoring Core Module.

Provides hashing, scanning, comparison, alerting, and threshold detection
for production-style FIM on Linux.
"""

from pxguard.core.hashing import HashEngine
from pxguard.core.scanner import DirectoryScanner
from pxguard.core.comparator import BaselineComparator
from pxguard.core.alerts import AlertManager
from pxguard.core.thresholds import ThresholdTracker

__all__ = [
    "HashEngine",
    "DirectoryScanner",
    "BaselineComparator",
    "AlertManager",
    "ThresholdTracker",
]
