"""
PXGuard - File Integrity Monitoring Core Module.

Provides hashing, scanning, comparison, alerting, and threshold detection
for production-style FIM on Linux.
"""

from core.hashing import HashEngine
from core.scanner import DirectoryScanner
from core.comparator import BaselineComparator
from core.alerts import AlertManager
from core.thresholds import ThresholdTracker

__all__ = [
    "HashEngine",
    "DirectoryScanner",
    "BaselineComparator",
    "AlertManager",
    "ThresholdTracker",
]
