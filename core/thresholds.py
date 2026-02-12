"""
PXGuard - Threshold-based detection (ransomware-like behavior).

Tracks change count per time window and escalates to CRITICAL when exceeded.
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from core.models import FIMEvent, Severity

logger = logging.getLogger(__name__)


@dataclass
class ThresholdConfig:
    """Configuration for change-rate threshold."""

    change_count: int
    time_window_seconds: float


class ThresholdTracker:
    """
    Maintains a sliding window of event timestamps. When the number of
    events in the window exceeds change_count, events are marked CRITICAL
    (ransomware-like burst detection).
    """

    def __init__(self, config: ThresholdConfig) -> None:
        self.config = config
        self._timestamps: Deque[float] = deque()

    def _prune_old(self, now: float) -> None:
        cutoff = now - self.config.time_window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def record_and_escalate(self, events: list[FIMEvent]) -> list[FIMEvent]:
        """
        Record event count in the time window. If over threshold,
        escalate severity to CRITICAL for returned events (copy).
        """
        now = time.monotonic()
        self._prune_old(now)
        for _ in events:
            self._timestamps.append(now)
        over_threshold = len(self._timestamps) >= self.config.change_count
        if over_threshold:
            logger.warning(
                "Threshold exceeded: %d changes in %.0fs (limit %d)",
                len(self._timestamps),
                self.config.time_window_seconds,
                self.config.change_count,
            )
        result: list[FIMEvent] = []
        for e in events:
            if over_threshold:
                result.append(
                    FIMEvent(
                        event_type=e.event_type,
                        file_path=e.file_path,
                        severity=Severity.CRITICAL,
                        old_path=e.old_path,
                        metadata={**e.metadata, "threshold_exceeded": True},
                    )
                )
            else:
                result.append(e)
        return result
