"""
PXGuard - Threshold-based detection (ransomware-like behavior).

Tracks change count per time window and escalates to CRITICAL when exceeded.
Uses cooldown to trigger alert only once per window and prevent log spam.
"""

import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional

from pxguard.core.models import FIMEvent, Severity

logger = logging.getLogger(__name__)


@dataclass
class ThresholdConfig:
    """Configuration for change-rate threshold."""

    change_count: int
    time_window_seconds: float
    cooldown_seconds: float = 0.0  # 0 means use time_window_seconds


class ThresholdTracker:
    """
    Maintains a sliding window of event timestamps. When the number of
    events in the window exceeds change_count, events are marked CRITICAL
    (ransomware-like burst detection). Cooldown ensures the threshold
    alert fires only once until cooldown expires or count drops below threshold.
    """

    def __init__(self, config: ThresholdConfig) -> None:
        self.config = config
        self._timestamps: Deque[float] = deque()
        self._cooldown_until: Optional[float] = None
        self._cooldown_sec = config.cooldown_seconds or config.time_window_seconds

    def _prune_old(self, now: float) -> None:
        cutoff = now - self.config.time_window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def record_and_escalate(self, events: list[FIMEvent]) -> list[FIMEvent]:
        """
        Record event count in the time window. If over threshold and not in cooldown,
        escalate severity to CRITICAL once; then enter cooldown to prevent spam.
        """
        now = time.monotonic()
        self._prune_old(now)

        # Exit cooldown if: count dropped below threshold OR cooldown time expired
        if self._cooldown_until is not None:
            if now >= self._cooldown_until or len(self._timestamps) < self.config.change_count:
                self._cooldown_until = None

        for _ in events:
            self._timestamps.append(now)

        over_threshold = len(self._timestamps) >= self.config.change_count
        # Only escalate and log once per cooldown window
        in_cooldown = self._cooldown_until is not None
        should_escalate = over_threshold and not in_cooldown

        if should_escalate:
            logger.warning(
                "Threshold exceeded: %d changes in %.0fs (limit %d); cooldown %.0fs",
                len(self._timestamps),
                self.config.time_window_seconds,
                self.config.change_count,
                self._cooldown_sec,
            )
            self._cooldown_until = now + self._cooldown_sec

        result: list[FIMEvent] = []
        for e in events:
            if should_escalate:
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
