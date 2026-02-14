"""
PXGuard - Advanced anomaly detection engine.

Replaces simple threshold with: static threshold, spike detection,
consecutive abnormal scans. State machine: NORMAL, SUSPICIOUS, ATTACK.
Cooldown prevents repeated alerts (default 5 min).
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Literal, Optional

logger = logging.getLogger(__name__)

AnomalyState = Literal["NORMAL", "SUSPICIOUS", "ATTACK"]

# Default cooldown seconds (5 min) between anomaly alerts
DEFAULT_ANOMALY_COOLDOWN_SECONDS = 300.0

# Window size for spike detection (mean of last N)
SPIKE_MEAN_WINDOW = 5

# Spike multiplier: current > mean(last_N) * this → anomaly
SPIKE_MULTIPLIER = 2.0

# Consecutive abnormal scans to escalate to ATTACK
CONSECUTIVE_ABNORMAL_FOR_ATTACK = 2


@dataclass
class AnomalyConfig:
    """Configuration for anomaly detection."""

    static_threshold: int
    """Static threshold: total changes above this → abnormal."""
    spike_multiplier: float = SPIKE_MULTIPLIER
    """Spike: current > mean(last N) * this → anomaly."""
    spike_window: int = SPIKE_MEAN_WINDOW
    """Number of recent scans for mean in spike detection."""
    consecutive_abnormal_for_attack: int = CONSECUTIVE_ABNORMAL_FOR_ATTACK
    """Consecutive abnormal scans to transition to ATTACK."""
    cooldown_seconds: float = DEFAULT_ANOMALY_COOLDOWN_SECONDS
    """Cooldown between anomaly-triggered alerts (e.g. report/email)."""


@dataclass
class AnomalyResult:
    """Result of evaluating one scan."""

    state: AnomalyState
    """Current state: NORMAL, SUSPICIOUS, ATTACK."""
    is_anomaly: bool
    """True if this scan should trigger report/email (respects cooldown)."""
    static_exceeded: bool
    """True if total changes exceeded static threshold."""
    spike_detected: bool
    """True if current > mean(last N) * multiplier."""
    consecutive_abnormal: int
    """Count of consecutive abnormal scans."""


class AnomalyEngine:
    """
    Advanced anomaly detection: static threshold, spike detection,
    consecutive abnormal scans. State machine with cooldown for alerts.
    No global mutable state; all state is on the instance.
    """

    def __init__(self, config: AnomalyConfig) -> None:
        self._config = config
        self._state: AnomalyState = "NORMAL"
        self._recent_totals: Deque[int] = deque(maxlen=max(config.spike_window, 10))
        self._consecutive_abnormal: int = 0
        self._cooldown_until: Optional[float] = None

    def evaluate(
        self,
        total_changes: int,
        created: int,
        modified: int,
        deleted: int,
    ) -> AnomalyResult:
        """
        Evaluate current scan totals. Returns state, is_anomaly (for report/email),
        and flags. Uses only real scan data; no dummy values.
        """
        static_exceeded = total_changes >= self._config.static_threshold

        # Spike: current > mean(last N) * multiplier (need at least 1 prior point)
        mean_recent = (
            sum(self._recent_totals) / len(self._recent_totals)
            if len(self._recent_totals) >= 1
            else 0.0
        )
        spike_detected = (
            mean_recent > 0
            and total_changes >= mean_recent * self._config.spike_multiplier
        )

        # Abnormal = static exceeded OR spike
        abnormal = static_exceeded or spike_detected
        if abnormal:
            self._consecutive_abnormal += 1
        else:
            self._consecutive_abnormal = 0

        # State machine
        if self._consecutive_abnormal >= self._config.consecutive_abnormal_for_attack:
            self._state = "ATTACK"
        elif abnormal:
            self._state = "SUSPICIOUS"
        else:
            self._state = "NORMAL"

        # Push current total for next spike mean (before we return)
        self._recent_totals.append(total_changes)

        # Should we trigger report/email? Only when anomaly and cooldown expired
        now = time.monotonic()
        if self._cooldown_until is not None and now < self._cooldown_until:
            is_anomaly = False
        else:
            is_anomaly = self._state in ("SUSPICIOUS", "ATTACK")
            if is_anomaly:
                self._cooldown_until = now + self._config.cooldown_seconds
                logger.warning(
                    "Anomaly detected: state=%s, static_exceeded=%s, spike=%s, consecutive=%d",
                    self._state,
                    static_exceeded,
                    spike_detected,
                    self._consecutive_abnormal,
                )

        return AnomalyResult(
            state=self._state,
            is_anomaly=is_anomaly,
            static_exceeded=static_exceeded,
            spike_detected=spike_detected,
            consecutive_abnormal=self._consecutive_abnormal,
        )

    def threat_level_for_dashboard(self) -> Literal["OK", "WARNING", "CRITICAL"]:
        """
        Map anomaly state to dashboard threat level (OK / WARNING / CRITICAL).
        Used for gauge and status display.
        """
        if self._state == "ATTACK":
            return "CRITICAL"
        if self._state == "SUSPICIOUS":
            return "WARNING"
        return "OK"
