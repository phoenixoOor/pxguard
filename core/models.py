"""
PXGuard - Shared data models (events, etc.).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EventType(str, Enum):
    """FIM event types."""

    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    CREATED = "CREATED"
    RENAMED = "RENAMED"


class Severity(str, Enum):
    """Alert severity levels."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class FIMEvent:
    """Structured FIM detection event."""

    event_type: EventType
    file_path: str
    severity: Severity = Severity.WARNING
    old_path: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "file_path": self.file_path,
            "severity": self.severity.value,
            "old_path": self.old_path,
            "metadata": self.metadata,
        }
