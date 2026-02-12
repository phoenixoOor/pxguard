"""
PXGuard - Baseline comparison module.

Compares current filesystem state against baseline to detect
MODIFIED, DELETED, CREATED, and RENAMED files.
"""

import logging
from pathlib import Path
from typing import Any, Optional

from pxguard.core.models import EventType, FIMEvent, Severity
from pxguard.core.scanner import DirectoryScanner

logger = logging.getLogger(__name__)


class BaselineComparator:
    """
    Compares a current scan manifest against a baseline manifest
    and produces a list of FIMEvent objects.
    """

    def __init__(self, scanner: Optional[DirectoryScanner] = None) -> None:
        self.scanner = scanner or DirectoryScanner()

    def load_baseline(self, baseline_path: Path) -> dict[str, dict[str, Any]]:
        """Load baseline from JSON file."""
        import json

        path = baseline_path.resolve()
        if not path.is_file():
            logger.warning("Baseline file not found: %s", path)
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError) as e:
            logger.exception("Failed to load baseline: %s", e)
            return {}

    def save_baseline(self, baseline_path: Path, manifest: dict[str, dict[str, Any]]) -> None:
        """Persist manifest to baseline JSON file."""
        import json

        path = baseline_path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        except OSError as e:
            logger.exception("Failed to save baseline: %s", e)
            raise

    def compare(
        self,
        baseline: dict[str, dict[str, Any]],
        current: dict[str, dict[str, Any]],
    ) -> list[FIMEvent]:
        """
        Compare baseline and current manifests; return list of FIMEvent.

        - In baseline but not current → DELETED
        - In current but not baseline → CREATED (or RENAMED if hash reuse)
        - In both but hash differs → MODIFIED
        """
        events: list[FIMEvent] = []
        baseline_hashes: dict[str, str] = {p: d["hash"] for p, d in baseline.items()}
        current_hashes: dict[str, str] = {p: d["hash"] for p, d in current.items()}

        # Hash -> set of paths in baseline (for rename detection)
        hash_to_baseline_paths: dict[str, set[str]] = {}
        for path, data in baseline.items():
            h = data["hash"]
            hash_to_baseline_paths.setdefault(h, set()).add(path)

        # Deleted: in baseline, not in current
        for path in baseline:
            if path not in current:
                events.append(
                    FIMEvent(
                        event_type=EventType.DELETED,
                        file_path=path,
                        severity=Severity.WARNING,
                    )
                )

        # Created / Modified / Renamed
        for path, cur_data in current.items():
            cur_hash = cur_data["hash"]
            if path not in baseline:
                # New path: check if hash existed elsewhere → RENAMED
                old_paths = hash_to_baseline_paths.get(cur_hash)
                if old_paths and len(old_paths) == 1:
                    old_path = next(iter(old_paths))
                    events.append(
                        FIMEvent(
                            event_type=EventType.RENAMED,
                            file_path=path,
                            severity=Severity.INFO,
                            old_path=old_path,
                        )
                    )
                    # Consume so same hash isn't used for multiple renames
                    hash_to_baseline_paths.pop(cur_hash, None)
                else:
                    events.append(
                        FIMEvent(
                            event_type=EventType.CREATED,
                            file_path=path,
                            severity=Severity.INFO,
                        )
                    )
            else:
                base_data = baseline[path]
                if base_data["hash"] != cur_hash:
                    events.append(
                        FIMEvent(
                            event_type=EventType.MODIFIED,
                            file_path=path,
                            severity=Severity.WARNING,
                            metadata={
                                "old_hash": base_data["hash"],
                                "new_hash": cur_hash,
                            },
                        )
                    )

        return events
