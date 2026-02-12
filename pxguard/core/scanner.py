"""
PXGuard - Directory scanner module.

Recursively scans directories and builds file manifests with hashes.
"""

import fnmatch
import logging
from pathlib import Path
from typing import Any, Optional

from pxguard.core.hashing import HashEngine

logger = logging.getLogger(__name__)


class DirectoryScanner:
    """
    Scans directories recursively and produces a manifest of files
    with hash, size, and last_modified.
    """

    def __init__(
        self,
        hash_engine: Optional[HashEngine] = None,
        exclude_patterns: Optional[list[str]] = None,
    ) -> None:
        self.hash_engine = hash_engine or HashEngine()
        self.exclude_patterns = exclude_patterns or []

    def _should_exclude(self, path: Path, root: Path) -> bool:
        """Check if path matches any exclude pattern (glob-style relative to root)."""
        try:
            rel = path.relative_to(root)
        except ValueError:
            return False
        rel_str = str(rel)
        for pattern in self.exclude_patterns:
            if "/" in pattern:
                if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(rel_str, "**/" + pattern):
                    return True
            else:
                if fnmatch.fnmatch(path.name, pattern):
                    return True
        return False

    def scan_directory(self, directory: Path) -> dict[str, dict[str, Any]]:
        """
        Recursively scan a directory and return a manifest.

        Returns:
            Dict mapping filepath (str) to {"hash", "size", "last_modified"}.
            Paths are normalized as strings for JSON compatibility.
        """
        directory = directory.resolve()
        if not directory.is_dir():
            logger.warning("Not a directory: %s", directory)
            return {}

        manifest: dict[str, dict[str, Any]] = {}
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            if self._should_exclude(path, directory):
                continue
            try:
                stat = path.stat()
                file_hash = self.hash_engine.compute_file_hash(path)
                if file_hash is None:
                    continue
                # Use path as string; relative to directory for consistency
                try:
                    key = str(path.relative_to(directory))
                except ValueError:
                    key = str(path)
                manifest[key] = {
                    "hash": file_hash,
                    "size": stat.st_size,
                    "last_modified": stat.st_mtime,
                }
            except (OSError, PermissionError) as e:
                logger.warning("Skipping %s: %s", path, e)
                continue
        return manifest

    def scan_directories(
        self, directories: list[Path], base_path: Optional[Path] = None
    ) -> dict[str, dict[str, Any]]:
        """
        Scan multiple directories and merge manifests.

        Keys are prefixed with directory name (relative to base_path) to avoid
        collisions when the same relative path exists in multiple dirs.
        """
        merged: dict[str, dict[str, Any]] = {}
        base = base_path or Path.cwd()
        for directory in directories:
            directory = (base / directory).resolve() if not directory.is_absolute() else directory
            if not directory.is_dir():
                logger.warning("Skipping non-directory: %s", directory)
                continue
            try:
                prefix = str(directory.relative_to(base))
            except ValueError:
                prefix = directory.name
            manifest = self.scan_directory(directory)
            for rel_path, data in manifest.items():
                merged[f"{prefix}/{rel_path}"] = data
        return merged
