"""
PXGuard - Hashing module.

Computes SHA256 hashes for file integrity verification.
"""

import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class HashEngine:
    """Computes and verifies file hashes using SHA256."""

    ALGORITHM = "sha256"
    CHUNK_SIZE = 8192

    def __init__(self, chunk_size: int = CHUNK_SIZE) -> None:
        self.chunk_size = chunk_size

    def compute_file_hash(self, file_path: Path) -> Optional[str]:
        """
        Compute SHA256 hash of a file.

        Args:
            file_path: Path to the file.

        Returns:
            Hex-encoded SHA256 hash string, or None on error.
        """
        if not file_path.is_file():
            logger.warning("Not a file or does not exist: %s", file_path)
            return None

        try:
            hasher = hashlib.new(self.ALGORITHM)
            with open(file_path, "rb") as f:
                while chunk := f.read(self.chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, PermissionError) as e:
            logger.exception("Failed to hash %s: %s", file_path, e)
            return None
