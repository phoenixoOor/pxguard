"""
PXGuard - Ransomware behavior simulator.

Simulates encryption by Base64 encoding or appending .locked.
Only operates inside the configured test directory (safety).
"""

import base64
import logging
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _resolve_allowed_root(project_root: Path, allowed_root: Path) -> Path:
    """Resolve allowed_root; if relative, relative to project_root."""
    project_root = Path(project_root)
    allowed_root = Path(allowed_root)
    if allowed_root.is_absolute():
        return allowed_root.resolve()
    return (project_root / allowed_root).resolve()


def _is_under(path: Path, directory: Path) -> bool:
    """Return True if path is under directory (canonical)."""
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def run_simulation(
    project_root: Path,
    allowed_root: Path,
    config_path: Optional[Path] = None,
    mode: str = "base64",
) -> None:
    """
    Run ransomware simulation: modify files only under allowed_root.

    Args:
        project_root: Project root (for resolving paths).
        allowed_root: Only files under this directory are touched.
        config_path: Optional config path for logging.
        mode: "base64" (encode contents) or "extension" (append .locked).
    """
    project_root = Path(project_root)
    allowed_root = Path(allowed_root)
    root = _resolve_allowed_root(project_root, allowed_root)
    if not root.is_dir():
        logger.error("Simulator allowed root does not exist or is not a directory: %s", root)
        print(f"[SIMULATOR] ERROR: Allowed root not found: {root}", file=sys.stderr)
        return

    logger.info("Starting ransomware simulator (root=%s, mode=%s)", root, mode)
    print(f"[SIMULATOR] Operating only under: {root}", file=sys.stderr)

    count = 0
    first_modified: Optional[Path] = None
    all_empty = True
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if not _is_under(path, root):
            continue
        try:
            if mode == "base64":
                size_before = path.stat().st_size
                _simulate_base64(path)
                if path.stat().st_size > 0:
                    all_empty = False
            else:
                _simulate_extension(path)
                all_empty = False
            if first_modified is None:
                first_modified = path
            count += 1
            logger.info("Simulated: %s", path)
            print(f"[SIMULATOR] Modified: {path}", file=sys.stderr)
        except Exception as e:
            logger.warning("Skip %s: %s", path, e)

    logger.info("Simulation complete: %d files processed", count)
    print(f"[SIMULATOR] Done. Modified {count} files.", file=sys.stderr)
    if count > 0 and mode == "base64":
        if all_empty:
            print(
                "[SIMULATOR] All files were empty; content stayed empty (Base64 of empty is empty). "
                "Add some text to files in test_assets to see visible Base64 content.",
                file=sys.stderr,
            )
        elif first_modified is not None:
            print(f"[SIMULATOR] Content is now Base64. Verify: head -c 80 {first_modified}", file=sys.stderr)


def _simulate_base64(file_path: Path) -> None:
    """Overwrite file with Base64-encoded content (simulated encryption)."""
    content = file_path.read_bytes()
    encoded = base64.b64encode(content)
    file_path.write_bytes(encoded)
    # Verify write: re-read and ensure content is now base64
    written = file_path.read_bytes()
    if written != encoded:
        raise IOError(f"Write verification failed: file content mismatch (len {len(written)} vs {len(encoded)})")


def _simulate_extension(file_path: Path) -> None:
    """Rename file to append .locked (simulated encryption)."""
    new_path = file_path.with_suffix(file_path.suffix + ".locked")
    file_path.rename(new_path)
