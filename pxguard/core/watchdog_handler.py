"""
PXGuard - Watchdog event handler for real-time file change detection.

Uses recursive observation and debouncing to avoid duplicate events and
to trigger a scan when files are created, modified, or deleted.
"""

import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional, Set

logger = logging.getLogger(__name__)

# Optional watchdog import
try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEvent,
        FileSystemEventHandler,
        FileCreatedEvent,
        FileModifiedEvent,
        FileDeletedEvent,
        DirCreatedEvent,
        DirDeletedEvent,
    )
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object  # type: ignore[misc, assignment]


class FIMEventHandler(FileSystemEventHandler):
    """
    Handles file system events for FIM: created, modified, deleted.
    Debounces by setting a shared flag and timestamp; the monitor loop
    runs a scan when the flag is set and debounce time has elapsed.
    """

    def __init__(
        self,
        on_pending_scan: Callable[[], None],
        debounce_seconds: float = 2.0,
        allowed_paths: Optional[Set[Path]] = None,
    ) -> None:
        super().__init__()
        self._on_pending_scan = on_pending_scan
        self._debounce_sec = max(0.5, debounce_seconds)
        self._allowed_paths = allowed_paths  # directories we care about
        self._lock = threading.Lock()
        self._pending_time: Optional[float] = None

    def _schedule_scan(self, path: str, event_type: str) -> None:
        """Record that a change occurred; caller will debounce and run scan."""
        with self._lock:
            now = time.monotonic()
            if self._pending_time is None:
                self._pending_time = now
            self._on_pending_scan()
        logger.debug("FIM event: %s %s (scan will run after debounce)", event_type, path)

    def _is_relevant(self, src_path: str) -> bool:
        if not self._allowed_paths:
            return True
        try:
            p = Path(src_path).resolve()
            for allowed in self._allowed_paths:
                try:
                    p.relative_to(allowed)
                    return True
                except ValueError:
                    continue
        except (OSError, RuntimeError):
            pass
        return False

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            if self._is_relevant(event.src_path):
                self._schedule_scan(event.src_path, "DirCreated")
        else:
            if self._is_relevant(event.src_path):
                self._schedule_scan(event.src_path, "Created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if self._is_relevant(event.src_path):
            self._schedule_scan(event.src_path, "Modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if self._is_relevant(event.src_path):
            self._schedule_scan(event.src_path, "Deleted" if not event.is_directory else "DirDeleted")


class DebouncedScanTrigger:
    """
    Tracks pending scan request and debounce time. The monitor loop should
    call should_run_scan() each cycle; when True, run one scan and then
    clear_pending().
    """

    def __init__(self, debounce_seconds: float = 2.0) -> None:
        self._debounce_sec = max(0.5, debounce_seconds)
        self._lock = threading.Lock()
        self._pending_time: Optional[float] = None

    def set_pending(self) -> None:
        with self._lock:
            if self._pending_time is None:
                self._pending_time = time.monotonic()

    def should_run_scan(self) -> bool:
        """True if a scan should run (pending and debounce elapsed)."""
        with self._lock:
            if self._pending_time is None:
                return False
            if time.monotonic() - self._pending_time >= self._debounce_sec:
                return True
            return False

    def clear_pending(self) -> None:
        with self._lock:
            self._pending_time = None


def start_watchdog_observer(
    directories: list[Path],
    handler: "FIMEventHandler",
    recursive: bool = True,
) -> Optional["Observer"]:
    """
    Start watchdog Observer watching the given directories recursively.
    Returns the Observer (call observer.stop() and observer.join() on shutdown).
    """
    if not WATCHDOG_AVAILABLE or Observer is None:
        logger.warning("watchdog not available; install with: pip install watchdog")
        return None
    observer = Observer()
    for directory in directories:
        dir_str = str(Path(directory).resolve())
        try:
            observer.schedule(handler, dir_str, recursive=recursive)
            logger.info("Watchdog observing %s (recursive=%s)", dir_str, recursive)
        except OSError as e:
            logger.warning("Cannot watch %s: %s", dir_str, e)
    observer.start()
    return observer
