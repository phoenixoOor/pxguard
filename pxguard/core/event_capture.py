"""
PXGuard - Real-time event capture via inotify.

Runs a daemon thread that watches monitored directories using Linux
inotify.  When a file event fires, it immediately resolves the
responsible process (before it can exit) and caches the result.

The main scan loop then checks this cache, giving process attribution
that pure polling can never achieve — by the time a 10-second scan
cycle runs, short-lived processes (rm, mv, scripts) have long exited.

Linux-only.  Gracefully degrades to no-op on other platforms.
No external dependencies — uses ctypes to call libc directly.
"""

import ctypes
import ctypes.util
import logging
import os
import select
import struct
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Optional, Set, Tuple

if TYPE_CHECKING:
    from pxguard.core.process_resolver import ProcessInfo, ProcessResolver

logger = logging.getLogger(__name__)

# ── inotify constants ──────────────────────────────────────────────────────
IN_MODIFY = 0x00000002
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_ISDIR = 0x40000000
_WATCH_MASK = IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
_EVENT_HEADER = 16  # struct inotify_event: wd(4) + mask(4) + cookie(4) + len(4)

# ── libc probe ─────────────────────────────────────────────────────────────
_libc: Optional[ctypes.CDLL] = None
INOTIFY_AVAILABLE = False

try:
    _libc_name = ctypes.util.find_library("c")
    if _libc_name:
        _libc = ctypes.CDLL(_libc_name, use_errno=True)
        INOTIFY_AVAILABLE = hasattr(_libc, "inotify_init")
except Exception:
    pass


# ── Cache ──────────────────────────────────────────────────────────────────
class ProcessCaptureCache:
    """Thread-safe TTL cache: resolved_path → (ProcessInfo, timestamp)."""

    def __init__(self, ttl: float = 30.0) -> None:
        self._ttl = ttl
        self._data: Dict[str, Tuple["ProcessInfo", float]] = {}
        self._lock = threading.Lock()

    def put(self, resolved_path: str, info: "ProcessInfo") -> None:
        with self._lock:
            self._data[resolved_path] = (info, time.time())

    def get(self, resolved_path: str) -> Optional["ProcessInfo"]:
        with self._lock:
            entry = self._data.get(resolved_path)
            if entry:
                info, ts = entry
                if time.time() - ts < self._ttl:
                    return info
                del self._data[resolved_path]
        return None

    def cleanup(self) -> None:
        cutoff = time.time() - self._ttl
        with self._lock:
            self._data = {
                k: v for k, v in self._data.items() if v[1] >= cutoff
            }


# ── Capture thread ─────────────────────────────────────────────────────────
class EventCaptureThread:
    """
    Daemon thread: inotify watch → immediate process resolution → cache.

    Start with start().  The thread runs until stop() is called or
    the monitor exits (daemon=True auto-kills it).
    """

    def __init__(
        self,
        directories: list,
        resolver: "ProcessResolver",
        cache: ProcessCaptureCache,
    ) -> None:
        self._directories = []
        for d in directories:
            try:
                self._directories.append(str(Path(d).resolve()))
            except (OSError, RuntimeError):
                pass
        self._resolver = resolver
        self._cache = cache
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._inotify_fd = -1
        self._wd_map: Dict[int, str] = {}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        """Start the capture thread. Returns True on success."""
        if not INOTIFY_AVAILABLE or not _libc:
            logger.debug("[CAPTURE] inotify not available on this platform")
            return False
        try:
            fd = _libc.inotify_init()
            if fd < 0:
                logger.debug("[CAPTURE] inotify_init() failed (errno=%d)", ctypes.get_errno())
                return False
            self._inotify_fd = fd
            for d in self._directories:
                self._add_watches_recursive(d)
            if not self._wd_map:
                os.close(self._inotify_fd)
                self._inotify_fd = -1
                logger.debug("[CAPTURE] No watches added")
                return False
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="pxguard-capture",
            )
            self._thread.start()
            logger.info(
                "[CAPTURE] Real-time process capture active (%d watches)",
                len(self._wd_map),
            )
            return True
        except Exception as exc:
            logger.debug("[CAPTURE] Failed to start: %s", exc)
            if self._inotify_fd >= 0:
                try:
                    os.close(self._inotify_fd)
                except OSError:
                    pass
                self._inotify_fd = -1
            return False

    def stop(self) -> None:
        self._stop_event.set()
        if self._inotify_fd >= 0:
            try:
                os.close(self._inotify_fd)
            except OSError:
                pass
            self._inotify_fd = -1
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ── internal ───────────────────────────────────────────────────────────

    def _add_watches_recursive(self, path: str) -> None:
        try:
            wd = _libc.inotify_add_watch(
                self._inotify_fd, path.encode("utf-8"), _WATCH_MASK,
            )
            if wd >= 0:
                self._wd_map[wd] = path
        except OSError:
            pass
        try:
            with os.scandir(path) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        self._add_watches_recursive(entry.path)
        except (OSError, PermissionError):
            pass

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    ready, _, _ = select.select(
                        [self._inotify_fd], [], [], 0.5,
                    )
                except (ValueError, OSError):
                    break
                if not ready:
                    continue
                try:
                    buf = os.read(self._inotify_fd, 8192)
                except OSError:
                    break
                if not buf:
                    break
                self._handle_buffer(buf)
        except Exception as exc:
            logger.debug("[CAPTURE] Watch loop error: %s", exc)

    def _handle_buffer(self, buf: bytes) -> None:
        offset = 0
        paths: Set[str] = set()

        while offset + _EVENT_HEADER <= len(buf):
            wd, mask, _cookie, name_len = struct.unpack_from("iIII", buf, offset)
            offset += _EVENT_HEADER
            if offset + name_len > len(buf):
                break
            raw_name = buf[offset:offset + name_len]
            offset += name_len
            name = raw_name.rstrip(b"\0").decode("utf-8", errors="replace")

            if mask & IN_ISDIR:
                if mask & IN_CREATE:
                    dir_path = self._wd_map.get(wd)
                    if dir_path and name:
                        self._add_watches_recursive(os.path.join(dir_path, name))
                continue

            dir_path = self._wd_map.get(wd)
            if dir_path and name:
                paths.add(os.path.join(dir_path, name))

        if paths:
            try:
                results = self._resolver.resolve_batch(list(paths))
                for path, info in results.items():
                    if info.resolved:
                        self._cache.put(path, info)
                        logger.debug(
                            "[CAPTURE] Caught %s for %s",
                            info.format_source(), os.path.basename(path),
                        )
            except Exception as exc:
                logger.debug("[CAPTURE] Batch resolve error: %s", exc)
