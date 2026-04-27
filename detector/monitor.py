"""
monitor.py
----------
Continuously tails the Nginx JSON access log and emits parsed log entries
as Python dicts to any registered callback.

Each parsed entry contains:
  source_ip, timestamp, method, path, status, response_size
"""

import json
import os
import time
import threading
import logging
from typing import Callable, List

logger = logging.getLogger(__name__)


class LogEntry:
    """Structured representation of a single Nginx access log line."""

    __slots__ = ("source_ip", "timestamp", "method", "path", "status", "response_size", "raw")

    def __init__(self, source_ip: str, timestamp: float, method: str,
                 path: str, status: int, response_size: int, raw: str = ""):
        self.source_ip = source_ip
        self.timestamp = timestamp
        self.method = method
        self.path = path
        self.status = status
        self.response_size = response_size
        self.raw = raw

    def is_error(self) -> bool:
        return self.status >= 400

    def __repr__(self):
        return (f"LogEntry(ip={self.source_ip}, status={self.status}, "
                f"path={self.path}, ts={self.timestamp})")


class LogMonitor:
    """
    Tails a file in real time (like `tail -F`) and dispatches parsed LogEntry
    objects to all registered callbacks.

    Uses a background daemon thread so the caller is never blocked.
    Handles log rotation by re-opening when the inode changes or the file
    shrinks (truncation).
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._callbacks: List[Callable[[LogEntry], None]] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def register(self, callback: Callable[[LogEntry], None]) -> None:
        """Register a function to be called with every new LogEntry."""
        self._callbacks.append(callback)

    def start(self) -> None:
        """Start the background tailing thread."""
        self._thread = threading.Thread(target=self._tail_loop, daemon=True, name="log-monitor")
        self._thread.start()
        logger.info("LogMonitor started on %s", self.log_path)

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _tail_loop(self) -> None:
        """
        Main tail loop.  Opens the log file, seeks to the end (we only care
        about new traffic, not replaying history on start), then reads new
        lines as they arrive.  On rotation or truncation it re-opens.
        """
        fh = None
        last_inode = None

        while not self._stop_event.is_set():
            # (Re-)open file when it doesn't exist yet or inode changed
            try:
                current_inode = os.stat(self.log_path).st_ino
            except FileNotFoundError:
                time.sleep(1)
                continue

            if fh is None or current_inode != last_inode:
                if fh:
                    fh.close()
                fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
                fh.seek(0, 2)          # seek to end – skip existing data on first open
                last_inode = current_inode
                logger.info("LogMonitor (re)opened %s", self.log_path)

            # Read all available new lines
            while not self._stop_event.is_set():
                line = fh.readline()
                if not line:
                    # Check for truncation: if file position > file size the
                    # log was rotated/truncated; break inner loop to re-open.
                    try:
                        if fh.tell() > os.path.getsize(self.log_path):
                            break
                    except OSError:
                        break
                    time.sleep(0.05)   # 50 ms poll interval
                    continue

                line = line.strip()
                if not line:
                    continue

                entry = self._parse_line(line)
                if entry:
                    self._dispatch(entry)

        if fh:
            fh.close()

    def _parse_line(self, line: str) -> LogEntry | None:
        """
        Parse one JSON log line.  Returns None on any parse error so the
        daemon never crashes due to a malformed log entry.

        Expected JSON keys (matching nginx.conf log_format):
          source_ip, time_local, request_method, request_uri, status,
          body_bytes_sent
        """
        try:
            obj = json.loads(line)

            # Resolve the real client IP: honour X-Forwarded-For forwarded by Nginx
            source_ip = (
                obj.get("http_x_forwarded_for")
                or obj.get("source_ip")
                or obj.get("remote_addr")
                or "0.0.0.0"
            )
            # X-Forwarded-For may be a comma-list; take the first (leftmost) entry
            source_ip = source_ip.split(",")[0].strip()

            # Parse timestamp – Nginx time_local: "27/Apr/2026:12:34:56 +0000"
            ts_raw = obj.get("time_iso8601") or obj.get("timestamp") or obj.get("time_local", "")
            timestamp = self._parse_timestamp(ts_raw)

            method = obj.get("request_method") or obj.get("method", "UNKNOWN")
            path = obj.get("request_uri") or obj.get("path", "/")
            status = int(obj.get("status", 0))
            response_size = int(obj.get("body_bytes_sent") or obj.get("response_size") or 0)

            return LogEntry(
                source_ip=source_ip,
                timestamp=timestamp,
                method=method,
                path=path,
                status=status,
                response_size=response_size,
                raw=line,
            )
        except Exception as exc:
            logger.debug("Failed to parse log line: %s | error: %s", line[:120], exc)
            return None

    @staticmethod
    def _parse_timestamp(ts_raw: str) -> float:
        """
        Convert Nginx timestamp string to a UNIX float.
        Supports ISO-8601 and Nginx default time_local format.
        Falls back to time.time() if parsing fails.
        """
        if not ts_raw:
            return time.time()
        from datetime import datetime, timezone

        # ISO-8601 produced by $time_iso8601 in nginx.conf
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S+%f"):
            try:
                return datetime.strptime(ts_raw[:25], fmt).timestamp()
            except ValueError:
                pass

        # Nginx default: "27/Apr/2026:12:34:56 +0000"
        try:
            dt = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
            return dt.timestamp()
        except ValueError:
            pass

        return time.time()

    def _dispatch(self, entry: LogEntry) -> None:
        for cb in self._callbacks:
            try:
                cb(entry)
            except Exception as exc:
                logger.error("Callback error: %s", exc)
