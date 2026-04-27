"""
audit.py
--------
Writes structured audit log entries for every ban, unban, and baseline
recalculation event.

Format:
  [2026-04-27T12:34:56Z] BAN     1.2.3.4 | z_score | rate=142.3 | mean=2.1 | duration=10m
  [2026-04-27T12:44:56Z] UNBAN   1.2.3.4 | backoff_schedule | offences=1
  [2026-04-27T13:00:00Z] BASELINE global | mean=3.14 | stddev=0.72 | window=30m
"""

import os
import threading
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditLogger:
    """Thread-safe structured audit logger."""

    def __init__(self, log_path: str):
        self._path = log_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        logger.info("AuditLogger writing to %s", log_path)

    def ban(self, ip: str, condition: str, rate: float,
            mean: float, duration: str) -> None:
        line = (f"[{_now()}] BAN     {ip} | {condition} | "
                f"rate={rate:.2f} | mean={mean:.2f} | duration={duration}")
        self._write(line)

    def unban(self, ip: str, condition: str, offence_count: int) -> None:
        line = (f"[{_now()}] UNBAN   {ip} | {condition} | "
                f"offences={offence_count}")
        self._write(line)

    def baseline(self, scope: str, mean: float, stddev: float,
                 window_minutes: int) -> None:
        line = (f"[{_now()}] BASELINE {scope} | "
                f"mean={mean:.4f} | stddev={stddev:.4f} | window={window_minutes}m")
        self._write(line)

    def _write(self, line: str) -> None:
        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
            except OSError as exc:
                logger.error("AuditLogger write error: %s", exc)
        # Also emit to standard logger so it appears in container stdout
        logger.info("AUDIT: %s", line)
