"""
blocker.py
----------
Manages iptables DROP rules for banned IPs.

Each ban is recorded in an in-memory dict and written to the audit log.
The Unbanner (unbanner.py) calls release() when the backoff timer expires.

iptables commands require root.  The daemon should be run as root (or with
the NET_ADMIN capability) inside the Docker container.
"""

import subprocess
import time
import threading
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class BanRecord:
    __slots__ = ("ip", "banned_at", "offence_count", "current_duration")

    def __init__(self, ip: str, banned_at: float, offence_count: int, duration: int):
        self.ip = ip
        self.banned_at = banned_at
        self.offence_count = offence_count          # number of times this IP has been banned
        self.current_duration = duration            # seconds for current ban (-1 = permanent)


class IPBlocker:
    """
    Adds and removes iptables INPUT DROP rules for anomalous IPs.

    Thread-safe: all mutations are protected by a lock.
    """

    def __init__(self, audit_logger=None):
        self._lock = threading.Lock()
        self._bans: Dict[str, BanRecord] = {}
        self._audit = audit_logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ban(self, ip: str, duration_seconds: int, offence_count: int,
            condition: str, rate: float, mean: float) -> bool:
        """
        Drop all inbound packets from `ip` using iptables.

        Returns True if the rule was successfully inserted, False otherwise.
        """
        with self._lock:
            if ip in self._bans:
                logger.info("IP %s is already banned; skipping duplicate ban", ip)
                return False

            success = self._iptables_add(ip)
            if not success:
                return False

            record = BanRecord(
                ip=ip,
                banned_at=time.time(),
                offence_count=offence_count,
                duration=duration_seconds,
            )
            self._bans[ip] = record

        dur_str = self._fmt_duration(duration_seconds)
        logger.warning("BANNED %s | %s | rate=%.2f | mean=%.2f | duration=%s",
                       ip, condition, rate, mean, dur_str)

        if self._audit:
            self._audit.ban(ip=ip, condition=condition, rate=rate,
                            mean=mean, duration=dur_str)
        return True

    def release(self, ip: str, condition: str = "unban_schedule") -> bool:
        """Remove the iptables rule and delete the ban record."""
        with self._lock:
            if ip not in self._bans:
                logger.debug("Tried to release %s but it is not banned", ip)
                return False
            record = self._bans.pop(ip)

        success = self._iptables_remove(ip)
        dur_str = self._fmt_duration(record.current_duration)
        logger.info("UNBANNED %s | offences=%d | was_duration=%s",
                    ip, record.offence_count, dur_str)

        if self._audit:
            self._audit.unban(ip=ip, condition=condition,
                              offence_count=record.offence_count)
        return success

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._bans

    def get_ban(self, ip: str) -> Optional[BanRecord]:
        with self._lock:
            return self._bans.get(ip)

    def all_bans(self) -> Dict[str, BanRecord]:
        """Return a shallow copy of current bans for the dashboard."""
        with self._lock:
            return dict(self._bans)

    def offence_count(self, ip: str) -> int:
        with self._lock:
            rec = self._bans.get(ip)
            return rec.offence_count if rec else 0

    # ------------------------------------------------------------------
    # iptables helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iptables_add(ip: str) -> bool:
        """Insert a DROP rule at the top of the INPUT chain."""
        cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        return IPBlocker._run(cmd, f"add DROP rule for {ip}")

    @staticmethod
    def _iptables_remove(ip: str) -> bool:
        """Delete the DROP rule for `ip` (may need multiple calls if duplicated)."""
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        # Run until no more matching rules exist
        removed = False
        for _ in range(5):  # safety ceiling
            if IPBlocker._run(cmd, f"remove DROP rule for {ip}", check=False):
                removed = True
            else:
                break
        return removed

    @staticmethod
    def _run(cmd: list, description: str, check: bool = True) -> bool:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.debug("iptables OK: %s", description)
                return True
            else:
                if check:
                    logger.error("iptables FAILED (%s): %s | stderr: %s",
                                 description, " ".join(cmd), result.stderr.strip())
                return False
        except FileNotFoundError:
            logger.error("iptables binary not found – running without kernel blocking")
            return False
        except subprocess.TimeoutExpired:
            logger.error("iptables timed out: %s", description)
            return False

    @staticmethod
    def _fmt_duration(seconds: int) -> str:
        if seconds < 0:
            return "permanent"
        if seconds < 3600:
            return f"{seconds // 60}m"
        return f"{seconds // 3600}h"
