"""
unbanner.py
-----------
Automatically releases IP bans on a backoff schedule.

Schedule (from config):
  Offence 1 →  10 minutes
  Offence 2 →  30 minutes
  Offence 3 →   2 hours
  Offence 4+  →  permanent (no automatic release)

A background thread wakes every 10 seconds and checks whether any ban's
duration has expired.  On expiry it calls IPBlocker.release() and sends a
Slack unban notification.
"""

import time
import threading
import logging
from typing import List

logger = logging.getLogger(__name__)

PERMANENT = -1


class AutoUnbanner:
    """
    Watches all current bans and releases them when their timer expires.

    Parameters
    ----------
    blocker      : IPBlocker instance
    notifier     : SlackNotifier instance
    schedule     : list of durations in minutes, e.g. [10, 30, 120]
                   The offence_count determines which entry to use.
                   Beyond the last entry → permanent ban.
    check_interval : how often (seconds) to poll for expired bans
    """

    def __init__(self, blocker, notifier, schedule_minutes: List[int],
                 check_interval: int = 10):
        self._blocker = blocker
        self._notifier = notifier
        self._schedule = [m * 60 for m in schedule_minutes]  # convert to seconds
        self._check_interval = check_interval

        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._watch_loop, daemon=True, name="auto-unbanner"
        )
        self._thread.start()
        logger.info("AutoUnbanner started (schedule=%s min)", schedule_minutes)

    def ban_duration_for(self, offence_count: int) -> int:
        """
        Return the ban duration in seconds for the given offence number.
        offence_count is 1-indexed (first offence = 1).
        Returns PERMANENT (-1) if beyond the schedule.
        """
        idx = offence_count - 1
        if idx < len(self._schedule):
            return self._schedule[idx]
        return PERMANENT

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------
    # Background watch loop
    # ------------------------------------------------------------------

    def _watch_loop(self) -> None:
        while not self._stop.wait(timeout=self._check_interval):
            self._check_expired()

    def _check_expired(self) -> None:
        now = time.time()
        bans = self._blocker.all_bans()   # snapshot

        for ip, record in bans.items():
            if record.current_duration == PERMANENT:
                continue  # never auto-release permanent bans

            elapsed = now - record.banned_at
            if elapsed >= record.current_duration:
                logger.info(
                    "Ban expired for %s (offence %d, duration %ds)",
                    ip, record.offence_count, record.current_duration,
                )
                released = self._blocker.release(ip, condition="backoff_schedule")
                if released:
                    # Determine duration for potential next ban
                    next_duration = self.ban_duration_for(record.offence_count + 1)
                    next_dur_str = (
                        "permanent" if next_duration == PERMANENT
                        else f"{next_duration // 60}m"
                    )
                    self._notifier.send_unban(
                        ip=ip,
                        offence_count=record.offence_count,
                        was_duration=record.current_duration,
                        next_ban_duration=next_dur_str,
                    )
