"""
baseline.py
-----------
Maintains a rolling 30-minute window of per-second request counts and
computes an adaptive mean + stddev baseline recalculated every 60 seconds.

Design
------
- A collections.deque holds (timestamp_second, count) tuples.
  Old entries (> window_minutes old) are evicted on every recalculation.
- Per-hour slots track counts separately so the detector can prefer the
  current hour's baseline when it has enough samples (>= min_requests).
- Both a global baseline and per-IP baselines are maintained.
- Error-rate baselines are tracked in a parallel structure.
"""

import math
import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

# Type aliases
_Deque = deque  # deque[Tuple[float, int]]  (second_bucket, count)


class _HourSlot:
    """Aggregate stats for one clock hour."""
    __slots__ = ("hour_key", "total_requests", "seconds_seen", "mean", "stddev")

    def __init__(self, hour_key: int):
        self.hour_key = hour_key       # epoch // 3600
        self.total_requests = 0
        self.seconds_seen = 0
        self.mean = 0.0
        self.stddev = 0.0


class BaselineTracker:
    """
    Thread-safe tracker that maintains a rolling baseline for global traffic
    and per-IP traffic.

    Attributes exposed for the detector:
      global_baseline()   -> (mean, stddev)
      ip_baseline(ip)     -> (mean, stddev)
      error_baseline()    -> (mean, stddev)   # for global 4xx/5xx rate
      ip_error_baseline(ip) -> (mean, stddev)
    """

    def __init__(self, window_minutes: int = 30,
                 recalc_interval: int = 60,
                 min_requests: int = 10,
                 per_second_floor: float = 1.0,
                 error_rate_floor: float = 0.05):
        self._window_minutes = window_minutes
        self._recalc_interval = recalc_interval
        self._min_requests = min_requests
        self._per_second_floor = per_second_floor
        self._error_rate_floor = error_rate_floor

        self._lock = threading.Lock()

        # --- Global request counts: deque of (second_bucket, count) ---
        # second_bucket = int(timestamp) so multiple requests in the same
        # second accumulate into one entry.
        self._global_counts: _Deque = deque()
        self._global_current_second: int = 0
        self._global_current_count: int = 0

        # --- Per-IP counts: same structure, one deque per IP ---
        self._ip_counts: Dict[str, _Deque] = defaultdict(deque)
        self._ip_current: Dict[str, Tuple[int, int]] = {}   # ip -> (second, count)

        # --- Error counts (4xx/5xx) ---
        self._global_error_counts: _Deque = deque()
        self._global_error_current: Tuple[int, int] = (0, 0)

        self._ip_error_counts: Dict[str, _Deque] = defaultdict(deque)
        self._ip_error_current: Dict[str, Tuple[int, int]] = {}

        # --- Per-hour slot for global traffic ---
        self._hour_slots: Dict[int, _HourSlot] = {}

        # --- Cached baselines (updated every recalc_interval seconds) ---
        self._global_mean: float = per_second_floor
        self._global_stddev: float = 0.0
        self._ip_baselines: Dict[str, Tuple[float, float]] = {}
        self._global_error_mean: float = error_rate_floor
        self._global_error_stddev: float = 0.0
        self._ip_error_baselines: Dict[str, Tuple[float, float]] = {}

        self._last_recalc: float = 0.0

        # --- Background recalculation thread ---
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._recalc_loop, daemon=True, name="baseline-recalc"
        )
        self._thread.start()
        logger.info(
            "BaselineTracker started (window=%dm, recalc=%ds)",
            window_minutes, recalc_interval,
        )

    # ------------------------------------------------------------------
    # Public: record a new request
    # ------------------------------------------------------------------

    def record(self, ip: str, timestamp: float, is_error: bool) -> None:
        """Called for every incoming log entry."""
        bucket = int(timestamp)  # floor to whole second
        with self._lock:
            # --- Global ---
            self._accumulate(self._global_counts,
                             bucket, 1,
                             self._global_current_second,
                             self._global_current_count)
            # Store updated current second/count back
            if self._global_counts and self._global_counts[-1][0] == bucket:
                self._global_current_second = bucket
                self._global_current_count = self._global_counts[-1][1]
            else:
                self._global_current_second = bucket
                self._global_current_count = 1

            # --- Per-IP ---
            ip_sec, ip_cnt = self._ip_current.get(ip, (0, 0))
            self._accumulate(self._ip_counts[ip], bucket, 1, ip_sec, ip_cnt)
            if self._ip_counts[ip] and self._ip_counts[ip][-1][0] == bucket:
                self._ip_current[ip] = (bucket, self._ip_counts[ip][-1][1])
            else:
                self._ip_current[ip] = (bucket, 1)

            # --- Errors ---
            if is_error:
                e_sec, e_cnt = self._global_error_current
                self._accumulate(self._global_error_counts, bucket, 1, e_sec, e_cnt)
                if self._global_error_counts and self._global_error_counts[-1][0] == bucket:
                    self._global_error_current = (bucket, self._global_error_counts[-1][1])
                else:
                    self._global_error_current = (bucket, 1)

                ipe_sec, ipe_cnt = self._ip_error_current.get(ip, (0, 0))
                self._accumulate(self._ip_error_counts[ip], bucket, 1, ipe_sec, ipe_cnt)
                if self._ip_error_counts[ip] and self._ip_error_counts[ip][-1][0] == bucket:
                    self._ip_error_current[ip] = (bucket, self._ip_error_counts[ip][-1][1])
                else:
                    self._ip_error_current[ip] = (bucket, 1)

            # Update hour slot
            hour_key = int(timestamp) // 3600
            if hour_key not in self._hour_slots:
                self._hour_slots[hour_key] = _HourSlot(hour_key)
            slot = self._hour_slots[hour_key]
            slot.total_requests += 1

    # ------------------------------------------------------------------
    # Public: read baselines
    # ------------------------------------------------------------------

    def global_baseline(self) -> Tuple[float, float]:
        """Return (mean, stddev) for global per-second request rate."""
        return self._global_mean, self._global_stddev

    def ip_baseline(self, ip: str) -> Tuple[float, float]:
        """Return (mean, stddev) for a specific IP's per-second rate."""
        return self._ip_baselines.get(ip, (self._per_second_floor, 0.0))

    def error_baseline(self) -> Tuple[float, float]:
        return self._global_error_mean, self._global_error_stddev

    def ip_error_baseline(self, ip: str) -> Tuple[float, float]:
        return self._ip_error_baselines.get(ip, (self._error_rate_floor, 0.0))

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------
    # Internal: background recalculation
    # ------------------------------------------------------------------

    def _recalc_loop(self) -> None:
        while not self._stop.wait(timeout=self._recalc_interval):
            self._recalculate()

    def _recalculate(self) -> None:
        """Evict old data and recompute all baselines."""
        cutoff = time.time() - self._window_minutes * 60
        now_hour = int(time.time()) // 3600

        with self._lock:
            # --- Evict stale global entries ---
            self._evict(self._global_counts, cutoff)
            self._evict(self._global_error_counts, cutoff)

            # Evict stale per-IP entries and prune IPs with no recent data
            stale_ips = []
            for ip, dq in self._ip_counts.items():
                self._evict(dq, cutoff)
                if not dq:
                    stale_ips.append(ip)
            for ip in stale_ips:
                del self._ip_counts[ip]
                self._ip_current.pop(ip, None)
                self._ip_error_counts.pop(ip, None)
                self._ip_error_current.pop(ip, None)
                self._ip_baselines.pop(ip, None)
                self._ip_error_baselines.pop(ip, None)

            for ip, dq in self._ip_error_counts.items():
                self._evict(dq, cutoff)

            # --- Recompute global baseline ---
            counts = [c for _, c in self._global_counts]
            self._global_mean, self._global_stddev = self._stats(
                counts, self._per_second_floor
            )

            # Prefer current-hour slot if it has enough data
            slot = self._hour_slots.get(now_hour)
            if slot and slot.total_requests >= self._min_requests:
                # Recompute the slot's mean from current window counts
                hour_start = now_hour * 3600
                hour_counts = [c for t, c in self._global_counts if t >= hour_start]
                if hour_counts:
                    slot.mean, slot.stddev = self._stats(hour_counts, self._per_second_floor)
                    slot.seconds_seen = len(hour_counts)
                    # If current hour has enough data, use its baseline
                    if slot.seconds_seen >= self._min_requests:
                        self._global_mean = slot.mean
                        self._global_stddev = slot.stddev

            # Error baseline
            ecounts = [c for _, c in self._global_error_counts]
            self._global_error_mean, self._global_error_stddev = self._stats(
                ecounts, self._error_rate_floor
            )

            # --- Recompute per-IP baselines ---
            for ip, dq in self._ip_counts.items():
                counts_ip = [c for _, c in dq]
                self._ip_baselines[ip] = self._stats(counts_ip, self._per_second_floor)

            for ip, dq in self._ip_error_counts.items():
                ecounts_ip = [c for _, c in dq]
                self._ip_error_baselines[ip] = self._stats(ecounts_ip, self._error_rate_floor)

        self._last_recalc = time.time()
        logger.debug(
            "Baseline recalculated: global mean=%.2f stddev=%.2f",
            self._global_mean, self._global_stddev,
        )

    # ------------------------------------------------------------------
    # Internal: pure helpers (no lock needed)
    # ------------------------------------------------------------------

    @staticmethod
    def _accumulate(dq: _Deque, bucket: int, increment: int,
                    current_sec: int, current_cnt: int) -> None:
        """
        Append or update the last entry of `dq` for `bucket`.
        If the last entry matches the bucket, increment its count.
        Otherwise append a new (bucket, increment) tuple.
        This is the core of the deque-based sliding window accumulation.
        """
        if dq and dq[-1][0] == bucket:
            # Replace last entry with incremented count
            old_sec, old_cnt = dq[-1]
            dq[-1] = (old_sec, old_cnt + increment)
        else:
            dq.append((bucket, increment))

    @staticmethod
    def _evict(dq: _Deque, cutoff: float) -> None:
        """
        Remove entries from the left of `dq` whose timestamp (second bucket)
        is older than `cutoff`.  This is O(k) where k is the number of
        evicted entries, not O(n), because deques support O(1) popleft.
        """
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    @staticmethod
    def _stats(counts: list, floor: float) -> Tuple[float, float]:
        """
        Compute mean and population stddev from a list of counts.
        Apply a floor to mean so baselines are never zero.
        """
        if not counts:
            return floor, 0.0
        n = len(counts)
        mean = sum(counts) / n
        mean = max(mean, floor)
        variance = sum((c - mean) ** 2 for c in counts) / n
        stddev = math.sqrt(variance)
        return mean, stddev

    def get_summary(self) -> dict:
        """Return a dict suitable for the dashboard."""
        with self._lock:
            return {
                "global_mean": round(self._global_mean, 3),
                "global_stddev": round(self._global_stddev, 3),
                "last_recalc": self._last_recalc,
                "window_minutes": self._window_minutes,
                "tracked_ips": len(self._ip_counts),
                "hour_slots": {
                    str(k): {
                        "total_requests": v.total_requests,
                        "mean": round(v.mean, 3),
                        "stddev": round(v.stddev, 3),
                    }
                    for k, v in self._hour_slots.items()
                },
            }
