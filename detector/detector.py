"""
detector.py
-----------
Anomaly detection using two deque-based sliding windows (per-IP and global)
over the last 60 seconds.

Detection fires when EITHER:
  1. z-score  > z_score_threshold  (default 3.0), OR
  2. current rate > spike_multiplier * baseline_mean  (default 5×)

If an IP already has a high error rate (4xx/5xx ≥ 3× baseline error rate)
its thresholds are automatically tightened (halved).

Thread-safety: all state is guarded by a single re-entrant lock.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from typing import Callable, Dict, List, Optional, Tuple

from monitor import LogEntry
from baseline import BaselineTracker

logger = logging.getLogger(__name__)


class AnomalyEvent:
    """Describes a single detected anomaly."""

    __slots__ = ("kind", "ip", "current_rate", "mean", "stddev",
                 "z_score", "timestamp", "reason")

    def __init__(self, kind: str, ip: Optional[str], current_rate: float,
                 mean: float, stddev: float, z_score: float, reason: str):
        self.kind = kind            # "ip" or "global"
        self.ip = ip
        self.current_rate = current_rate
        self.mean = mean
        self.stddev = stddev
        self.z_score = z_score
        self.timestamp = time.time()
        self.reason = reason        # "z_score" | "spike" | "error_surge"

    def __repr__(self):
        return (f"AnomalyEvent(kind={self.kind}, ip={self.ip}, "
                f"rate={self.current_rate:.2f}, mean={self.mean:.2f}, "
                f"z={self.z_score:.2f}, reason={self.reason})")


class AnomalyDetector:
    """
    Keeps two sets of deque-based sliding windows over the last
    `window_seconds` seconds:

      _global_window  – deque of (timestamp, 1) for every request
      _ip_windows     – per-IP deque of (timestamp, 1) per request

    On each new log entry the detector:
      1. Appends to both deques.
      2. Evicts entries older than window_seconds from the LEFT.
      3. Computes rates = len(deque) / window_seconds.
      4. Compares rates against the baseline with z-score and spike checks.
      5. Fires callbacks on anomaly.
    """

    def __init__(self,
                 baseline: BaselineTracker,
                 window_seconds: int = 60,
                 z_score_threshold: float = 3.0,
                 spike_multiplier: float = 5.0,
                 error_rate_multiplier: float = 3.0):
        self._baseline = baseline
        self._window_seconds = window_seconds
        self._z_threshold = z_score_threshold
        self._spike_mult = spike_multiplier
        self._error_mult = error_rate_multiplier

        self._lock = threading.Lock()

        # Global sliding window: deque of float timestamps
        self._global_window: deque = deque()

        # Per-IP sliding windows
        self._ip_windows: Dict[str, deque] = defaultdict(deque)

        # Per-IP error windows (for error-surge detection)
        self._ip_error_windows: Dict[str, deque] = defaultdict(deque)

        # Callbacks invoked on anomaly detection
        self._handlers: List[Callable[[AnomalyEvent], None]] = []

        # Suppress repeated alerts: track last-alert time per IP/global
        self._last_alert: Dict[str, float] = {}
        self._alert_cooldown = 30.0   # seconds between repeated alerts for same IP

        # Public metrics (read by dashboard without lock for approximate values)
        self.global_rps: float = 0.0
        self.ip_rps: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on_anomaly(self, handler: Callable[[AnomalyEvent], None]) -> None:
        """Register a callback to receive AnomalyEvent objects."""
        self._handlers.append(handler)

    def process(self, entry: LogEntry) -> None:
        """
        Process one parsed log entry.  Called from the LogMonitor callback
        which runs in the monitor background thread.
        """
        now = entry.timestamp
        ip = entry.source_ip
        is_error = entry.is_error()

        with self._lock:
            # --- Append to windows ---
            self._global_window.append(now)
            self._ip_windows[ip].append(now)
            if is_error:
                self._ip_error_windows[ip].append(now)

            # --- Evict old entries ---
            cutoff = now - self._window_seconds
            self._evict_left(self._global_window, cutoff)
            self._evict_left(self._ip_windows[ip], cutoff)
            self._evict_left(self._ip_error_windows[ip], cutoff)

            # --- Compute current rates ---
            global_rate = len(self._global_window) / self._window_seconds
            ip_rate = len(self._ip_windows[ip]) / self._window_seconds
            ip_error_rate = len(self._ip_error_windows[ip]) / self._window_seconds

            # Update public metrics (approx – no lock held by dashboard)
            self.global_rps = global_rate
            self.ip_rps[ip] = ip_rate

        # --- Baseline reads (outside lock to avoid deadlock with baseline lock) ---
        g_mean, g_stddev = self._baseline.global_baseline()
        ip_mean, ip_stddev = self._baseline.ip_baseline(ip)
        ip_err_mean, _ = self._baseline.ip_error_baseline(ip)

        # --- Determine effective thresholds (tighten if error surge) ---
        tightened = False
        if ip_err_mean > 0 and ip_error_rate >= self._error_mult * ip_err_mean:
            effective_z = self._z_threshold / 2.0
            effective_spike = self._spike_mult / 2.0
            tightened = True
        else:
            effective_z = self._z_threshold
            effective_spike = self._spike_mult

        # --- Check per-IP anomaly ---
        ip_z = self._z_score(ip_rate, ip_mean, ip_stddev)
        ip_anomaly_reason = None
        if ip_z > effective_z:
            ip_anomaly_reason = "z_score"
        elif ip_mean > 0 and ip_rate >= effective_spike * ip_mean:
            ip_anomaly_reason = "spike"
        elif tightened and ip_error_rate >= self._error_mult * ip_err_mean:
            ip_anomaly_reason = "error_surge"

        if ip_anomaly_reason:
            self._maybe_fire(AnomalyEvent(
                kind="ip",
                ip=ip,
                current_rate=ip_rate,
                mean=ip_mean,
                stddev=ip_stddev,
                z_score=ip_z,
                reason=ip_anomaly_reason,
            ))

        # --- Check global anomaly ---
        g_z = self._z_score(global_rate, g_mean, g_stddev)
        global_anomaly_reason = None
        if g_z > self._z_threshold:
            global_anomaly_reason = "z_score"
        elif g_mean > 0 and global_rate >= self._spike_mult * g_mean:
            global_anomaly_reason = "spike"

        if global_anomaly_reason:
            self._maybe_fire(AnomalyEvent(
                kind="global",
                ip=None,
                current_rate=global_rate,
                mean=g_mean,
                stddev=g_stddev,
                z_score=g_z,
                reason=global_anomaly_reason,
            ))

    def top_ips(self, n: int = 10) -> List[Tuple[str, float]]:
        """Return the top-n IPs by current request rate."""
        snapshot = dict(self.ip_rps)
        return sorted(snapshot.items(), key=lambda x: x[1], reverse=True)[:n]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _evict_left(dq: deque, cutoff: float) -> None:
        """
        Remove timestamps from the left of `dq` that are older than `cutoff`.
        O(k) where k = number of evicted entries; popleft is O(1) on deque.
        """
        while dq and dq[0] < cutoff:
            dq.popleft()

    @staticmethod
    def _z_score(value: float, mean: float, stddev: float) -> float:
        """Standard z-score; returns 0 if stddev == 0."""
        if stddev == 0:
            return 0.0
        return (value - mean) / stddev

    def _maybe_fire(self, event: AnomalyEvent) -> None:
        """Fire the event only if cooldown has elapsed for this IP/global key."""
        key = event.ip or "__global__"
        now = time.time()
        if now - self._last_alert.get(key, 0) < self._alert_cooldown:
            return
        self._last_alert[key] = now
        logger.warning("ANOMALY DETECTED: %s", event)
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as exc:
                logger.error("Anomaly handler error: %s", exc)
