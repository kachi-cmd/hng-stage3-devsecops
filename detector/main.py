"""
main.py
-------
Entry point for the HNG anomaly detection / DDoS detection daemon.

Wires together:
  LogMonitor  →  BaselineTracker  +  AnomalyDetector
  AnomalyDetector  →  IPBlocker  +  SlackNotifier  +  AuditLogger
  AutoUnbanner watches IPBlocker and calls SlackNotifier on release
  Dashboard serves live metrics

Run as root (or with NET_ADMIN capability) so iptables commands succeed.
"""

import logging
import signal
import sys
import time
import threading
import yaml
import os

from audit import AuditLogger
from baseline import BaselineTracker
from blocker import IPBlocker
from dashboard import Dashboard
from detector import AnomalyDetector, AnomalyEvent
from monitor import LogMonitor
from notifier import SlackNotifier
from unbanner import AutoUnbanner

# ---------------------------------------------------------------------------
# Logging setup – structured, to stdout so Docker captures it
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
logger = logging.getLogger("main")


# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------
def load_config(path: str = "/app/config.yaml") -> dict:
    if not os.path.exists(path):
        # Try relative path (dev mode)
        path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(path, "r") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Build the offence-count tracker (persists across bans for the same IP)
# ---------------------------------------------------------------------------
_offence_counts: dict = {}
_offence_lock = threading.Lock()


def get_and_increment_offence(ip: str) -> int:
    """Return the NEW offence count (1-indexed) after incrementing."""
    with _offence_lock:
        _offence_counts[ip] = _offence_counts.get(ip, 0) + 1
        return _offence_counts[ip]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    cfg = load_config()

    slack_webhook = cfg["slack"]["webhook_url"]
    log_path = cfg["log"]["nginx_access_log"]
    audit_path = cfg["log"]["audit_log"]

    det_cfg = cfg["detection"]
    blk_cfg = cfg["blocking"]
    dash_cfg = cfg["dashboard"]

    # --- Instantiate components ---
    audit = AuditLogger(audit_path)

    notifier = SlackNotifier(slack_webhook)

    baseline = BaselineTracker(
        window_minutes=det_cfg["baseline_window_minutes"],
        recalc_interval=det_cfg["baseline_recalc_interval_seconds"],
        min_requests=det_cfg["min_requests_for_baseline"],
        per_second_floor=det_cfg["per_second_floor"],
        error_rate_floor=det_cfg["error_rate_floor"],
    )

    blocker = IPBlocker(audit_logger=audit)

    unbanner = AutoUnbanner(
        blocker=blocker,
        notifier=notifier,
        schedule_minutes=blk_cfg["unban_schedule_minutes"],
    )

    detector = AnomalyDetector(
        baseline=baseline,
        window_seconds=det_cfg["sliding_window_seconds"],
        z_score_threshold=det_cfg["z_score_threshold"],
        spike_multiplier=det_cfg["spike_multiplier"],
        error_rate_multiplier=det_cfg["error_rate_multiplier"],
    )

    monitor = LogMonitor(log_path)

    dashboard = Dashboard(
        port=dash_cfg["port"],
        detector=detector,
        baseline=baseline,
        blocker=blocker,
    )

    # --- Periodic baseline audit logging ---
    def _audit_baseline_periodically():
        while True:
            time.sleep(det_cfg["baseline_recalc_interval_seconds"])
            mean, stddev = baseline.global_baseline()
            audit.baseline(
                scope="global",
                mean=mean,
                stddev=stddev,
                window_minutes=det_cfg["baseline_window_minutes"],
            )

    threading.Thread(
        target=_audit_baseline_periodically, daemon=True, name="baseline-auditor"
    ).start()

    # --- Wire anomaly events → block / alert ---
    def on_anomaly(event: AnomalyEvent):
        if event.kind == "ip":
            ip = event.ip
            if blocker.is_banned(ip):
                return  # already handled

            offence = get_and_increment_offence(ip)
            duration = unbanner.ban_duration_for(offence)

            dur_str = "permanent" if duration < 0 else f"{duration // 60}m"

            banned = blocker.ban(
                ip=ip,
                duration_seconds=duration,
                offence_count=offence,
                condition=f"{event.reason} (z={event.z_score:.2f})",
                rate=event.current_rate,
                mean=event.mean,
            )
            if banned:
                notifier.send_ban(
                    ip=ip,
                    condition=event.reason,
                    rate=event.current_rate,
                    mean=event.mean,
                    stddev=event.stddev,
                    z_score=event.z_score,
                    duration=dur_str,
                )
        else:
            # Global anomaly – Slack alert only, no IP to block
            notifier.send_global_anomaly(
                condition=event.reason,
                rate=event.current_rate,
                mean=event.mean,
                stddev=event.stddev,
                z_score=event.z_score,
            )

    detector.on_anomaly(on_anomaly)

    # --- Wire log monitor → baseline + detector ---
    def on_log_entry(entry):
        baseline.record(entry.source_ip, entry.timestamp, entry.is_error())
        detector.process(entry)

    monitor.register(on_log_entry)

    # --- Start everything ---
    dashboard.start()
    monitor.start()

    logger.info("=" * 60)
    logger.info("HNG Anomaly Detection Engine started")
    logger.info("  Log file    : %s", log_path)
    logger.info("  Audit log   : %s", audit_path)
    logger.info("  Dashboard   : http://0.0.0.0:%d", dash_cfg["port"])
    logger.info("=" * 60)

    # --- Graceful shutdown ---
    def _shutdown(sig, frame):
        logger.info("Received signal %s; shutting down…", sig)
        monitor.stop()
        baseline.stop()
        unbanner.stop()
        notifier.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Keep the main thread alive (all workers are daemon threads)
    while True:
        time.sleep(10)
        # Emit a heartbeat so the container log shows the daemon is alive
        mean, stddev = baseline.global_baseline()
        logger.info(
            "HEARTBEAT | global_rps=%.3f | baseline_mean=%.3f | stddev=%.3f | bans=%d",
            detector.global_rps, mean, stddev, len(blocker.all_bans()),
        )


if __name__ == "__main__":
    main()
