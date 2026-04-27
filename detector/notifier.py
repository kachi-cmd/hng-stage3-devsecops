"""
notifier.py
-----------
Sends Slack notifications for ban, unban, and global anomaly events.

All HTTP calls are made in a background thread so they never block the
detection hot-path.  A simple in-memory queue is used to decouple the
detector from the Slack API.
"""

import json
import queue
import threading
import time
import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 8   # seconds per HTTP request


class SlackNotifier:
    """
    Thread-safe Slack notifier that dispatches messages via a background
    worker thread so alert delivery never delays detection or blocking.
    """

    def __init__(self, webhook_url: str):
        self._webhook = webhook_url
        self._queue: queue.Queue = queue.Queue(maxsize=200)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._worker, daemon=True, name="slack-notifier"
        )
        self._thread.start()
        logger.info("SlackNotifier started")

    # ------------------------------------------------------------------
    # Public send helpers
    # ------------------------------------------------------------------

    def send_ban(self, ip: str, condition: str, rate: float, mean: float,
                 stddev: float, z_score: float, duration: str) -> None:
        ts = self._now()
        text = (
            f":no_entry: *IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Rate:* `{rate:.2f} req/s`  |  *Baseline mean:* `{mean:.2f} req/s`  "
            f"|  *Stddev:* `{stddev:.2f}`  |  *Z-score:* `{z_score:.2f}`\n"
            f"*Ban duration:* `{duration}`\n"
            f"*Time:* `{ts}`"
        )
        self._enqueue(text)

    def send_unban(self, ip: str, offence_count: int,
                   was_duration: int, next_ban_duration: str) -> None:
        ts = self._now()
        was_str = f"{was_duration // 60}m" if was_duration >= 0 else "permanent"
        text = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Offences so far:* `{offence_count}`\n"
            f"*Was banned for:* `{was_str}`\n"
            f"*Next ban if re-offended:* `{next_ban_duration}`\n"
            f"*Time:* `{ts}`"
        )
        self._enqueue(text)

    def send_global_anomaly(self, condition: str, rate: float,
                             mean: float, stddev: float, z_score: float) -> None:
        ts = self._now()
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {condition}\n"
            f"*Global rate:* `{rate:.2f} req/s`\n"
            f"*Baseline mean:* `{mean:.2f} req/s`  |  *Stddev:* `{stddev:.2f}`  "
            f"|  *Z-score:* `{z_score:.2f}`\n"
            f"*Time:* `{ts}`"
        )
        self._enqueue(text)

    def stop(self) -> None:
        self._stop.set()
        self._queue.put(None)   # sentinel to unblock worker

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _enqueue(self, text: str) -> None:
        try:
            self._queue.put_nowait({"text": text})
        except queue.Full:
            logger.warning("Slack notification queue full; dropping message")

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                payload = self._queue.get(timeout=5)
            except queue.Empty:
                continue

            if payload is None:
                break   # sentinel

            self._post(payload)

    def _post(self, payload: dict) -> None:
        if not self._webhook or self._webhook.startswith("https://hooks.slack.com/services/YOUR"):
            logger.debug("Slack webhook not configured; skipping notification")
            return
        try:
            resp = requests.post(
                self._webhook,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=_TIMEOUT,
            )
            if resp.status_code != 200:
                logger.warning("Slack responded %d: %s", resp.status_code, resp.text[:200])
            else:
                logger.debug("Slack notification sent OK")
        except requests.RequestException as exc:
            logger.error("Slack HTTP error: %s", exc)

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
