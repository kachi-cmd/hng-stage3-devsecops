"""
dashboard.py
------------
Lightweight Flask dashboard served at :8080.
Refreshes every 3 seconds via meta-refresh and a small JS fetch loop.

Endpoints:
  GET /          → HTML dashboard
  GET /api/stats → JSON stats (for JS polling)
  GET /health    → {"status": "ok"}
"""

import os
import time
import threading
import logging
from datetime import datetime, timezone, timedelta

import psutil
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger(__name__)

_START_TIME = time.time()

_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HNG DDoS Detection Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
           background: #0d1117; color: #c9d1d9; min-height: 100vh; padding: 20px; }
    h1 { color: #58a6ff; margin-bottom: 4px; font-size: 1.6rem; }
    .subtitle { color: #8b949e; font-size: 0.85rem; margin-bottom: 20px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px; margin-bottom: 20px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
    .card h3 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em;
               color: #8b949e; margin-bottom: 8px; }
    .card .value { font-size: 1.8rem; font-weight: 700; color: #58a6ff; }
    .card .value.warn { color: #f0883e; }
    .card .value.danger { color: #f85149; }
    .card .sub { font-size: 0.78rem; color: #8b949e; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { text-align: left; padding: 8px 12px; color: #8b949e;
         border-bottom: 1px solid #30363d; font-weight: 600; }
    td { padding: 8px 12px; border-bottom: 1px solid #21262d; }
    tr:hover td { background: #1c2128; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; }
    .badge.banned { background: #3d1a1a; color: #f85149; }
    .badge.ok { background: #1a2d1a; color: #3fb950; }
    .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
               padding: 16px; margin-bottom: 16px; }
    .section h2 { font-size: 1rem; margin-bottom: 12px; color: #c9d1d9; }
    #last-update { position: fixed; bottom: 12px; right: 16px; font-size: 0.75rem;
                   color: #484f58; }
    .progress { background: #21262d; border-radius: 4px; height: 6px; margin-top: 6px; }
    .progress-bar { height: 6px; border-radius: 4px; background: #58a6ff;
                    transition: width .5s ease; }
  </style>
</head>
<body>
  <h1>🛡️ HNG Anomaly Detection Engine</h1>
  <p class="subtitle">Real-time DDoS / anomaly detection for cloud.ng • Auto-refreshes every 3s</p>

  <div class="grid">
    <div class="card">
      <h3>Global req/s</h3>
      <div class="value" id="global-rps">—</div>
      <div class="sub">Baseline mean: <span id="baseline-mean">—</span></div>
    </div>
    <div class="card">
      <h3>Stddev</h3>
      <div class="value" id="stddev">—</div>
      <div class="sub">σ from baseline</div>
    </div>
    <div class="card">
      <h3>Banned IPs</h3>
      <div class="value danger" id="ban-count">—</div>
      <div class="sub">Active blocks</div>
    </div>
    <div class="card">
      <h3>CPU Usage</h3>
      <div class="value" id="cpu">—</div>
      <div class="progress"><div class="progress-bar" id="cpu-bar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <h3>Memory Usage</h3>
      <div class="value" id="mem">—</div>
      <div class="progress"><div class="progress-bar" id="mem-bar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <h3>Uptime</h3>
      <div class="value" id="uptime">—</div>
      <div class="sub">Daemon running</div>
    </div>
  </div>

  <div class="section">
    <h2>🚫 Currently Banned IPs</h2>
    <table>
      <thead><tr><th>IP Address</th><th>Banned At</th><th>Duration</th><th>Offences</th></tr></thead>
      <tbody id="ban-table"><tr><td colspan="4" style="color:#8b949e">No bans active</td></tr></tbody>
    </table>
  </div>

  <div class="section">
    <h2>📊 Top 10 Source IPs (req/s)</h2>
    <table>
      <thead><tr><th>IP Address</th><th>Rate (req/s)</th><th>Status</th></tr></thead>
      <tbody id="top-ip-table"><tr><td colspan="3" style="color:#8b949e">No data yet</td></tr></tbody>
    </table>
  </div>

  <div id="last-update">Updating…</div>

  <script>
    async function refresh() {
      try {
        const r = await fetch('/api/stats');
        const d = await r.json();

        document.getElementById('global-rps').textContent = d.global_rps.toFixed(2);
        document.getElementById('baseline-mean').textContent = d.baseline_mean.toFixed(2) + ' req/s';
        document.getElementById('stddev').textContent = d.baseline_stddev.toFixed(2);
        document.getElementById('ban-count').textContent = d.banned_count;
        document.getElementById('cpu').textContent = d.cpu_percent.toFixed(1) + '%';
        document.getElementById('mem').textContent = d.mem_percent.toFixed(1) + '%';
        document.getElementById('cpu-bar').style.width = d.cpu_percent + '%';
        document.getElementById('mem-bar').style.width = d.mem_percent + '%';
        document.getElementById('uptime').textContent = d.uptime;

        // Ban table
        const banBody = document.getElementById('ban-table');
        if (d.bans.length === 0) {
          banBody.innerHTML = '<tr><td colspan="4" style="color:#8b949e">No bans active</td></tr>';
        } else {
          banBody.innerHTML = d.bans.map(b =>
            `<tr><td><code>${b.ip}</code></td><td>${b.banned_at}</td>
             <td>${b.duration}</td><td>${b.offence_count}</td></tr>`
          ).join('');
        }

        // Top IP table
        const topBody = document.getElementById('top-ip-table');
        if (d.top_ips.length === 0) {
          topBody.innerHTML = '<tr><td colspan="3" style="color:#8b949e">No data yet</td></tr>';
        } else {
          topBody.innerHTML = d.top_ips.map(([ip, rate]) => {
            const isBanned = d.bans.some(b => b.ip === ip);
            const badge = isBanned
              ? '<span class="badge banned">BANNED</span>'
              : '<span class="badge ok">OK</span>';
            return `<tr><td><code>${ip}</code></td><td>${rate.toFixed(3)}</td><td>${badge}</td></tr>`;
          }).join('');
        }

        document.getElementById('last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();
      } catch (e) {
        document.getElementById('last-update').textContent = 'Error fetching stats';
      }
    }

    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""


class Dashboard:
    """
    Flask-based dashboard.  Runs in its own daemon thread so it doesn't
    interfere with the main detection loop.
    """

    def __init__(self, port: int, detector, baseline, blocker):
        self._port = port
        self._detector = detector
        self._baseline = baseline
        self._blocker = blocker

        self._app = Flask(__name__)
        self._app.logger.setLevel(logging.WARNING)
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.WARNING)

        self._app.add_url_rule("/", "index", self._index)
        self._app.add_url_rule("/api/stats", "stats", self._stats)
        self._app.add_url_rule("/health", "health", self._health)

    def start(self) -> None:
        t = threading.Thread(
            target=lambda: self._app.run(host="0.0.0.0", port=self._port, debug=False),
            daemon=True, name="dashboard"
        )
        t.start()
        logger.info("Dashboard listening on :%d", self._port)

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    def _index(self):
        return render_template_string(_HTML)

    def _stats(self):
        mean, stddev = self._baseline.global_baseline()
        bans = self._blocker.all_bans()
        top_ips = self._detector.top_ips(10)

        ban_list = []
        for ip, rec in bans.items():
            dur_s = rec.current_duration
            if dur_s < 0:
                dur_str = "permanent"
            else:
                remaining = max(0, int(dur_s - (time.time() - rec.banned_at)))
                dur_str = f"{remaining // 60}m {remaining % 60}s remaining"
            ban_list.append({
                "ip": ip,
                "banned_at": datetime.fromtimestamp(rec.banned_at, tz=timezone.utc)
                              .strftime("%H:%M:%S UTC"),
                "duration": dur_str,
                "offence_count": rec.offence_count,
            })

        uptime_secs = int(time.time() - _START_TIME)
        h, rem = divmod(uptime_secs, 3600)
        m, s = divmod(rem, 60)

        data = {
            "global_rps": round(self._detector.global_rps, 3),
            "baseline_mean": round(mean, 3),
            "baseline_stddev": round(stddev, 3),
            "banned_count": len(bans),
            "bans": ban_list,
            "top_ips": [[ip, round(r, 4)] for ip, r in top_ips],
            "cpu_percent": psutil.cpu_percent(interval=None),
            "mem_percent": psutil.virtual_memory().percent,
            "uptime": f"{h}h {m}m {s}s",
        }
        return jsonify(data)

    def _health(self):
        return jsonify({"status": "ok", "uptime_seconds": int(time.time() - _START_TIME)})
