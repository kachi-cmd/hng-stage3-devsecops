# HNG Anomaly Detection Engine

> Real-time DDoS / anomaly detection daemon for cloud.ng (HNG DevSecOps Stage 7)

**Server IP:** `<YOUR_VPS_IP>`
**Metrics Dashboard:** `http://<YOUR_VPS_IP>:8080` (live during grading)
**GitHub Repo:** `https://github.com/<your-username>/hng-devsecops`
**Blog Post:** `https://<your-blog-link>`

---

## Language Choice

**Python 3.11** was chosen because:
- `collections.deque` is a first-class, O(1) popleft data structure — perfect for the sliding window requirement.
- `threading` + `queue` make it straightforward to run the log monitor, baseline recalculator, notifier, and dashboard concurrently without the complexity of async runtimes.
- `subprocess.run` gives clean, auditable iptables integration.
- The entire stack fits in a single Docker image under 200 MB.

---

## Architecture

```
Nginx (JSON logs)
      │
      ▼  (shared Docker volume: HNG-nginx-logs, read-only to detector)
LogMonitor  ──────────────────────────────────────────────┐
      │                                                   │
      ▼                                                   ▼
BaselineTracker                                   AnomalyDetector
  rolling 30-min window                           deque sliding windows
  recalc every 60s                                z-score + spike check
  per-hour slots                                        │
                                               ┌────────┴────────┐
                                               ▼                  ▼
                                          IP anomaly        Global anomaly
                                               │                  │
                                          IPBlocker          SlackNotifier
                                         (iptables)         (global alert)
                                               │
                                          AutoUnbanner
                                        (backoff: 10m/30m/2h/perm)
                                               │
                                          SlackNotifier (unban alert)

Dashboard (Flask :8080) reads from Detector + Baseline + Blocker
AuditLogger writes every ban / unban / baseline recalculation
```

---

## How the Sliding Window Works

The detector maintains two sets of `collections.deque` objects:

1. **`_global_window`** — one deque containing the UNIX timestamp of every incoming request.
2. **`_ip_windows`** — one deque per source IP, same structure.

**On each new request:**
```python
# Append the new timestamp
self._global_window.append(now)
self._ip_windows[ip].append(now)

# Evict entries older than 60 seconds from the LEFT
cutoff = now - 60
while self._global_window and self._global_window[0] < cutoff:
    self._global_window.popleft()   # O(1) — deque popleft is O(1), not O(n)
```

**Rate computation:**
```python
global_rate = len(self._global_window) / 60   # requests per second
ip_rate     = len(self._ip_windows[ip]) / 60
```

`deque.popleft()` is O(1) (doubly-linked list under the hood), so eviction is efficient even under heavy traffic. A plain `list.pop(0)` would be O(n) and would slow down the hot path.

---

## How the Baseline Works

`BaselineTracker` maintains a **rolling 30-minute window** of per-second bucket counts using a deque of `(second_bucket, count)` tuples:

```python
# Accumulate: same second → update count; new second → append
if deque and deque[-1][0] == bucket:
    deque[-1] = (bucket, deque[-1][1] + increment)
else:
    deque.append((bucket, increment))
```

**Recalculation (every 60 seconds):**
1. Evict entries older than 30 minutes from the left.
2. Compute `mean = sum(counts) / len(counts)` and population `stddev = sqrt(variance)`.
3. Apply a **floor** (`per_second_floor = 1.0`) so the mean is never near-zero — prevents false anomalies on an idle server.
4. If the **current-hour slot** has ≥ 10 samples, prefer it over the full 30-minute window.  This means the baseline tracks intra-day traffic patterns (e.g., low traffic at 3 AM, high traffic at noon) rather than averaging them away.

**Per-hour slots** accumulate total requests per clock hour.  When the current hour has enough data, its mean/stddev replace the rolling 30-minute baseline.  This gives the system two timescales: a short-term (30 min) and a medium-term (within current hour) baseline.

**Configuration (config.yaml):**
```yaml
detection:
  baseline_window_minutes: 30
  baseline_recalc_interval_seconds: 60
  min_requests_for_baseline: 10
  per_second_floor: 1.0
  error_rate_floor: 0.05
```

---

## Detection Logic

An IP or global rate is flagged anomalous when **either** condition fires:

```python
z_score = (current_rate - mean) / stddev

if z_score > 3.0:
    fire("z_score")

if current_rate >= 5.0 * mean:
    fire("spike")
```

**Error surge tightening:** if an IP's 4xx/5xx rate over the sliding window is ≥ 3× its baseline error rate, detection thresholds are halved (`effective_z = 1.5`, `effective_spike = 2.5x`):

```python
if ip_error_rate >= 3.0 * baseline_error_rate:
    effective_z     = z_threshold / 2      # tighter
    effective_spike = spike_mult / 2       # tighter
```

A 30-second per-IP cooldown prevents alert floods for the same IP.

---

## How iptables Blocking Works

When a per-IP anomaly fires, the daemon runs:

```bash
iptables -I INPUT 1 -s <IP> -j DROP
```

`-I INPUT 1` inserts the rule at the **top** of the INPUT chain, so it takes effect immediately and cannot be bypassed by other rules lower down.

Auto-unban uses the inverse:
```bash
iptables -D INPUT -s <IP> -j DROP
```

The daemon requires `CAP_NET_ADMIN` (provided via `cap_add: [NET_ADMIN]` in Docker Compose, or by running as root on the host).

**Backoff schedule:**
| Offence | Ban Duration |
|---------|-------------|
| 1st     | 10 minutes  |
| 2nd     | 30 minutes  |
| 3rd     | 2 hours     |
| 4th+    | Permanent   |

---

## Repository Structure

```
hng-devsecops/
├── detector/
│   ├── main.py          # Entry point, wires everything together
│   ├── monitor.py       # Nginx log tailing and parsing
│   ├── baseline.py      # Rolling baseline computation
│   ├── detector.py      # Sliding window + anomaly detection
│   ├── blocker.py       # iptables ban management
│   ├── unbanner.py      # Auto-unban with backoff schedule
│   ├── notifier.py      # Slack alert delivery
│   ├── dashboard.py     # Flask live metrics dashboard
│   ├── audit.py         # Structured audit logging
│   ├── config.yaml      # All thresholds and settings
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   └── nginx.conf       # JSON log format + reverse proxy config
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── tool-running.png
│   ├── ban-slack.png
│   ├── unban-slack.png
│   ├── global-alert-slack.png
│   ├── iptables-banned.png
│   ├── audit-log.png
│   └── baseline-graph.png
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Setup Instructions (Fresh VPS → Running Stack)

### 1. Provision a VPS

Minimum: 2 vCPU, 2 GB RAM, Ubuntu 22.04 LTS.  
Tested on: DigitalOcean, Hetzner, AWS EC2.

### 2. Install Docker & Docker Compose

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
```

### 3. Clone the repository

```bash
git clone https://github.com/<your-username>/hng-devsecops.git
cd hng-devsecops
```

### 4. Configure environment

```bash
cp .env.example .env
nano .env
# Fill in: SERVER_IP, SLACK_WEBHOOK_URL, passwords
```

### 5. Update config.yaml with your Slack webhook

```bash
nano detector/config.yaml
# Set: slack.webhook_url
```

### 6. Open firewall ports

```bash
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # Nginx / Nextcloud
sudo ufw allow 8080/tcp # Dashboard
sudo ufw enable
```

### 7. Start the stack

```bash
docker compose up -d --build
```

### 8. Verify everything is running

```bash
docker compose ps
# All containers should show "Up"

# Check detector logs
docker compose logs -f detector

# Test dashboard
curl http://localhost:8080/health
```

### 9. Confirm Nextcloud is accessible

```bash
curl -I http://<YOUR_VPS_IP>/
# Should return 200 or 302 (Nextcloud login redirect)
```

### 10. Confirm log sharing

```bash
docker exec hng-nginx ls -la /var/log/nginx/
# Should show hng-access.log being written

docker exec hng-detector ls -la /var/log/nginx/
# Same file visible read-only in detector container
```

---

## Testing Locally (without a VPS)

```bash
# Generate fake log traffic to test the detector
docker exec hng-nginx sh -c \
  'for i in $(seq 1 200); do
     echo "{\"source_ip\":\"10.0.0.99\",\"time_iso8601\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"request_method\":\"GET\",\"request_uri\":\"/\",\"status\":200,\"body_bytes_sent\":512}" \
     >> /var/log/nginx/hng-access.log;
   done'

# Watch detector respond
docker compose logs -f detector
```

---

## Screenshots

All required screenshots are in the `screenshots/` directory.

---

## Blog Post

[Link to blog post]

---

## Notes

- **Fail2Ban is NOT used** — all detection and blocking is custom-built.
- **No rate-limiting libraries** — sliding windows are implemented with `collections.deque`.
- **All thresholds** are in `detector/config.yaml` — nothing is hardcoded.
- The daemon survives log rotation (LogMonitor detects inode changes and re-opens).
- Permanent bans (4th+ offence) are never auto-released; manual intervention required.
