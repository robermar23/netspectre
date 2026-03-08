# Feature 5 — Advanced Hardening & Application Security

> Implementation Plan for NetSpecter — Branch: `offense`
> Covers: `@security-scanning-security-hardening`, `@security-scanning-security-sast`

---

## Overview

Feature 5 elevates NetSpecter from a reactive scanner into a **proactive security posture platform**. It bridges the gap between network-layer scanning (Nmap, passive capture) and application-layer hardening awareness. The four sub-features are designed as independent, cohesive modules that integrate cleanly into the existing IPC/preload/renderer architecture.

| Sub-Feature | Codename | Difficulty | External Dep |
|---|---|---|---|
| 5A — Continuous Delta Monitoring | `hardening-monitor` | Medium | None (pure Node) |
| 5B — Default Credential Spraying | `cred-spray` | Low-Medium | None (built-in http/net) |
| 5C — Container & Cloud Enumeration | `cloud-enum` | Medium | None (built-in http/net) |
| 5D — Live Traffic Interception (MiTM Proxy) | `mitm-proxy` | High | `arp-scan` or `arpspoof` (optional) |

---

## Shared Infrastructure Changes

### 1. `src/shared/ipc.js` — New Channel Constants

```js
// --- Feature 5A: Hardening Monitor ---
HARDENING_START_MONITOR: 'hardening-start-monitor',
HARDENING_STOP_MONITOR:  'hardening-stop-monitor',
HARDENING_SET_BASELINE:  'hardening-set-baseline',
HARDENING_GET_BASELINE:  'hardening-get-baseline',
HARDENING_GET_SCHEDULES: 'hardening-get-schedules',
HARDENING_DELTA_ALERT:   'hardening-delta-alert',       // main -> renderer
HARDENING_DELTA_REPORT:  'hardening-delta-report',      // main -> renderer (full diff)
HARDENING_MONITOR_STATUS:'hardening-monitor-status',    // main -> renderer

// --- Feature 5B: Default Credential Spray ---
CREDSPRAY_START:    'credspray-start',
CREDSPRAY_STOP:     'credspray-stop',
CREDSPRAY_HIT:      'credspray-hit',        // main -> renderer
CREDSPRAY_PROGRESS: 'credspray-progress',   // main -> renderer
CREDSPRAY_COMPLETE: 'credspray-complete',   // main -> renderer
CREDSPRAY_ERROR:    'credspray-error',      // main -> renderer

// --- Feature 5C: Container & Cloud Enumeration ---
CLOUDENUM_START:    'cloudenum-start',
CLOUDENUM_STOP:     'cloudenum-stop',
CLOUDENUM_FINDING:  'cloudenum-finding',    // main -> renderer
CLOUDENUM_PROGRESS: 'cloudenum-progress',   // main -> renderer
CLOUDENUM_COMPLETE: 'cloudenum-complete',   // main -> renderer
CLOUDENUM_ERROR:    'cloudenum-error',      // main -> renderer

// --- Feature 5D: MiTM ARP Proxy ---
MITM_START:         'mitm-start',
MITM_STOP:          'mitm-stop',
MITM_PACKET:        'mitm-packet',          // main -> renderer
MITM_CRED_FOUND:    'mitm-cred-found',      // main -> renderer
MITM_STATUS:        'mitm-status',          // main -> renderer
MITM_ERROR:         'mitm-error',           // main -> renderer
```

### 2. `src/shared/networkConstants.js` — New Constants

```js
// Feature 5B — Default credential spray pairs (IoT / network gear)
export const IOT_DEFAULT_CREDENTIALS = [
  { user: 'admin',      pass: 'admin' },
  { user: 'admin',      pass: 'password' },
  { user: 'admin',      pass: '1234' },
  { user: 'admin',      pass: '' },
  { user: 'root',       pass: 'root' },
  { user: 'root',       pass: 'toor' },
  { user: 'root',       pass: '' },
  { user: 'cisco',      pass: 'cisco' },
  { user: 'guest',      pass: 'guest' },
  { user: 'user',       pass: 'user' },
  { user: 'support',    pass: 'support' },
  { user: 'service',    pass: 'service' },
  { user: 'supervisor', pass: 'supervisor' },
  { user: 'ubnt',       pass: 'ubnt' },     // Ubiquiti
  { user: 'pi',         pass: 'raspberry' }, // Raspberry Pi
  { user: 'admin',      pass: 'admin1234' },
  { user: 'admin',      pass: '123456' },
];

// Feature 5C — Container/Cloud indicator ports
export const CONTAINER_INDICATOR_PORTS = {
  DOCKER_DAEMON:   2375,  // Docker remote API (unencrypted) — CRITICAL
  DOCKER_DAEMON_TLS: 2376, // Docker remote API (TLS)
  KUBELET:         10250, // Kubernetes Kubelet API — CRITICAL
  KUBELET_RO:      10255, // Kubernetes Kubelet read-only API (deprecated)
  KUBE_API:        6443,  // Kubernetes API server (TLS)
  KUBE_API_HTTP:   8080,  // Kubernetes API server (insecure, legacy)
  ETCD:            2379,  // etcd client port
  ETCD_PEER:       2380,  // etcd peer port
  CONSUL:          8500,  // HashiCorp Consul HTTP API
  NOMAD:           4646,  // HashiCorp Nomad HTTP API
  VAULT:           8200,  // HashiCorp Vault API
  PORTAINER:       9000,  // Portainer Docker management UI
  WEAVE_NET:       6783,  // Weave Net overlay
  FLANNEL:         8472,  // Flannel VXLAN UDP
  PROMETHEUS:      9090,  // Prometheus metrics
  GRAFANA:         3000,  // Grafana dashboard
  CLOUD_META_HTTP: 80,    // HTTP (probe for cloud metadata routes)
};

// Cloud metadata probe paths (SSRF indicators)
export const CLOUD_METADATA_PATHS = [
  '/latest/meta-data/',                          // AWS EC2
  '/metadata/instance?api-version=2021-02-01',   // Azure IMDS
  '/computeMetadata/v1/',                        // GCP
  '/opc/v1/instance/',                           // Oracle Cloud
  '/v1/data-dog',                                // DigitalOcean
];

// Feature 5A — Hardening monitor defaults
export const HARDENING_MONITOR_INTERVALS = {
  CONTINUOUS:  60 * 1000,       // 1 minute
  FREQUENT:    5 * 60 * 1000,   // 5 minutes
  STANDARD:    15 * 60 * 1000,  // 15 minutes
  RELAXED:     60 * 60 * 1000,  // 1 hour
};
```

### 3. `src/main/store.js` — Schema Additions

Add `hardeningMonitor` and `credSpray` to the electron-store schema:

```js
hardeningMonitor: {
  type: 'object',
  properties: {
    enabled:          { type: 'boolean', default: false },
    intervalMs:       { type: 'number',  default: 900000 },  // 15 min
    notifySystem:     { type: 'boolean', default: true },
    autoSnapshot:     { type: 'boolean', default: true },
    maxBaselines:     { type: 'number',  default: 10 },
  },
  default: { enabled: false, intervalMs: 900000, notifySystem: true, autoSnapshot: true, maxBaselines: 10 }
},
baselines: {
  type: 'object',
  default: {}   // keyed by subnet CIDR string
},
credSpray: {
  type: 'object',
  properties: {
    consentGiven: { type: 'boolean', default: false }
  },
  default: { consentGiven: false }
}
```

---

## 5A — Continuous Delta Monitoring (Hardening Mode)

### Design Goals

- Run background re-scans of a target subnet on a configurable schedule
- Diff each new scan against the stored baseline for that subnet
- Alert (in-app notification + optional OS notification) when:
  - A **new host** appears on the network
  - A new **open port** appears on an existing host
  - A previously-open port **closes** (potential incident or evasion)
  - A host's **hostname or MAC address** changes
- Allow the user to **acknowledge** alerts or **promote** the new state to the new baseline

### Backend: `src/main/hardeningMonitor.js`

**Module Responsibilities:**
- `startMonitor(subnet, options, mainWindow)` — begins an interval-based re-scan loop
- `stopMonitor(subnet)` — clears the interval and cancels any running probe
- `setBaseline(subnet, hosts)` — persists the current host array as the new baseline
- `getBaseline(subnet)` — retrieves the stored baseline from electron-store
- `diffSnapshots(baseline, current)` — pure function: computes structural delta between two host arrays
- Internal: `runMonitorCycle(subnet, mainWindow)` — runs one probe cycle, diffs, emits results

**Data Structures:**

```js
// A host snapshot entry stored in electron-store
{
  ip: '192.168.1.5',
  mac: 'AA:BB:CC:DD:EE:FF',
  hostname: 'desktop-abc',
  ports: [22, 80, 443],         // open port numbers only
  firstSeen: 1700000000000,     // epoch ms
  lastSeen: 1700000000000,
}

// Delta result object emitted on HARDENING_DELTA_ALERT
{
  subnet: '192.168.1.0/24',
  timestamp: 1700000000000,
  newHosts:        [{ ip, mac, hostname, ports }],
  removedHosts:    [{ ip, mac, hostname }],
  changedHosts: [
    {
      ip: '192.168.1.5',
      newPorts:     [8080],
      closedPorts:  [23],
      macChanged:   false,
      hostnameChanged: true,
      prevHostname: 'old-name',
      currHostname: 'new-name',
    }
  ],
  severity: 'critical' | 'warning' | 'info'  // derived from delta content
}
```

**Diffing Algorithm (`diffSnapshots`):**

```
Input: baseline[], current[]
1. Build a Map<ip, host> for both arrays
2. New hosts = IPs in current not in baseline
3. Removed hosts = IPs in baseline not in current
4. Changed hosts = IPs in both; compare port sets (symmetric diff), MAC, hostname
5. Derive severity:
   - 'critical': new host OR new port on known host
   - 'warning': port closed OR MAC/hostname changed
   - 'info': no changes detected
6. Return delta object; if severity === 'info', return null (no alert)
```

**Scheduling:**

- Store active monitors as `Map<subnet, { intervalId, running: bool }>`
- Each cycle: acquire a "running" flag to prevent overlapping scans
- Use `scanner.js`'s lightweight ARP/ping probe (not Nmap) to keep cycle fast
- For deep diff with port changes: optionally run a quick TCP connect scan (Node.js `net.createConnection`) against `COMMON_PORTS` for changed/new hosts
- Persist last-run timestamp; on app restart, immediately run a catch-up cycle if elapsed > interval

**OS Notifications:**

```js
import { Notification } from 'electron';

function sendSystemNotification(delta) {
  if (!Notification.isSupported()) return;
  new Notification({
    title: `NetSpecter Alert — ${delta.subnet}`,
    body: buildAlertSummary(delta),
    urgency: delta.severity === 'critical' ? 'critical' : 'normal'
  }).show();
}
```

**IPC Handler Registration (in `main.js`):**

```js
ipcMain.handle(IPC_CHANNELS.HARDENING_START_MONITOR, async (_e, { subnet, options }) => {
  // Validate subnet is a valid CIDR
  startMonitor(subnet, options, mainWindow);
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.HARDENING_STOP_MONITOR, async (_e, { subnet }) => {
  stopMonitor(subnet);
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.HARDENING_SET_BASELINE, async (_e, { subnet, hosts }) => {
  setBaseline(subnet, hosts);
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.HARDENING_GET_BASELINE, async (_e, { subnet }) => {
  return getBaseline(subnet);
});

ipcMain.handle(IPC_CHANNELS.HARDENING_GET_SCHEDULES, async () => {
  return getActiveMonitors();  // returns Map as plain object
});
```

### Preload & Renderer API

**`src/main/preload.js` additions:**

```js
hardeningMonitor: {
  start:       (subnet, options) => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_START_MONITOR, { subnet, options }),
  stop:        (subnet)          => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_STOP_MONITOR, { subnet }),
  setBaseline: (subnet, hosts)   => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_SET_BASELINE, { subnet, hosts }),
  getBaseline: (subnet)          => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_GET_BASELINE, { subnet }),
  getSchedules:()                => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_GET_SCHEDULES),
  onDeltaAlert: (cb) => ipcRenderer.on(IPC_CHANNELS.HARDENING_DELTA_ALERT,   (_e, v) => cb(v)),
  onDeltaReport:(cb) => ipcRenderer.on(IPC_CHANNELS.HARDENING_DELTA_REPORT,  (_e, v) => cb(v)),
  onStatus:    (cb)  => ipcRenderer.on(IPC_CHANNELS.HARDENING_MONITOR_STATUS, (_e, v) => cb(v)),
},
```

**`src/renderer/api.js` addition** (mirrors preload, used by index.js):

```js
export const hardeningMonitor = window.electronAPI.hardeningMonitor;
```

### UI: Hardening Monitor Side Panel (`#hardening-panel`)

**Panel Width:** 520px — right-side slide-in, consistent with Dir Fuzzer panel.

**Header Controls:**
- `#btn-hardening-open` — shield icon, always visible (no external dep), `.hardening-mode` CSS class for active state (red pulsing badge)
- Toggle button with state: `[INACTIVE]` → `[MONITORING]` → animated pulse indicator

**Panel Layout:**

```
┌─────────────────────────────────────────────────┐
│  [Shield Icon] Hardening Monitor         [X]    │
├─────────────────────────────────────────────────┤
│  Subnet: [192.168.1.0/24 ▼]                     │
│  Interval: [● Continuous] [15min] [1hr] [Custom]│
│  [Set Current Scan as Baseline]  [Start Monitor] │
├─────────────────────────────────────────────────┤
│  ACTIVE ALERTS                                  │
│  ┌───────────────────────────────────────────┐  │
│  │ 🔴 CRITICAL — New host 192.168.1.42       │  │
│  │    MAC: 00:11:22:33:44:55 (Unknown vendor)│  │
│  │    First seen: 14:32:01                   │  │
│  │    [Investigate] [Add to Whitelist]       │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │ 🟡 WARNING — Port 8080 opened on .1.5     │  │
│  │    Hostname: desktop-abc                  │  │
│  │    [Scan Port] [Acknowledge]              │  │
│  └───────────────────────────────────────────┘  │
├─────────────────────────────────────────────────┤
│  BASELINE SUMMARY                               │
│  Subnet: 192.168.1.0/24 | 23 hosts | 14:00:00  │
│  [View Full Baseline] [Export Delta Report]     │
└─────────────────────────────────────────────────┘
```

**Alert Card Interactions:**
- `[Investigate]` — opens the host details panel for the flagged IP
- `[Scan Port]` — triggers a targeted Nmap scan on the flagged port
- `[Add to Whitelist]` — adds the host to `state.whitelist`; suppresses future alerts
- `[Acknowledge]` — dismisses the card visually (not persisted; re-appears on next delta)
- `[Promote to Baseline]` — updates the stored baseline to include this change

**Status Bar:**
- Pulsing green dot when monitoring is active
- Last scan time and next scan countdown timer
- Alert counter badge on `#btn-hardening-open` header button

**CSS Classes:**
- `.hardening-only` — for header button conditional visibility (no dep — always shown)
- `.alert-critical` — red border/glow
- `.alert-warning` — orange border/glow
- `.hardening-active` on `body` — enables pulsing indicator on panel button

---

## 5B — Default Credential Spraying

### Design Goals

- Spray a curated list of known IoT/device default credentials against discovered hosts
- Supported protocols: **HTTP Basic Auth**, **HTTP Form-based**, **SSH** (via `ssh2` npm or Hydra fallback), **Telnet** (via raw `net.Socket`)
- Pure Node.js for HTTP/Telnet; optional Hydra delegation for SSH/FTP
- Rate-limited (max 3 requests/sec per host) — not a full brute-force; a quick spray
- Strict consent flow (same `#pentest-consent-overlay` pattern as Feature 4)
- Never logs or persists credentials in cleartext beyond the session

### Backend: `src/main/credSpray.js`

**Module Responsibilities:**
- `startCredSpray(opts, onHit, onProgress, onComplete, onError)` — async spray runner
- `stopCredSpray()` — cancels via AbortController
- `cleanupCredSpray()` — called on app close
- Protocol handlers (pure Node.js):
  - `sprayHttpBasic(ip, port, credentials, signal)` — HEAD/GET with `Authorization: Basic` header
  - `sprayHttpForm(ip, port, opts, credentials, signal)` — POST with form body; detect success by status code or redirect pattern
  - `sprayTelnet(ip, credentials, signal)` — raw TCP socket; read banner, write `user\r\npass\r\n`, check prompt
- Optional Hydra delegation for SSH when Hydra is installed:
  - Build temporary wordlist files in `os.tmpdir()` → delete after use
  - Use `spawn('hydra', [...args])` with arg array (never shell string)

**Configuration Object:**

```js
{
  targets: ['192.168.1.1', '192.168.1.5'],  // validated IPs only
  protocols: ['http-basic', 'http-form', 'telnet'],  // ssh requires hydra
  ports: { 'http-basic': 80, 'telnet': 23, 'ssh': 22 },
  credentials: IOT_DEFAULT_CREDENTIALS,     // from networkConstants.js, or user-loaded
  customCredentials: null,                  // optional user-supplied array
  delayMs: 400,                             // per-attempt delay (rate limiting)
  timeoutMs: 3000,                          // per-connection timeout
  stopOnFirstHit: false,                    // continue or stop per-host after a hit
}
```

**Hit Event Payload:**

```js
{
  ip:       '192.168.1.1',
  protocol: 'http-basic',
  port:     80,
  user:     'admin',
  pass:     'admin',
  evidence: 'HTTP 200 OK (was 401)',
  severity: 'critical'
}
```

**Security Controls:**
- `AbortController` passed into all async loops; `signal.aborted` checked between attempts
- Temporary files (for Hydra wordlists) written to `os.tmpdir()` with random suffix, deleted in `finally` blocks
- No credential is ever written to electron-store, logs, or disk beyond temp Hydra files
- Validate each target IP against `ipRegex` before spawning any connection
- Rate limiting enforced with `await sleep(opts.delayMs)` between attempts

**IPC Handler (in `main.js`):**

```js
ipcMain.handle(IPC_CHANNELS.CREDSPRAY_START, async (_e, opts) => {
  // validate: each ip in opts.targets passes ipRegex
  // validate: opts.protocols is a subset of allowed list
  startCredSpray(opts,
    hit      => mainWindow.webContents.send(IPC_CHANNELS.CREDSPRAY_HIT, hit),
    progress => mainWindow.webContents.send(IPC_CHANNELS.CREDSPRAY_PROGRESS, progress),
    result   => mainWindow.webContents.send(IPC_CHANNELS.CREDSPRAY_COMPLETE, result),
    err      => mainWindow.webContents.send(IPC_CHANNELS.CREDSPRAY_ERROR, { message: err.message })
  );
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.CREDSPRAY_STOP, async () => {
  stopCredSpray();
  return { ok: true };
});
```

### Preload & Renderer API

**`src/main/preload.js` additions:**

```js
credSpray: {
  start:      (opts) => ipcRenderer.invoke(IPC_CHANNELS.CREDSPRAY_START, opts),
  stop:       ()     => ipcRenderer.invoke(IPC_CHANNELS.CREDSPRAY_STOP),
  onHit:      (cb)   => ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_HIT,      (_e, v) => cb(v)),
  onProgress: (cb)   => ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_PROGRESS, (_e, v) => cb(v)),
  onComplete: (cb)   => ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_COMPLETE, (_e, v) => cb(v)),
  onError:    (cb)   => ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_ERROR,    (_e, v) => cb(v)),
},
```

### UI: Credential Spray Modal (`#credspray-modal-overlay`)

**Trigger Points:**
- `#btn-credspray-open` in header toolbar (`.pentest-only` — only visible when in pentest mode)
- "Default Credential Spray" button in host details panel's "Quick Actions" section (pre-fills single target)
- `window.__openCredSprayModal(ip)` exposed for programmatic integration

**Modal Layout:**

```
┌──────────────────────────────────────────────────────┐
│  Default Credential Spray                      [X]   │
├──────────────────────────────────────────────────────┤
│  TARGETS                                             │
│  [Single IP: _________] [Use all discovered hosts ○] │
│                                                      │
│  PROTOCOLS                                           │
│  [✓] HTTP Basic Auth  Port: [80___]                  │
│  [✓] HTTP Form        Form Path: [/login___]         │
│  [ ] Telnet           Port: [23___]                  │
│  [ ] SSH (req. Hydra) Port: [22___]                  │
│                                                      │
│  CREDENTIALS                                         │
│  ● Built-in IoT defaults (17 pairs)                  │
│  ○ Load custom list (.txt, user:pass per line)       │
│    [Browse...]                                       │
│                                                      │
│  OPTIONS                                             │
│  Delay between attempts: [400] ms                    │
│  Timeout per connection: [3000] ms                   │
│  [✓] Stop scanning host after first successful login │
│                                                      │
│  ─────────────────────────────────────────────────── │
│  [Cancel]                          [Start Spray]     │
└──────────────────────────────────────────────────────┘
```

**Results Panel (slides open below controls on start):**

```
┌──────────────────────────────────────────────────────┐
│  RESULTS   [14 / 51 attempts]  [████░░░░] 27%        │
│  ┌────────────────────────────────────────────────┐  │
│  │ 🔴 192.168.1.1  HTTP Basic  admin / admin      │  │
│  │    Evidence: HTTP 200 (was 401)  [Copy] [Open] │  │
│  ├────────────────────────────────────────────────┤  │
│  │ 🔴 192.168.1.254  HTTP Form  admin / password  │  │
│  │    Evidence: Redirect to /dashboard [Copy]     │  │
│  └────────────────────────────────────────────────┘  │
│  [Stop] [Export CSV] [Clear]                         │
└──────────────────────────────────────────────────────┘
```

**Consent Flow:**
- Re-uses existing `#pentest-consent-overlay` pattern
- `pendingBfConfig._type === 'credspray'` → after consent → calls `runCredSpray()`
- Consent is session-persistent (same as brute-force)

**Host Details Integration:**
- Inject "Spray Defaults" quick-action button for hosts where `ports` includes 80, 23, 22, or 443
- Button calls `window.__openCredSprayModal(host.ip)`

---

## 5C — Container & Cloud Enumeration

### Design Goals

- Probe discovered hosts for signs of Docker daemon, Kubernetes components, and cloud metadata endpoints
- Entirely passive-ish TCP connect + HTTP probes — zero external dependencies
- Classify findings by severity: **Critical** (unauthenticated API), **Warning** (TLS-protected API), **Info** (service detected, auth required)
- Surface findings in a dedicated panel with actionable remediation guidance
- Integrate into host details panel: show "Container/Cloud Risk" badge on hosts with hits

### Backend: `src/main/cloudEnum.js`

**Module Responsibilities:**
- `startCloudEnum(opts, onFinding, onProgress, onComplete, onError)` — async enumeration
- `stopCloudEnum()` — AbortController cancellation
- `cleanupCloudEnum()` — process map cleanup
- Probe functions (all pure Node.js `http`/`https`/`net`):
  - `probeDockerDaemon(ip, signal)` — HTTP GET to `http://ip:2375/version`; check for JSON with `ApiVersion`
  - `probeDockerDaemonTLS(ip, signal)` — HTTPS GET to `https://ip:2376/version` (self-signed expected)
  - `probeKubelet(ip, signal)` — HTTP GET to `http://ip:10250/pods` and `http://ip:10255/pods`
  - `probeKubeAPI(ip, signal)` — HTTPS GET to `https://ip:6443/version`
  - `probeEtcd(ip, signal)` — HTTP GET to `http://ip:2379/version`
  - `probeCloudMetadata(ip, signal)` — HTTP GET to `http://ip:80/latest/meta-data/` with `Host: 169.254.169.254`; then probe GCP/Azure/Oracle paths
  - `probeConsul(ip, signal)` — HTTP GET to `http://ip:8500/v1/status/leader`
  - `probePrometheus(ip, signal)` — HTTP GET to `http://ip:9090/-/ready`
  - `probePortainer(ip, signal)` — HTTP GET to `http://ip:9000/api/status`
- `fingerprint(ip, signal)` — runs all probes for a single IP; emits findings

**Finding Object:**

```js
{
  ip:          '192.168.1.20',
  service:     'docker-daemon',
  port:        2375,
  severity:    'critical',           // critical | warning | info
  title:       'Unauthenticated Docker Daemon',
  description: 'Docker Remote API exposed without TLS or authentication. An attacker can run arbitrary containers, mount host filesystem, and achieve full root code execution.',
  evidence:    'HTTP 200 — ApiVersion: 1.41, Engine: 20.10.7',
  cve:         null,
  remediation: 'Bind Docker socket to unix:///var/run/docker.sock only, or enforce TLS mutual auth. Remove -H tcp:// from dockerd flags.',
  references:  ['https://docs.docker.com/engine/security/protect-access/'],
  rawResponse: '{"ApiVersion":"1.41",...}',  // first 500 chars only
}
```

**Severity Classification Logic:**

| Service | Condition | Severity |
|---|---|---|
| Docker Daemon `:2375` | HTTP 200 with JSON | **Critical** |
| Docker Daemon `:2376` | HTTPS 200 with JSON | Warning |
| Kubelet `:10250/pods` | HTTP 200 with pod list | **Critical** |
| Kubelet `:10255/pods` | HTTP 200 (RO API) | Warning |
| etcd `:2379` | HTTP 200 | **Critical** |
| Cloud Metadata | HTTP 200 with metadata content | **Critical** |
| Consul `:8500` | HTTP 200 | Warning |
| Prometheus `:9090` | HTTP 200 | Info |
| Portainer `:9000` | HTTP 200 | Info |
| Kube API `:6443` | HTTPS 200 (unauth) | **Critical** |
| Kube API `:6443` | 401/403 | Info |

**IPC Handler (in `main.js`):**

```js
ipcMain.handle(IPC_CHANNELS.CLOUDENUM_START, async (_e, opts) => {
  // validate: opts.targets are valid IPs
  startCloudEnum(opts,
    finding  => mainWindow.webContents.send(IPC_CHANNELS.CLOUDENUM_FINDING, finding),
    progress => mainWindow.webContents.send(IPC_CHANNELS.CLOUDENUM_PROGRESS, progress),
    result   => mainWindow.webContents.send(IPC_CHANNELS.CLOUDENUM_COMPLETE, result),
    err      => mainWindow.webContents.send(IPC_CHANNELS.CLOUDENUM_ERROR, { message: err.message })
  );
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.CLOUDENUM_STOP, async () => {
  stopCloudEnum();
  return { ok: true };
});
```

### Preload & Renderer API

**`src/main/preload.js` additions:**

```js
cloudEnum: {
  start:      (opts) => ipcRenderer.invoke(IPC_CHANNELS.CLOUDENUM_START, opts),
  stop:       ()     => ipcRenderer.invoke(IPC_CHANNELS.CLOUDENUM_STOP),
  onFinding:  (cb)   => ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_FINDING,  (_e, v) => cb(v)),
  onProgress: (cb)   => ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_PROGRESS, (_e, v) => cb(v)),
  onComplete: (cb)   => ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_COMPLETE, (_e, v) => cb(v)),
  onError:    (cb)   => ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_ERROR,    (_e, v) => cb(v)),
},
```

### UI: Cloud Enumeration Side Panel (`#cloudenum-panel`)

**Panel Width:** 580px — right-side slide-in

**Header Controls:**
- `#btn-cloudenum-open` — cloud icon with Docker/K8s sub-icon, always visible
- `window.__openCloudEnumPanel(ip)` for single-host scan from host details

**Panel Layout:**

```
┌───────────────────────────────────────────────────────┐
│  [Cloud Icon] Container & Cloud Enumeration     [X]   │
├───────────────────────────────────────────────────────┤
│  TARGETS                                              │
│  ● All discovered hosts (23 hosts)                    │
│  ○ Single host: [________________]                    │
│                                                       │
│  PROBES (all enabled by default)                      │
│  [✓] Docker Daemon  [✓] Kubernetes  [✓] etcd          │
│  [✓] Consul/Vault   [✓] Cloud Metadata               │
│  [✓] Prometheus     [✓] Portainer                    │
│                                                       │
│  Concurrency: [═══●═══════] 10 simultaneous           │
│  Timeout:     [3000] ms per probe                     │
│                                                       │
│  [Start Enumeration]                                  │
├───────────────────────────────────────────────────────┤
│  FINDINGS  [3 Critical  2 Warning  5 Info]            │
│                                                       │
│  🔴 CRITICAL — 192.168.1.20 — Docker Daemon Exposed  │
│  Port 2375 — Unauthenticated HTTP API                 │
│  "ApiVersion: 1.41, Engine: 20.10.7"                  │
│  ► An attacker can spawn containers, mount host FS,   │
│    and achieve full host takeover.                    │
│  REMEDIATION: Bind to unix socket; enforce TLS mTLS.  │
│  [Copy Evidence] [Scan Host] [Add to Report]          │
│                                                       │
│  🔴 CRITICAL — 192.168.1.25 — Kubelet API Exposed    │
│  Port 10250 — Pod list accessible unauthenticated     │
│  ...                                                  │
│                                                       │
│  [Stop] [Export JSON] [Export PDF Report]             │
└───────────────────────────────────────────────────────┘
```

**Host Details Integration:**
- After cloud enum runs, inject a `🐳 Container Risk` badge on host cards with findings
- Badge color: red for critical, orange for warning
- Clicking badge opens the panel filtered to that host's findings

**CSS Classes:**
- `.cloudenum-only` — for optional visibility control (no dep required → always visible)
- `.finding-critical` — red left border
- `.finding-warning` — orange left border
- `.finding-info` — blue left border

---

## 5D — Live Traffic Interception (MiTM Proxy)

### Design Goals

- Perform local ARP cache poisoning to route a target's traffic through the scanning host
- Capture and parse HTTP/HTTPS (decrypted only where possible via SSL strip) traffic
- Extract and display cleartext credentials, cookies, and tokens from intercepted HTTP streams
- This feature requires **strict user consent**, **explicit configuration**, and **prominent warnings**
- Optional external dependency: `arpspoof` (from `dsniff`) or `arp-scan`; graceful degradation if unavailable

### Security & Legal Guardrails (Non-Negotiable)

1. **Double-consent gate**: dedicated MiTM consent modal with plain-language legal warning; separate from standard pentest consent
2. **Target IP validation**: only allows targeting hosts within discovered scan results (prevents targeting of arbitrary IPs)
3. **Auto-stop timer**: mandatory maximum session duration (default 60 seconds, max 10 minutes configurable); hard-coded ceiling
4. **IP forwarding enforcement**: module must enable IPv4 forwarding (sysctl on Linux/macOS; `netsh` on Windows) before poisoning, and restore original after
5. **Gateway protection**: refuse to ARP-poison the default gateway IP unless explicitly confirmed
6. **Cleanup on crash**: register `app.on('before-quit')` cleanup to send gratuitous ARP corrections to restore ARP tables

### Backend: `src/main/mitmProxy.js`

**Module Responsibilities:**
- `startMitm(opts, onPacket, onCredFound, onStatus, onError)` — initiates ARP poisoning + capture
- `stopMitm()` — stops poisoning, restores ARP tables, stops capture
- `cleanupMitm()` — emergency cleanup on app quit
- Internal:
  - `enableIpForwarding(platform)` — platform-aware IP forwarding
  - `disableIpForwarding(platform)` — restores IP forwarding state
  - `startArpSpoof(targetIp, gatewayIp, interface, signal)` — spawns `arpspoof` process
  - `startCapture(interface, targetIp, signal)` — spawns `tshark` on target's IP filter
  - `parseHttpStream(rawData)` — extracts credentials, cookies, tokens from cleartext HTTP
  - `restoreArp(targetIp, gatewayIp, interface)` — sends `arp -s` correction commands

**Dependency Check:**
- `arpspoof` — checked via `checkDependency('arpspoof')` (new entry in `DEPENDENCY_PATHS`)
- `tshark` — already tracked; required for capture
- Graceful degradation: if `arpspoof` missing, inform user to install `dsniff`; do not partially execute

**Configuration Object:**

```js
{
  targetIp:    '192.168.1.5',     // victim; must be in state.hosts
  gatewayIp:   '192.168.1.1',     // attacker's default gateway
  interface:   'eth0',            // captured from GET_INTERFACES
  durationMs:  60000,             // mandatory timer; max 600000 (10 min)
  captureHttp: true,
  extractCreds: true,
}
```

**Packet Event:**

```js
{
  timestamp:   1700000000000,
  srcIp:       '192.168.1.5',
  dstIp:       '93.184.216.34',
  protocol:    'HTTP',
  method:      'POST',
  host:        'example.com',
  path:        '/login',
  body:        'username=admin&password=...',  // truncated at 2000 chars
  credFound:   true,
  credential:  { user: 'admin', pass: '...', source: 'POST body' }
}
```

**IPC Handlers (in `main.js`):**

```js
ipcMain.handle(IPC_CHANNELS.MITM_START, async (_e, opts) => {
  // Validate targetIp is in state.hosts (from a completed scan)
  // Validate durationMs <= 600000
  startMitm(opts, ...);
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.MITM_STOP, async () => {
  await stopMitm();
  return { ok: true };
});
```

**Cleanup Registration (in `main.js`):**

```js
app.on('before-quit', async () => {
  await cleanupMitm();
});
```

### Preload & Renderer API

**`src/main/preload.js` additions:**

```js
mitm: {
  start:       (opts) => ipcRenderer.invoke(IPC_CHANNELS.MITM_START, opts),
  stop:        ()     => ipcRenderer.invoke(IPC_CHANNELS.MITM_STOP),
  onPacket:    (cb)   => ipcRenderer.on(IPC_CHANNELS.MITM_PACKET,    (_e, v) => cb(v)),
  onCredFound: (cb)   => ipcRenderer.on(IPC_CHANNELS.MITM_CRED_FOUND,(_e, v) => cb(v)),
  onStatus:    (cb)   => ipcRenderer.on(IPC_CHANNELS.MITM_STATUS,    (_e, v) => cb(v)),
  onError:     (cb)   => ipcRenderer.on(IPC_CHANNELS.MITM_ERROR,     (_e, v) => cb(v)),
},
```

### UI: MiTM Intercept Side Panel (`#mitm-panel`)

**Panel Width:** 640px — widest panel; requires space for HTTP traffic display

**Header Controls:**
- `#btn-mitm-open` — antenna/intercept icon; `.tshark-only.arpspoof-only` — visible only when both deps present
- Prominent red `[LIVE INTERCEPT]` badge when active

**MiTM Consent Modal (`#mitm-consent-overlay`):**

```
┌──────────────────────────────────────────────────────────┐
│  ⚠️  LIVE TRAFFIC INTERCEPTION — LEGAL WARNING           │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  This feature performs ARP cache poisoning to intercept  │
│  traffic between the selected target and your network    │
│  gateway. This technique:                                │
│                                                          │
│  • Is ILLEGAL when performed on networks you do not      │
│    own or have EXPLICIT written authorization to test    │
│  • May disrupt network connectivity for the target       │
│  • Will automatically stop after the selected duration   │
│                                                          │
│  This tool is intended solely for:                       │
│  - Security professionals on authorized engagements      │
│  - Testing your own devices on your own network          │
│  - Educational demonstration in controlled labs          │
│                                                          │
│  [ ] I have explicit authorization to test this network  │
│  [ ] I understand the legal risks and consequences       │
│  [ ] I accept full responsibility for my actions         │
│                                                          │
│  [Cancel]                          [I Accept — Continue] │
│                                    (disabled until all ✓) │
└──────────────────────────────────────────────────────────┘
```

**Panel Layout:**

```
┌──────────────────────────────────────────────────────────┐
│  [Intercept Icon] MiTM Traffic Intercept          [X]    │
│  [● LIVE — 192.168.1.5 → 192.168.1.1 — 00:42 remaining] │
├──────────────────────────────────────────────────────────┤
│  CONFIG                                                  │
│  Target:  [192.168.1.5 ▼]  Gateway: [192.168.1.1 ▼]    │
│  Iface:   [eth0 ▼]         Duration: [60s ▼]            │
│  [✓] Extract credentials   [✓] Log HTTP traffic         │
│  [Start Intercept]                                       │
├──────────────────────────────────────────────────────────┤
│  CAPTURED CREDENTIALS                                    │
│  ┌──────────────────────────────────────────────────┐   │
│  │ 🔴 admin / password123  (POST /login on site.co) │   │
│  │    14:33:02 — example.com [Copy] [Redact]        │   │
│  └──────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────┤
│  HTTP TRAFFIC LOG                                        │
│  [Filter: ________] [✓] Creds only  [ ] All requests    │
│  ┌──────────────────────────────────────────────────┐   │
│  │ 14:33:01  POST  example.com  /login  200         │   │
│  │ 14:33:00  GET   api.site.co  /v1/user  200       │   │
│  └──────────────────────────────────────────────────┘   │
│  [Stop] [Export PCAP] [Export CSV] [Clear]               │
└──────────────────────────────────────────────────────────┘
```

**Safety Timer:**
- Countdown timer always visible when active
- `setInterval` on renderer + `setTimeout` on backend both enforce session limit
- `[STOP]` button always accessible; never hidden during active session

**CSS Classes:**
- `.arpspoof-only.tshark-only` — double dependency gating
- `.mitm-active` on `body` — enables red warning border on app chrome during active session

---

## Integration: `src/main/main.js`

### Imports to Add

```js
import { startMonitor, stopMonitor, setBaseline, getBaseline, getActiveMonitors, cleanupMonitor } from './hardeningMonitor.js';
import { startCredSpray, stopCredSpray, cleanupCredSpray } from './credSpray.js';
import { startCloudEnum, stopCloudEnum, cleanupCloudEnum } from './cloudEnum.js';
import { startMitm, stopMitm, cleanupMitm } from './mitmProxy.js';
```

### IPC Handler Registration Block

Add after existing Feature 4 handlers:

```js
// --- Feature 5A: Hardening Monitor ---
ipcMain.handle(IPC_CHANNELS.HARDENING_START_MONITOR, ...);
ipcMain.handle(IPC_CHANNELS.HARDENING_STOP_MONITOR, ...);
ipcMain.handle(IPC_CHANNELS.HARDENING_SET_BASELINE, ...);
ipcMain.handle(IPC_CHANNELS.HARDENING_GET_BASELINE, ...);
ipcMain.handle(IPC_CHANNELS.HARDENING_GET_SCHEDULES, ...);

// --- Feature 5B: Default Credential Spray ---
ipcMain.handle(IPC_CHANNELS.CREDSPRAY_START, ...);
ipcMain.handle(IPC_CHANNELS.CREDSPRAY_STOP, ...);

// --- Feature 5C: Container & Cloud Enumeration ---
ipcMain.handle(IPC_CHANNELS.CLOUDENUM_START, ...);
ipcMain.handle(IPC_CHANNELS.CLOUDENUM_STOP, ...);

// --- Feature 5D: MiTM Proxy ---
ipcMain.handle(IPC_CHANNELS.MITM_START, ...);
ipcMain.handle(IPC_CHANNELS.MITM_STOP, ...);
```

### Cleanup Registration

Add to `app.on('window-all-closed')` / `app.on('before-quit')`:

```js
cleanupMonitor();
cleanupCredSpray();
cleanupCloudEnum();
await cleanupMitm();   // async: must await ARP table restoration
```

---

## State Object (`src/renderer/state.js`)

Add to the shared state:

```js
// Feature 5A
isHardeningMonitorActive: false,
hardeningAlerts: [],          // [{ subnet, delta, acknowledgedAt }]
hardeningBaselines: {},       // { [subnet]: { hosts[], capturedAt } }

// Feature 5B
isCredSprayRunning: false,
credSprayHits: [],            // [{ ip, protocol, port, user, pass, evidence }]

// Feature 5C
isCloudEnumRunning: false,
cloudFindings: [],            // [{ ip, service, port, severity, title, ... }]

// Feature 5D
isMitmActive: false,
mitmPackets: [],              // [{ timestamp, srcIp, dstIp, host, path, ... }]
mitmCreds: [],                // [{ user, pass, source, host }]
```

---

## Dependency Management

### New Dependency: `arpspoof` (Feature 5D only)

Add to `DEPENDENCY_PATHS` in `src/main/store.js`:

```js
arpspoof: {
  win32: ['arpspoof'],      // not commonly available on Windows; show warning
  darwin: [
    'arpspoof',
    '/opt/homebrew/bin/arpspoof',
    '/usr/local/bin/arpspoof',
  ],
  linux: [
    'arpspoof',
    '/usr/bin/arpspoof',
    '/usr/sbin/arpspoof',
  ],
  versionArg: '--help'
}
```

Add to `store.js` schema:

```js
arpspoof: {
  type: 'object',
  properties: {
    enabled: { type: 'boolean', default: false },
    path:    { type: 'string',  default: '' }
  },
  default: { enabled: false, path: '' }
}
```

Add to `state.js`:

```js
isArpspoofInstalled: false,
```

Add to startup dependency check in `src/renderer/index.js`:

```js
checkDependency('arpspoof').then(r => {
  state.isArpspoofInstalled = r.installed;
  syncDependencyToggle('arpspoof', r.installed);
});
```

Add CSS class `.arpspoof-only` throughout `index.html` and `style.css`.

---

## Settings Panel Additions (`src/renderer/index.html`)

Add a new **Hardening** settings section to the existing settings modal:

```html
<!-- Feature 5A Settings -->
<div class="settings-section">
  <h3>Hardening Monitor</h3>
  <label>
    <span>Scan Interval</span>
    <select id="setting-hardening-interval">
      <option value="60000">1 minute (Continuous)</option>
      <option value="300000">5 minutes</option>
      <option value="900000" selected>15 minutes (Default)</option>
      <option value="3600000">1 hour</option>
    </select>
  </label>
  <label class="toggle-row">
    <span>System notifications for alerts</span>
    <input type="checkbox" id="setting-hardening-notify" checked />
  </label>
  <label class="toggle-row">
    <span>Auto-snapshot baseline on scan complete</span>
    <input type="checkbox" id="setting-hardening-autosnap" checked />
  </label>
  <label>
    <span>Max stored baselines per subnet</span>
    <input type="number" id="setting-hardening-maxbaselines" value="10" min="1" max="50" />
  </label>
</div>
```

---

## CSS Theme Additions (`src/renderer/style.css`)

### New Variables

```css
:root {
  /* Feature 5 — Hardening colors */
  --hardening:       #22c55e;   /* green for "protected" state */
  --hardening-alert: #ef4444;   /* red for critical alert */
  --hardening-warn:  #f97316;   /* orange for warning */

  /* Feature 5D — MiTM active state */
  --mitm-active-glow: rgba(239, 68, 68, 0.3);
}
```

### MiTM Active Body State

```css
body.mitm-active {
  outline: 3px solid var(--hardening-alert);
  outline-offset: -3px;
  animation: mitm-pulse 1.5s ease-in-out infinite;
}

@keyframes mitm-pulse {
  0%, 100% { outline-color: rgba(239, 68, 68, 0.8); }
  50%       { outline-color: rgba(239, 68, 68, 0.2); }
}
```

### Alert Card Styles

```css
.hardening-alert-card {
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-left: 4px solid var(--hardening-alert);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 8px;
}

.hardening-alert-card.warning {
  background: rgba(249, 115, 22, 0.08);
  border-color: rgba(249, 115, 22, 0.3);
  border-left-color: var(--hardening-warn);
}

.finding-critical { border-left: 4px solid #ef4444; }
.finding-warning  { border-left: 4px solid #f97316; }
.finding-info     { border-left: 4px solid #3b82f6; }

.severity-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
}
.severity-badge.critical { background: rgba(239,68,68,0.2); color: #ef4444; }
.severity-badge.warning  { background: rgba(249,115,22,0.2); color: #f97316; }
.severity-badge.info     { background: rgba(59,130,246,0.2); color: #3b82f6; }
```

---

## Testing Plan

### Test Files

| File | Covers |
|---|---|
| `test/hardeningMonitor.test.js` | Delta diffing, baseline storage, severity logic |
| `test/credSpray.test.js` | HTTP probe logic, rate limiting, cancellation |
| `test/cloudEnum.test.js` | Probe responses, severity classification, fingerprinting |
| `test/mitmProxy.test.js` | ARP command construction, cleanup, session timer |

### `test/hardeningMonitor.test.js` — Key Test Cases

```js
describe('diffSnapshots', () => {
  it('returns null for identical snapshots');
  it('detects a new host with severity critical');
  it('detects a removed host with severity warning');
  it('detects a new open port as critical');
  it('detects a closed port as warning');
  it('detects a MAC address change as warning');
  it('detects a hostname change as warning');
  it('handles empty baseline (first run)');
  it('handles empty current scan (network down)');
  it('correctly identifies severity from mixed deltas');
});

describe('setBaseline / getBaseline', () => {
  it('persists a baseline and retrieves it by subnet');
  it('returns null for unknown subnet');
  it('overwrites existing baseline on re-set');
});
```

### `test/credSpray.test.js` — Key Test Cases

```js
describe('sprayHttpBasic', () => {
  it('returns hit when server responds 200 to basic auth after 401');
  it('returns no hit when server responds 401 to all credentials');
  it('respects AbortController cancellation mid-spray');
  it('handles connection timeout gracefully');
  it('respects the per-attempt delay');
  it('validates target IP before connecting');
  it('does not log credentials to console');
});

describe('sprayTelnet', () => {
  it('sends user/pass and detects successful login prompt');
  it('handles connection refused gracefully');
  it('aborts on signal');
});
```

### `test/cloudEnum.test.js` — Key Test Cases

```js
describe('probeDockerDaemon', () => {
  it('returns critical finding when port 2375 returns Docker version JSON');
  it('returns no finding when port 2375 is closed');
  it('returns no finding when response is not Docker JSON');
});

describe('probeKubelet', () => {
  it('returns critical finding when port 10250 returns pod list');
  it('returns warning when port 10255 returns pod list (RO API)');
  it('returns info when port 6443 returns 401 (auth required)');
});

describe('probeCloudMetadata', () => {
  it('returns critical finding when AWS metadata endpoint responds');
  it('returns critical finding when GCP metadata endpoint responds');
  it('skips when no metadata endpoint responds');
});

describe('fingerprint (full probe suite)', () => {
  it('runs all probes and aggregates findings for one host');
  it('respects AbortController across all sub-probes');
  it('emits progress events during enumeration');
  it('handles all probes timing out gracefully');
});
```

### `test/mitmProxy.test.js` — Key Test Cases

```js
describe('session timer enforcement', () => {
  it('automatically stops after durationMs');
  it('rejects durationMs > 600000');
  it('emits MITM_STATUS on timeout');
});

describe('target validation', () => {
  it('rejects targets not found in hosts list');
  it('rejects invalid IP formats');
  it('warns when targeting gateway IP');
});

describe('cleanup', () => {
  it('spawns arp correction commands on stopMitm()');
  it('restores IP forwarding state on stopMitm()');
  it('calls cleanupMitm() on app quit event');
});

describe('HTTP parsing', () => {
  it('extracts Basic Auth credentials from Authorization header');
  it('extracts form credentials from POST body (username/password fields)');
  it('truncates body at 2000 chars');
  it('returns no credentials when no cleartext auth found');
});
```

---

## File Creation Summary

The following new files need to be created:

| File | Description |
|---|---|
| `src/main/hardeningMonitor.js` | 5A backend — delta monitoring, baseline management |
| `src/main/credSpray.js` | 5B backend — default credential spraying |
| `src/main/cloudEnum.js` | 5C backend — container & cloud probe suite |
| `src/main/mitmProxy.js` | 5D backend — ARP poisoning + HTTP capture |
| `test/hardeningMonitor.test.js` | 5A Vitest unit tests |
| `test/credSpray.test.js` | 5B Vitest unit tests |
| `test/cloudEnum.test.js` | 5C Vitest unit tests |
| `test/mitmProxy.test.js` | 5D Vitest unit tests |

The following existing files need to be modified:

| File | Changes |
|---|---|
| `src/shared/ipc.js` | +30 new channel constants |
| `src/shared/networkConstants.js` | `IOT_DEFAULT_CREDENTIALS`, `CONTAINER_INDICATOR_PORTS`, `CLOUD_METADATA_PATHS`, `HARDENING_MONITOR_INTERVALS` |
| `src/main/store.js` | `hardeningMonitor`, `baselines`, `credSpray`, `arpspoof` schema + DEPENDENCY_PATHS |
| `src/main/preload.js` | `hardeningMonitor`, `credSpray`, `cloudEnum`, `mitm` bridge objects |
| `src/main/main.js` | imports + IPC handler registrations + cleanup hooks |
| `src/renderer/api.js` | mirror new preload bridge namespaces |
| `src/renderer/state.js` | new state fields for all 4 sub-features |
| `src/renderer/index.html` | 4 new panels/modals, settings section, header buttons |
| `src/renderer/index.js` | event wiring, UI logic for all 4 sub-features |
| `src/renderer/style.css` | new CSS variables, alert card styles, mitm-active body animation |

---

## Implementation Order (Recommended)

Implement in this order to build on stable foundations:

1. **Shared infrastructure first** — `ipc.js`, `networkConstants.js`, `store.js` schema changes
2. **5C — Cloud Enumeration** — pure HTTP probes, no external deps, lowest risk, good integration test for probe pattern
3. **5A — Hardening Monitor** — builds on existing scanner infrastructure; validates delta algorithm
4. **5B — Credential Spray** — extends brute-force consent flow already established in Feature 4A
5. **5D — MiTM Proxy** — most complex; requires external deps; implement last with full guard rails

Each sub-feature should be merged independently in its own commit set following the pattern:
```
feat(hardening): implement delta monitoring engine (5A backend)
feat(hardening): add hardening monitor UI panel (5A renderer)
feat(hardening): add hardeningMonitor tests (5A tests)
```

---

## Risk Register

| Risk | Mitigation |
|---|---|
| Hardening monitor scan storms (too frequent, loads network) | Enforce minimum 30s interval; use lightweight ping/ARP probes, not Nmap |
| Credential spray triggers IDS/IPS on target | Rate limit enforced (400ms delay); document user must own network |
| Cloud metadata probe misidentifies web server as cloud | Strict response body validation (must contain known metadata field names) |
| MiTM ARP poisoning breaks target connectivity | IP forwarding enabled before poisoning; restored on cleanup; auto-stop timer |
| MiTM fails to restore ARP on crash | `app.on('before-quit')` async cleanup + OS-level gratuitous ARP broadcast |
| Temp credential files for Hydra persist on disk | Written to `os.tmpdir()`, deleted in `finally` block; names are random UUIDs |
| Baseline grows unbounded in electron-store | `maxBaselines` setting enforced; FIFO rotation when limit reached |
