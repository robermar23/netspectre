<div align="center">
  <img src="src/renderer/public/logo.png" alt="NetSpecter Logo" width="200" />
</div>

# NetSpecter: Network Host Detection & Forensic Scanner

**Version 1.18.0** — A modern, cross-platform desktop application built with Electron 40, Node.js, and Vanilla JS that provides deep network visibility, OS fingerprinting, forensic-level port scanning, passive packet intelligence, and a full-stack web application security testing workspace. Includes a comprehensive **Offensive Penetration Testing** suite for red team operations.

![App Dashboard Preview](resources/dashboard-preview.png)

---

## Features

### 🔍 Network Discovery & Scanning

- **Blazing Fast Subnet Sweeping**: Heavily concurrent asynchronous ICMP ping sweeps followed by localized ARP table inspection instantly discover all physical devices on your local network — including hosts that block ICMP via TCP port probing fallback.
- **Advanced Hardware Identification**: Discovered MAC addresses are resolved via a local memory cache backed by a rate-limited, dynamic lookup to the live `macvendors.com` API, providing highly accurate manufacturer readings (e.g., *Raspberry Pi Foundation*, *Sony Interactive Entertainment*, *Apple, Inc.*).
- **Heuristic OS Fingerprinting**: Intelligently determines the underlying Operating System (Windows, macOS, Linux, iOS, Android) by analyzing hardware vendor combined with unique port signatures (e.g., `445`+`135` → Windows; `22`+`548` → macOS).
- **Forensic Deep Scans**: Click any discovered host to trigger a cancellable deep scan. The Node.js backend chunks raw TCP socket sweeps across all **65,535 ports** to bypass OS networking limits, with live progress streaming.
- **Nmap Integration**: Optional Nmap-powered scans with `vuln` script support, XML output parsing, and real-time CVE badge injection. Discovered CVEs are automatically matched and injected into the host's Details panel with severity ratings and reference links.
- **CVE Discovery & Badge Injection**: NetSpecter parses incoming Nmap `vuln` terminal output asynchronously in real-time. Matched CVEs map to the host's audit cache, injecting stylized vulnerability definitions and dynamic reference links directly into the Details panel.

### 📡 Passive Network Intelligence

- **Passive Packet Capture**: Advanced raw packet capture powered by the `tshark` backend. All capture operations are non-destructive and passive.
- **Cleartext Credential Sniffing**: Detect credentials transmitted in plaintext over FTP, HTTP Basic Auth, POP3, and IMAP protocols. Detected credentials are flagged in the host's findings without being persisted to disk.
- **Rogue DHCP Detection**: Identifies unauthorized DHCP servers on the network by monitoring DHCP OFFER and ACK messages and comparing against known/expected DHCP servers.
- **Rogue DNS Detection**: Monitors DNS response traffic to detect DNS responses originating from unexpected resolvers — a key indicator of DNS hijacking or spoofing attacks.
- **ARP Spoofing Detection**: Real-time monitoring of ARP traffic to detect IP-to-MAC mapping conflicts, identifying man-in-the-middle positioning attempts.
- **DNS/mDNS Query Harvesting**: Passively captures DNS and mDNS queries to discover stealth hosts that do not respond to ICMP or TCP probes but announce themselves via name resolution.
- **VLAN Hopping & Tag Detection**: Integrates with `tshark` to passively listen for 802.1Q tagged frames on network interfaces, exposing misconfigured trunk ports and VLAN hopping vulnerabilities.
- **SNMP Walking & MIB Parsing**: Walk SNMPv1/v2c/v3 devices to pull routing tables, interface statistics, and firmware versions. Intelligent OID parsing with caching for known enterprise MIBs.
- **PCAP Export**: Export live or captured traffic to `.pcap` files for offline analysis with Wireshark or other packet analysis tools.
- **Interactive Topology Map**: Visual network graph powered by Cytoscape.js showing hosts, subnets, and gateway relationships, with host-type icon differentiation.

### ⚔️ Offensive Pentest Suite

> All offensive features require acceptance of the **Pentest Consent Gate** on first use. These tools are intended for authorized penetration testing only.

- **Multi-Protocol Brute-Force Engine**: Integrated [Hydra](https://github.com/vanhauser-thc/thc-hydra) orchestration for high-speed multi-protocol credential stuffing (SSH, FTP, Telnet, HTTP, SMB, RDP, etc.). Supports custom wordlists, protocol-specific targeting, and real-time progress streaming. Triggered contextually from port action buttons (e.g., SSH port 22 → "Brute Force" button appears automatically).
- **Default Credential Spray**: Spray a target host with protocol-aware default credential pairs (admin/admin, root/root, etc.) without Hydra — pure Node.js transports. Supports SSH, HTTP Basic, FTP, Telnet, and SMB. Results stream live with hit highlighting.
- **Metasploit RPC Control Plane**: Full orchestration of [Metasploit Framework](https://www.metasploit.com/) via MSFRPC. Connect to a running `msfrpcd` instance, browse the module library, launch exploits against discovered hosts, manage active sessions, and interact with the Metasploit database directly from the NetSpecter UI.
- **Interactive Reverse Shell Hub**: Multi-handler listener supporting Bash, Python, PowerShell, PHP, and Netcat reverse shell payloads. Feature-rich terminal emulation with auto-reconnect, copy-to-clipboard payload generation, and selectable listener port.
- **Web Directory Fuzzer**: Fast, concurrent web path discovery (up to 50 simultaneous requests) to locate hidden `admin`, `config`, `backup`, and API endpoints. Zero external dependencies — pure Node.js `http`/`https`. Supports custom wordlists (up to 100k entries), file extension expansion, and status code filtering. CSV export included.
- **SMB/NFS Share Explorer**: Deep inspection of network shares via `smbclient` to identify misconfigured permissions and sensitive data exposure. Browse directory trees with breadcrumb navigation and download files directly from the dashboard.

### 🌐 Web Application Testing Workspace

NetSpecter includes a complete web application security testing workspace accessible via the **Web App** tab, providing Burp Suite-style capabilities natively in the desktop app.

#### 🔒 Intercepting HTTPS Proxy (Feature 7A)

- **MITM Proxy**: On-the-fly TLS certificate generation using `node-forge` for seamless HTTPS interception. Supports HTTP CONNECT tunneling and WebSocket capture.
- **Request History**: All proxied requests/responses are persisted in a local SQLite database (`better-sqlite3`). Full HAR 1.2 export for offline analysis.
- **Browser Integration**: Configure your browser to route traffic through `127.0.0.1:<port>` (default 8080). The proxy CA certificate can be exported for installation in the browser trust store.
- **Traffic Filtering**: Filter history by host, method, status code, path, and response size. Highlight entries matching custom patterns.
- **Intercept & Edit**: Pause in-flight requests for manual inspection and modification before forwarding.

#### 🗺️ Web Crawling & Attack Surface Mapping (Feature 7B)

- **Passive Crawler**: Automatically builds a sitemap from proxied traffic — every URL, form, and parameter is recorded without issuing additional requests.
- **Active Crawler**: Playwright-powered headless browser crawling that follows links, submits forms, and discovers JavaScript-rendered endpoints that static crawlers miss.
- **API Endpoint Detection**: Automatically classifies discovered URLs as REST API endpoints, GraphQL operations, WebSocket connections, or standard HTML pages.
- **Sitemap Tree View**: Visual hierarchical tree of discovered endpoints grouped by host, path depth, and content type. Click any node to send to Repeater, Scanner, or Intruder.
- **External URL Recording**: Tracks external URLs referenced by the target application for supply-chain and third-party risk analysis.

#### 🔬 Active Vulnerability Scanner (Feature 7C)

- **10 OWASP-Aligned Scan Modules** — individually toggleable:
  - **SQLi** — Time-based blind, error-based (DB fingerprint), boolean-based, UNION-based injection
  - **XSS** — Reflected (canary token), DOM sink hints, encoded bypass variants
  - **SSRF** — Cloud metadata probes (AWS/GCP/Azure), timing-based blind detection, OAST probe support
  - **XXE** — File read probes (Unix/Windows paths), XML parser delta detection, OAST callbacks
  - **Command Injection** — Output reflection, time-based, and OAST `curl` probes
  - **Path Traversal** — LFI via common file content patterns and response size delta
  - **CORS Misconfiguration** — Arbitrary origin, null origin, subdomain bypass, prefix bypass, `ACAO:*/ACAC:true` detection
  - **HTTP Security Headers** — Missing `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, version disclosure, insecure cookie flags
  - **Broken Authentication** — Rate-limit bypass (20-request replay), username enumeration, weak credential testing, JWT inspection
  - **Deserialization** — PHP object injection, Java serialization gadget headers, Python pickle patterns, ViewState analysis
- **Scan Targets**: URL (single target), Proxy History (bulk scan captured requests), or Sitemap (crawled endpoints)
- **Live Findings Table**: Severity-sorted (Critical → Info), expandable rows with description, evidence, remediation, and OWASP/CVE reference links
- **Network Badge Injection**: When a scanner finding URL matches a known network host, a `.web-vuln-badge` is injected onto the host card in the Network workspace
- **Export**: JSON, CSV, and styled HTML report

#### 🔁 Request Repeater (Feature 7D)

- **Raw HTTP Editor**: Full-featured raw request editor supporting manual modification of method, path, headers, and body before retransmission
- **HTTPS Support**: Sends requests directly via Node.js `http`/`https` modules — bypasses browser CORS entirely
- **Response Viewer**: Side-by-side raw request/response panes with timing (ms), status code, and response size
- **History Navigation**: Per-tab request history with forward/back navigation. Multiple independent Repeater tabs

#### ⚡ Intruder (Feature 7D)

- **Position Markers**: `§value§` syntax marks injection positions in raw request templates
- **Four Attack Types** (matching Burp Intruder):
  - **Sniper** — Iterates each position independently (list × positions requests)
  - **Battering Ram** — Same payload applied to all positions simultaneously
  - **Pitchfork** — Parallel payload lists, row-aligned
  - **Cluster Bomb** — Cartesian product of all payload lists across all positions
- **Payload Sources**: Manual list, built-in wordlists, custom file import, character fuzz sets
- **Results Table**: Status code, response length, duration, response delta — all filterable
- **Concurrency Control**: Configurable max concurrent requests (1–20)

#### 🎲 Token Sequencer (Feature 7D)

- **Statistical Randomness Analysis**: Capture token samples (session IDs, CSRF tokens, API keys) and analyze their entropy and predictability
- **Bit-level Analysis**: FIPS 140-2 monobit, poker, runs, and long-runs tests
- **Visualization**: Entropy charts and bit distribution histograms

#### 🔤 Encoder/Decoder (Feature 7D)

- **Multi-format encoding/decoding**: URL, HTML, Base64, Hex, ASCII, Unicode, GZIP
- **Hash generation**: MD5, SHA-1, SHA-256, SHA-512
- **Smart decode**: Auto-detects encoding scheme and applies decode chain

#### 🔀 Comparer (Feature 7D)

- **Side-by-side diff**: Compare two HTTP responses, request bodies, or arbitrary text
- **Word-level and byte-level diff modes**
- **Highlight changes**: Added, removed, and modified content highlighted with distinct colors

### 🔬 Security Monitoring & Hardening

- **Continuous Hardening Monitor**: Schedule recurring security snapshots of discovered hosts. Automatically diffs each new scan against the last known state and alerts on new open ports, changed banners, new CVEs, or SSL certificate changes. Delta view clearly shows added/removed findings.
- **Security Analyzer**: Aggregates all scan data — open ports, CVEs, OS fingerprint, banner strings — and produces a prioritized risk score with actionable hardening recommendations per host.

### 🌩️ Container & Cloud Enumeration

- **Docker Daemon Probing**: Detects exposed Docker daemons (`/var/run/docker.sock` via HTTP API, TCP 2375/2376) and queries container inventory, image list, and resource usage.
- **Kubernetes Probing**: Probes the Kubelet API (port 10250/10255) and the Kubernetes API Server (port 6443/8443) for unauthenticated access, listing pods, namespaces, and secrets.
- **etcd Exposure**: Detects unprotected etcd instances (port 2379) and attempts to read the key space, including potential Kubernetes secret material.
- **Cloud Metadata Service Detection**: Probes for exposed AWS IMDSv1 (`169.254.169.254`), GCP metadata, Azure IMDS, and DigitalOcean metadata endpoints — critical SSRF/misconfiguration indicators.
- **Consul & Vault Probing**: Detects Consul (port 8500) and HashiCorp Vault (port 8200) instances and checks for unauthenticated access to the key-value store and secrets engine.
- **Prometheus & Grafana Detection**: Identifies exposed Prometheus metrics endpoints and Grafana instances with default or no authentication.
- **Portainer Detection**: Identifies exposed Portainer container management UIs.
- **Critical Port Badges**: Host cards receive prominent ⚠ CRITICAL badges when container indicator ports (2375, 10250, 8443, 2379, etc.) are detected.
- **JSON Export**: Full finding set exportable as structured JSON.

### 🧳 General Management

- **Dashboard Filtering & Sorting**: Client-side search indexing allows seamless filtering by IP address, detected OS, hardware vendor, open ports, and CVE presence.
- **Data Persistence**: Offline session persistence saves all network scan states, deep scan vulnerabilities, banners, TLS traits, and SNMP data to a local JSON file. Reload sessions without rescanning.
- **Persistent Settings UI**: Unified modal to manage backend tool dependencies. Automatically detects Nmap, Tshark, Hydra, and Smbclient availability in your system PATH with visual status indicators.
- **Auto-Updates**: `electron-updater` integration checks for new releases on startup and prompts the user to download. Staged update channels (latest, beta) supported via GitHub Releases.

---

## 📦 Installation

### Windows

Download the latest `.exe` (NSIS installer) or `.exe` (portable) from the [Releases](https://github.com/robermar23/netspectre/releases) page and run it. No additional setup required.

> The NSIS installer creates Start Menu and Desktop shortcuts and allows custom install directory selection.

### macOS

Download the `.dmg` from the [Releases](https://github.com/robermar23/netspectre/releases) page, open it, and drag NetSpecter to your Applications folder.

> Universal binaries (x64 + arm64) are provided for Intel and Apple Silicon Macs.

### Linux (Recommended: `.deb`)

The **`.deb` package** is the recommended installation method for Debian/Ubuntu-based distributions. It automatically handles all system dependencies and provides full desktop integration.

```bash
# Download the latest .deb from Releases, then:
sudo dpkg -i netspectre_*.deb

# If there are missing dependencies, fix them with:
sudo apt-get install -f
```

RPM (`.rpm`) and portable (`.AppImage`) packages are also available for non-Debian distributions.

**Linux Note**: Raw socket operations (ICMP ping, deep port scanning) require either `sudo` or the `cap_net_raw` capability:

```bash
sudo setcap cap_net_raw+eip /usr/bin/netspectre
```

---

## 📖 Complete Documentation

For a comprehensive breakdown of how to use each feature, step-by-step UI walkthrough, and advanced Nmap exploitation techniques, read the [Getting Started Guide](docs/getting-started-guide.md).

---

## 🚀 Developer Onboarding

This project uses a split-process architecture standard for modern Electron applications, utilizing Vite as the frontend bundler for hyper-fast hot module replacement (HMR).

### Tech Stack

| Layer | Technology |
| --- | --- |
| **Container** | [Electron](https://www.electronjs.org/) v40 (Strict `contextIsolation` enabled) |
| **Frontend / Bundler** | [Vite](https://vitejs.dev/) v7 + Vanilla HTML/CSS/JS |
| **Backend / OS Bridge** | Node.js (`net`, `tls`, `http`, `https`, `child_process`, `os`) |
| **Persistence** | `electron-store` (settings), `better-sqlite3` (proxy history), JSON (scan sessions) |
| **TLS / Crypto** | `node-forge` (MITM proxy CA + leaf cert generation) |
| **Network Scanning** | `ping`, raw TCP sockets, `net-snmp`, `fast-xml-parser` (Nmap XML) |
| **Visualization** | [Cytoscape.js](https://js.cytoscape.org/) (topology graph) |
| **Browser Automation** | `playwright-core` (active crawler) |
| **Testing** | [Vitest](https://vitest.dev/) v4 + `@vitest/coverage-v8`, `jsdom` |
| **Packaging** | `electron-builder` v24 (DMG, NSIS, DEB, RPM, AppImage) |

### Prerequisites

Ensure you have the following installed:

- **Node.js** v18 or higher (v20 LTS recommended)
- **npm** v9+ or **yarn**
- **Python** v3.x (required by `node-gyp` for `better-sqlite3` native compilation)
- Your OS's native `ping` utility (pre-installed on all platforms)

**Optional external tools** (detected automatically at runtime):

- [Nmap](https://nmap.org/) — advanced port scanning and CVE detection
- [Wireshark / tshark](https://www.wireshark.org/) — passive packet capture
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) — multi-protocol brute-force
- [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) — SMB share enumeration
- [Metasploit Framework](https://www.metasploit.com/) — exploit framework (MSFRPC)

### 1. Clone & Install

```bash
git clone https://github.com/robermar23/NetSpecter.git
cd NetSpecter
npm install
```

> `npm install` automatically runs `electron-rebuild` as a `postinstall` hook to recompile `better-sqlite3` for the installed Electron version. Ensure Python and a C++ compiler are available.

### 2. Local Development

Start the application in development mode with Hot Module Replacement:

```bash
npm run dev
```

This concurrently:

1. Builds the preload script with `esbuild` (CommonJS format, `--external:electron`)
2. Starts the Vite dev server on port 5173
3. Launches Electron pointing at `http://localhost:5173`

Changes to renderer code hot-reload instantly. Changes to main process or preload files require an Electron restart.

### 3. Production Build

Bundle the renderer with Vite and prepare for packaging:

```bash
npm run build
```

### 4. Package & Distribute

Build platform-specific installers:

```bash
npm run dist
```

Output artifacts are placed in `release/<version>/`. Platform-specific targets:

- **macOS**: `.dmg` (x64 + arm64) + `.zip`
- **Windows**: `.exe` (NSIS installer) + portable `.exe`
- **Linux**: `.deb` + `.rpm` + `.AppImage`

### Project Structure

```text
NetSpecter/
├── src/
│   ├── main/                    # Main process (Node.js, privileged)
│   │   ├── main.js              # App lifecycle (~143 lines)
│   │   ├── preload.js           # contextBridge IPC bindings
│   │   ├── store.js             # electron-store schema + dependency paths
│   │   ├── logger.js            # Structured logger (warn/error in prod)
│   │   ├── windowManager.js     # Window creation + bounds persistence
│   │   ├── ipc/                 # IPC handler modules
│   │   │   ├── scanIpc.js       # Network scan IPC handlers
│   │   │   ├── settingsIpc.js   # Settings IPC handlers
│   │   │   ├── fileIpc.js       # File I/O IPC handlers
│   │   │   ├── utilIpc.js       # Utility IPC handlers
│   │   │   └── passiveIpc.js    # Passive capture IPC handlers
│   │   ├── webapp/              # Web app testing subsystem
│   │   │   ├── proxyServer.js   # MITM HTTPS proxy (node-forge)
│   │   │   ├── requestStore.js  # SQLite request history (better-sqlite3)
│   │   │   ├── crawler.js       # Passive sitemap crawler
│   │   │   ├── activeCrawler.js # Playwright active crawler
│   │   │   ├── apiDetector.js   # REST/GraphQL/WS classification
│   │   │   ├── repeaterEngine.js # Raw HTTP request relay
│   │   │   ├── intruderEngine.js # Fuzzer (Sniper/BatRam/Pitchfork/ClusterBomb)
│   │   │   ├── sequencerEngine.js # Token entropy analysis
│   │   │   ├── scanner/         # Vulnerability scanner modules (11 files)
│   │   │   └── ipc/webappIpc.js # Web app IPC handler registration
│   │   ├── nmapScanner.js       # Nmap CLI orchestration + XML parsing
│   │   ├── deepScanner.js       # Raw TCP 65535-port scanner
│   │   ├── tsharkScanner.js     # tshark CLI wrapper
│   │   ├── passiveCapture.js    # Packet capture coordinator
│   │   ├── bruteForce.js        # Hydra orchestration
│   │   ├── metasploitRpc.js     # MSFRPC client
│   │   ├── revShellListener.js  # Reverse shell TCP listener
│   │   ├── shareEnumerator.js   # SMB/NFS share enumeration
│   │   ├── dirFuzzer.js         # Web directory fuzzer
│   │   ├── hardeningMonitor.js  # Continuous security monitoring
│   │   ├── credSpray.js         # Default credential spray
│   │   ├── cloudEnum.js         # Container/cloud endpoint probing
│   │   └── securityAnalyzer.js  # Risk scoring and recommendations
│   ├── renderer/                # Renderer process (unprivileged UI)
│   │   ├── index.html           # Main markup (all panels, modals)
│   │   ├── index.js             # Slim orchestrator (~92 lines)
│   │   ├── api.js               # IPC wrapper (mirrors preload API)
│   │   ├── state.js             # Shared renderer state object
│   │   ├── ui.js                # Panel/modal utility functions
│   │   ├── topology.js          # Cytoscape.js topology graph
│   │   ├── style.css            # Glassmorphic dark theme
│   │   ├── webapp.css           # Web app workspace styling
│   │   └── modules/             # Feature module files
│   │       ├── init.js          # Startup dependency checks
│   │       ├── scanControls.js  # Network scan UI controls
│   │       ├── hostDetails.js   # Host detail panel + port actions
│   │       ├── deepScan.js      # Deep scan UI
│   │       ├── passiveIntel.js  # Passive capture module UI
│   │       ├── pcap.js          # PCAP export panel
│   │       ├── bruteForce.js    # Brute-force modal UI
│   │       ├── metasploit.js    # Metasploit modal UI
│   │       ├── revShell.js      # Reverse shell panel UI
│   │       ├── shareEnum.js     # Share explorer panel UI
│   │       ├── dirFuzz.js       # Dir fuzzer panel UI
│   │       ├── hardeningMonitor.js # Hardening monitor UI
│   │       ├── credSpray.js     # Credential spray UI
│   │       ├── cloudEnum.js     # Cloud enum panel UI
│   │       ├── settings.js      # Settings modal UI
│   │       └── webapp/          # Web app workspace modules
│   │           ├── index.js     # Tab manager / workspace router
│   │           ├── proxy.js     # Proxy history UI
│   │           ├── sitemap.js   # Crawl sitemap tree
│   │           ├── repeater.js  # Request repeater UI
│   │           ├── intruder.js  # Intruder fuzzer UI
│   │           ├── sequencer.js # Token sequencer UI
│   │           ├── decoder.js   # Encoder/decoder UI
│   │           ├── comparer.js  # Response diff UI
│   │           └── scanner.js   # Vulnerability scanner UI
│   └── shared/                  # Shared across all processes
│       ├── ipc.js               # All IPC channel constants (source of truth)
│       ├── networkConstants.js  # IP regexes, port sets, vendor map, payloads
│       ├── validate.js          # isValidIpOrHostname, isValidHttpUrl, isPathWithinRoot
│       └── webConstants.js      # Web app workspace constants
├── test/                        # Vitest test files
│   ├── *.test.js                # Main process unit tests (30 files)
│   ├── renderer/                # Renderer module tests (8 files)
│   └── webapp/                  # Web app subsystem tests (7 files)
├── resources/
│   ├── wordlists/               # Built-in wordlists
│   │   ├── basicauth.txt        # Basic auth credential pairs
│   │   ├── usernames.txt        # Username list for spray attacks
│   │   ├── passwords.txt        # Password list for spray attacks
│   │   ├── sqli-payloads.txt    # SQLi test payloads
│   │   └── xss-payloads.txt     # XSS test payloads
│   └── dashboard-preview.png
└── docs/                        # Developer documentation
    ├── getting-started-guide.md
    ├── FEATURE_4.md             # Offensive pentest feature plan
    ├── FEATURE_5.md             # Security monitoring feature plan
    ├── FEATURE_7.md             # Web app testing feature plan
    └── CHANGELOG.md
```

### IPC Architecture

All IPC channel names are defined as string constants in [`src/shared/ipc.js`](src/shared/ipc.js) — this is the single source of truth. Never use inline string channel names.

The IPC flow follows this pattern:

```text
Renderer (api.js)
  └── window.electronAPI.<method>()    ← defined by contextBridge in preload.js
        └── ipcRenderer.invoke(CHANNEL, payload)
              └── ipcMain.handle(CHANNEL, handler)  ← registered in feature module
                    └── feature module logic
                          └── mainWindow.webContents.send(EVENT, data)  ← push results
                                └── ipcRenderer.on(EVENT, callback)  ← renderer listener
```

**Adding a new IPC feature:**

1. Add channel constants to `src/shared/ipc.js`
2. Create a feature module in `src/main/` exporting `registerIpcHandlers(ipcMain, getWindow)`
3. Register it in `src/main/main.js`
4. Expose bindings in `src/main/preload.js` via `contextBridge`
5. Add the renderer-side wrapper in `src/renderer/api.js`

### Security Model

- `nodeIntegration: false` and `contextIsolation: true` — enforced on all `BrowserWindow` instances. No exceptions.
- All Node.js APIs are exposed to the renderer **only** via the preload `contextBridge`. Direct Node access from renderer is impossible by design.
- All `child_process.spawn()` calls use **argument arrays**, never shell string concatenation — preventing command injection.
- All IPC inputs are validated in the main process. IP addresses validated with `ipRegex`; URLs validated with `isValidHttpUrl()`; file paths checked with `isPathWithinRoot()`.
- Credentials are held **memory-only** for the session duration and are never logged or persisted to disk.

---

## 🧪 Testing

NetSpecter uses [Vitest](https://vitest.dev/) v4 for all test suites. Tests are organized across three directories:

```text
test/                    # Main process unit tests
test/renderer/           # Renderer module unit tests (jsdom environment)
test/webapp/             # Web app subsystem unit tests
```

### Running Tests

```bash
# Run all tests once
npm test

# Run tests in watch mode (development)
npx vitest

# Run tests with coverage report
npx vitest run --coverage
```

Coverage output is generated in `coverage/` using `@vitest/coverage-v8`. The target is **~80% coverage** across main process and renderer modules.

### Test Conventions

- **No real network calls** — all `child_process.spawn`, `http.request`, and socket operations are mocked
- **No real file system** — `fs` module is mocked where file I/O is not the subject under test
- **Mock `electron`** — Electron APIs (`dialog`, `shell`, `app`, `ipcMain`) are mocked via `vi.mock('electron')`
- Use `vi.resetAllMocks()` in `afterEach` (not `vi.clearAllMocks()`) when `mockImplementationOnce` queues are involved
- `better-sqlite3` mock: use `function MockDatabase()` (not arrow function) so `new Database()` works correctly
- `fs` mock with default import: return `{ ...mockFs, default: mockFs }` from the mock factory
- `vi.mock` factory cannot reference top-level `const` — inline values or use `vi.hoisted()` to declare them first
- SQLite tests: call `closeRequestStore()` in `afterEach` so `initRequestStore()` re-runs schema setup on the next test

### Test Coverage by Area

| Area | Test Files | Description |
| --- | --- | --- |
| Network Scanning | `nmapScanner`, `nmapXmlParser`, `scanner`, `deepScanner` | Nmap orchestration, XML parsing, raw port scanning |
| Passive Intelligence | `tsharkScanner`, `passiveCapture`, `dnsHarvester`, `credentialSniffer`, `arpSpoofDetector`, `rogueDhcpDetector`, `rogueDnsDetector` | All tshark-based passive modules |
| PCAP | `pcapAnalyzer`, `pcapExporter` | Capture and export |
| SNMP | `snmpWalker` | MIB walking and OID parsing |
| Offensive Tools | `bruteForce`, `metasploitRpc`, `revShellListener`, `dirFuzzer`, `credSpray`, `credSprayTransports` | All pentest modules |
| Security Monitoring | `hardeningMonitor`, `securityAnalyzer`, `cloudEnum` | Monitoring and cloud enum |
| App Core | `store`, `main`, `windowManager`, `networkConstants`, `topology` | Core infrastructure |
| Renderer | `renderer/bruteForce`, `renderer/cloudEnum`, `renderer/credSpray`, `renderer/dirFuzz`, `renderer/hardeningMonitor`, `renderer/revshellUI`, `renderer/settings`, `renderer/shareEnum` | UI module unit tests |
| Web App | `webapp/requestStore`, `webapp/proxyServer`, `webapp/crawler`, `webapp/activeCrawler`, `webapp/apiDetector`, `webapp/intruderEngine`, `webapp/sequencerEngine` | Full web app subsystem |

---

## 🏗️ Architecture Overview

NetSpecter follows Electron's strict security model with three isolated process contexts:

```text
┌─────────────────────────────────────────────────────────────────┐
│  Renderer Process (unprivileged — Chromium sandbox)             │
│                                                                 │
│  index.html ← style.css + webapp.css                           │
│  index.js (orchestrator) → modules/ (14 feature modules)       │
│  webapp/    (9 web-app modules)                                 │
│  state.js   (shared in-memory state)                            │
│  api.js     (window.electronAPI wrapper)                        │
└────────────────┬────────────────────────────────────────────────┘
                 │  contextBridge (preload.js)
                 │  window.electronAPI.*
                 │  ipcRenderer.invoke / ipcRenderer.on
┌────────────────▼────────────────────────────────────────────────┐
│  Main Process (privileged — full Node.js)                       │
│                                                                 │
│  main.js → windowManager → registerIpcHandlers (all modules)   │
│  ipc/      (scan, settings, file, util, passive handlers)       │
│  webapp/   (proxy, store, crawler, scanner, repeater, intruder) │
│  Feature modules: nmapScanner, deepScanner, bruteForce,        │
│                   metasploitRpc, revShellListener, dirFuzzer,   │
│                   hardeningMonitor, credSpray, cloudEnum, ...   │
└─────────────────────────────────────────────────────────────────┘
                 │  src/shared/
                 │  ipc.js (channel constants)
                 │  networkConstants.js (IP, ports, payloads)
                 │  validate.js (input validation)
                 └  webConstants.js (web app constants)
```

### Key Design Decisions

- **Modular IPC**: Each feature registers its own IPC handlers via `registerIpcHandlers(ipcMain, getWindow)`. This keeps `main.js` at ~143 lines (app lifecycle only).
- **Streaming Results**: Long-running operations (scans, captures, fuzzing) stream incremental results via `mainWindow.webContents.send()` rather than waiting for completion.
- **No Framework**: The renderer uses Vanilla JS with zero framework dependencies. Feature modules export `init()` functions; cross-module refs are passed as parameters.
- **Single State Object**: `state.js` holds all renderer-side in-memory state. This prevents prop-drilling while avoiding a reactive framework.
- **Semaphore Concurrency**: Concurrent operations (dir fuzz, intruder, scanner) use a semaphore pattern to enforce max concurrency without thread pools.

---

## License

This project is open-sourced software licensed under the [MIT license](LICENSE).

### Third-Party Software Disclosures

- **Nmap**: This application can optionally interact with [Nmap](https://nmap.org) if independently installed. NetSpecter acts as a graphical front-end.
- **Wireshark/Tshark**: NetSpecter can optionally utilize `tshark` (part of [Wireshark](https://www.wireshark.org/)) for passive VLAN tag discovery and packet capture.
- **Hydra**: NetSpecter integrates [Hydra](https://github.com/vanhauser-thc/thc-hydra) for multi-protocol brute-forcing.
- **Metasploit**: NetSpecter can optionally connect to [Metasploit Framework](https://www.metasploit.com/) via MSFRPC for advanced exploitation workflows.
- **net-snmp & Cytoscape**: NetSpecter bundles [net-snmp](https://www.npmjs.com/package/net-snmp) for JavaScript SNMP communication and [cytoscape](https://js.cytoscape.org/) for graph visualization.
- **node-forge**: Used internally for on-the-fly TLS certificate generation in the intercepting proxy.
- **better-sqlite3**: Used for local-only proxy request history storage.
- **Playwright**: Used for headless browser-based active web crawling.
