# NetSpecter: Getting Started Guide

Welcome to NetSpecter! This guide will walk you through installing the application, its core features, and how to harness the advanced capabilities of the integrated Nmap orchestration engine.

## 0. Installation

### Windows
Download the `.exe` installer from the [Releases page](https://github.com/robermar23/netspectre/releases) and double-click to install.

### macOS
Download the `.dmg`, open it, and drag NetSpecter into your **Applications** folder.

### Linux
**Recommended:** Download the `.deb` package and install:
```bash
sudo dpkg -i netspectre_*.deb
sudo apt-get install -f   # resolve any missing dependencies
```

**Fedora/RHEL:** Download the `.rpm` package:
```bash
sudo dnf install ./netspectre-*.rpm
```

**AppImage (advanced):** Requires `libfuse2` (`sudo apt install libfuse2`). Run as a normal user — **do not use `sudo`**. If you must run as root, pass `--no-sandbox`:
```bash
chmod +x Netspectre-*.AppImage
./Netspectre-*.AppImage --no-sandbox
```

> **💡 Tip:** NetSpecter detects if you are running as root on Linux and automatically applies the `--no-sandbox` flag internally. For the `.deb` and `.rpm` packages, this is handled seamlessly.

### Optional: Offensive Tools (Hydra, Metasploit, etc.)
To leverage NetSpecter's red-team capabilities, we recommend installing the following:

**Hydra Installation (Multi-protocol Brute-Force):**
```bash
# Debian/Ubuntu
sudo apt install hydra

# macOS (Homebrew)
brew install hydra

# Windows — download THC-Hydra from GitHub and add to PATH.
```

**Metasploit Framework (Exploitation Engine):**
Follow the official [Metasploit Installation Guide](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html). After installation, ensure `msfrpcd` is accessible.

**SMB/NFS Clients:**
```bash
# Debian/Ubuntu
sudo apt install smbclient nfs-common

# macOS (Homebrew)
brew install samba
```

**Windows SMB Support (Impacket):**
Windows natively caches SMB connections, which breaks credential testing and enumeration workflows. Instead of native Windows SMB, NetSpecter relies on Impacket (`impacket-smbclient`) for Windows users.
1. Install [Python 3](https://www.python.org/downloads/windows/).
2. Open PowerShell or Command Prompt and run:
   ```cmd
   pip install impacket
   ```
3. Open NetSpecter **Settings** and ensure the `smbclient` path automatically detects `impacket-smbclient.exe` (usually located in your Python `Scripts` folder).

## 1. Target Acquisition and Scope

NetSpecter uses a **Target Scope** model, where you define exactly which hosts you are authorized to test before they appear on your dashboard. Click the **＋ Add Hosts** button to open the acquisition modal.

### The Add Hosts Modal
The modal is divided into four powerful ingestion methods:

1. **🔍 Discover**: 
   - Select a network interface (e.g., `eth0`, `Wi-Fi`) and click **Scan Network**.
   - NetSpecter performs a lightweight ICMP/ARP sweep of the `/24` subnet.
   - Discovered hosts are added to the **Staging List** below.

2. **✏️ Manual**: 
   - Manually enter an **IP Address**, **Hostname**, or **MAC Address**.
   - **CIDR Expansion**: You can enter a range like `192.168.1.0/24`. NetSpecter will automatically expand this into 254 individual target entries in your staging list.

3. **📄 Import File**: 
   - Load a `.txt` or `.csv` file containing target identifiers (IPs, CIDRs, or hostnames), one per line.
   - Ideal for large-scale enterprise audits with predefined scopes.

4. **📥 Import Nmap XML**: 
   - Restore a previous session by importing an Nmap XML output file (`-oX`). This loads hosts along with any previously discovered ports, OS versions, and service metadata.

### The Staging Workflow
Before hosts are added to your live dashboard, they sit in the **Staging List**. This allow you to:
- **Review**: See exactly what you are about to add.
- **Deduplicate**: NetSpecter automatically prevents duplicate IP entries.
- **Filter**: Click the **✕** next to any staged host to remove it from the scope before committing.

Once satisfied, click **✅ Add to Dashboard**. 

> [!NOTE]
> **Background Probing**: When you manually add or import hosts, NetSpecter automatically triggers a background "enrichment probe" to check if the host is alive and pull basic metadata (MAC/Vendor) without requiring a full Deep Scan.

## 2. Out-of-Scope Blacklist 🛡️

Use the **Blacklist** button in the top toolbar to define a global exclusion list. 

- Add specific IPs, MAC addresses, or CIDR ranges.
- **Critical Safety**: Blacklisted hosts are **hidden** from the dashboard and **strictly ignored** by all active scanning engines (Native, Nmap, and Pentest Suite).
- If a discovery scan finds a blacklisted host, it is discarded immediately.

## 3. Navigating the Dashboard

Once the scan completes, a grid of "Host Cards" will populate containing newly discovered IPs on your network.

* **Status Indicators**: A pulsing green circle means the host replied successfully.
* **Metadata Extraction**: Your native devices often identify themselves via MAC Address. NetSpecter intercepts these MAC addresses and automatically fetches their hardware vendor registration (e.g. `Sony`, `Apple`).
* **View Modes**: At the top right, use the view toggles to seamlessly switch between **Grid Card View**, **Slim List View**, or the **Detailed Table View**.
* **Filtering and Sorting**: Use the search inputs above the hosts list to filter by IP, OS, or Vendor. Sort the discovered hosts by `IP` (default), `Vendor`, `OS`, or `Open Ports`.

## 4. Deep Sweeping and Native Discovery

If you see an interesting host, click its Host Card to open the **Details Lateral Panel**.

1. Click **Run Deep Scan**. 
2. NetSpecter will begin raw socket probing across all 65,535 TCP ports on that specific device.
3. Open ports will pop into the details pane dynamically.
4. If HTTP (80/443), SSH, or other recognizable banner services are found, the UI will attempt active payload grabs, extracting Software Versions, HTML Titles, and SSL/TLS Certificates.
5. **Action Shortcuts**: Any exposed standard services (HTTP, SSH, RDP) can be instantly triggered by clicking the native "Connect" buttons next to the respective ports in the Details pane.
6. **Deep Scan All**: You can proactively run a Deep Scan on all discovered targets by clicking the **"☢️ Deep Scan All"** button near the search filters! You can stop the bulk scan instantly via the same button.

## 5. Advanced: The Nmap Orchestration Engine

While NetSpecter's native engine is blazingly fast, network auditors might want greater depth. We have engineered a zero-modification native wrapper around **Nmap**.

### Installing Nmap
If Nmap is not installed in your system `$PATH` (or explicitly via standard defaults), a blue banner will appear instructing you to download it natively from `nmap.org`. NetSpecter natively attempts dynamic `$PATH` detection (`where nmap` / `which nmap`) to automatically discover custom installation prefixes.

### Leveraging Nmap
Once Nmap is installed, open the Details Panel for any Host. You'll see an "Engine" toggle button. Switch it to **Nmap**. 

You now have access to four hyper-advanced features:

1. **Nmap Deep Scan (All Ports)**: Aggressively checks all 65,535 ports using `-A` timing and fingerprinting options. 
2. **Nmap Standard Host Scan**: Scans the default 1000 top ports quickly using `-A` aggressive OS detection flags.
3. **Targeted Port Analysis**: Hover over any previously discovered Open Port blue tag in the UI and click it. NetSpecter spins up a targeted Nmap Service Scan (`-sV -sC`) directly against that specific listening socket to scrape exactly what process is running behind it.
4. **Nmap Vuln Scan (Scripts)**: Executes the aggressive `--script vuln` map against the host. 

## 6. Vulnerability Discovery (CVE Mapping)

When using the **Nmap Vuln Scan**, NetSpecter intercepts the raw terminal output buffer directly.

* It searches for `VULNERABILITY:` blocks. 
* It extracts the `CVE ID`, the `CVSS severity score` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and dynamically links directly to `vulners.com` or `exploit-db.com` if exploit PoCs are publicly available.
* All discovered vulnerabilities are cleanly mapped to a red "Vulnerabilities Discovered" list inside the Details panel. 
* The primary Dashboard Host Card security badge handles state propagation, flipping to a blazing red flag quantifying exactly how many Critical CVEs are bound to the specific host. If no vulnerabilities are found, it receives a glowing green `Audited Secure` badge.

## 7. Nmap Scripting Engine (NSE) Explorer

At the bottom of the Nmap actions list is the powerful **NSE Explorer Dropdown**.

When NetSpecter starts, it hunts your file system to discover your native Nmap installation footprint. It ingests all 600+ `.nse` lua scripts and categorizes them.

* Search for any script (e.g. `smb-`, `http-`) inside the input terminal.
* A dropdown will perfectly categorize them using dynamic color risk-badges (`safe` (Green), `discovery` (Blue), `intrusive/dos` (Yellow), `vuln/exploit` (Red)) so you know exactly how dangerous a payload is before sending it.
* You can append optional script arguments (e.g. `--script-args user=admin`) into the secondary box. 
* Click "Run Custom Script" and the execution outputs natively into the dashboard terminal blocks.

## 8. Interactive Ncat Sockets

Behind the Nmap Engine toggle is the localized **Ncat** Engine. This allows for raw TCP/UDP socket connectivity directly from the GUI.

1. Switch to the **Ncat** engine tab inside the Details panel.
2. Enter the target `Port`.
3. Fill out the `Payload` field (e.g. `GET / HTTP/1.0\r\n\r\n` or raw byte drops).
4. Click Connect & Send. The UI will keep the stream open to visualize bidirectional byte-drops mimicking raw native network connectivity.

## 9. VLAN Tag Discovery (Tshark)

NetSpecter natively integrates with Wireshark's CLI tool (`tshark`) to passively hunt for 802.1Q tags on your network interfaces, useful for uncovering misconfigured Trunk ports or preventing VLAN Hopping attacks.

1. Ensure Tshark is installed and enabled in the **Settings** modal.
2. Click the **🦈 VLAN Discovery** button located in the top control bar (next to the view toggles) to open the VLAN panel.
3. Choose the physical interface you want to listen on.
4. Click **Start Capture**. NetSpecter will transparently orchestrate a Wireshark capture filtered strictly to `vlan` packets.
5. As tagged frames are intercepted traversing the wire, the UI will extract the `VLAN ID` and the source/destination MAC addresses, appending them securely to the streaming dashboard widget in real-time.

## 10. Passive Network Intelligence (Tshark)

NetSpecter also features a powerful **Passive Intelligence** suite backed by Tshark. This allows you to silently monitor the network for configuration issues, security threats, and hidden hosts.

1. Click the **🕵️ Passive Intelligence** button in the top toolbar to open the panel.
2. Select your listening interface from the dropdown.
3. Toggle any of the four available modules:
   * **DHCP Rogue Detection**: Alerts you immediately if an unknown or spoofed DHCP server starts offering IP addresses on your subnet.
   * **Credential Sniffer**: Silently extracts cleartext passwords from insecure protocols like FTP, Telnet, HTTP Basic Auth, POP3, and IMAP. *(Note: You must explicitly accept a legal disclaimer before activating this module).*
   * **DNS Harvester**: Monitors DNS and mDNS queries passively. Any newly discovered hosts are seamlessly promoted to your main NetSpecter dashboard without sending a single active probe.
   * **ARP Spoofing Detection**: Monitors ARP replies to instantly detect Man-in-the-Middle (MitM) ARP poisoning attacks and gratuitous ARP announcements.
4. **PCAP Export**: Need raw packet data? Click the **📥 Export PCAP...** button to spawn a targeted packet capture saved directly to your hard drive, ready for Wireshark analysis.

## 11. SNMP Device Walking

NetSpecter supports SNMPv1, v2c, and v3 walking to extract detailed operational metrics from routers, switches, and local servers.

1. Ensure the target host is running an SNMP agent (e.g., `snmpd`).
2. Click on the host in the main dashboard to open the **Details Panel**.
3. Under the "Actions" section, click **SNMP Walk**.
4. Configure the SNMP Version and Community String (for v1/v2c) or Security/Auth parameters (for v3).
5. Click **Start Walk**. NetSpecter will concurrently pull Interface Statistics, System Descriptions, Routing Tables, and ARP caches.

## 12. Network Topology Map

Transform your flat host grid into an interactive visual graph to understand network topology at a glance.

1. Discover hosts on your subnet using the standard native scan.
2. In the top navigation bar, click the **📡 Topology** tab.
3. Your network will be automatically rendered using Cytoscape.js. Subnets are clustered, and hosts are linked to their respective detected gateways.
4. Interact with the graph: Click nodes to open their Host Details, use the toolbar to switch layouts (Force-directed, Hierarchical), or export the graph via the **Camera** icon.

## 13. Live Packet Capture & Analysis

Need deeper forensic visibility into a specific machine? NetSpecter integrates live `tshark` capture capabilities directly into the UI.

1. Navigate to the **Passive Intelligence** panel, or right-click any host in the grid and select **Capture Packets**.
2. Set a Capture Filter (e.g. `host 192.168.1.5` or `tcp port 80`) and Duration.
3. Click **Start Capture**.
4. The panel will stream packets in real-time. The **Stats Dashboard** instantly categorizes protocol distributions (TCP, UDP, ICMP), identifies Top Talkers, and alerts you to any Cleartext Protocols (like HTTP or FTP) detected on the wire.

## 14. Rogue DNS Detection

Similar to Rogue DHCP, the Rogue DNS module passively hunts for unauthorized name servers or DNS spoofing.

1. Open the **🕵️ Passive Intelligence** panel.
2. Toggle on the **🌐 Rogue DNS** module.
3. NetSpecter will establish a baseline of trusted DNS responders. If an unexpected server responds, or if conflicting A records are offered within a short window, a high-severity alert card is injected into the dashboard natively.

## 15. Offensive Pentest Suite (NEW)
NetSpecter now includes a powerful suite of offensive tools designed for authorized penetration testing and red-teaming. These tools are accessible via the **⚔️ Pentest** tab or the host context menu.

> [!CAUTION]
> These tools perform active offensive operations. Only use them on networks and systems you are explicitly authorized to test.

### 16. Multi-Protocol Brute-Force (Hydra)
Automate credential discovery across multiple services using the integrated THC-Hydra engine.

1. Right-click a target host and select **Pentest** → **Brute-Force Attack...**
2. **Select Protocol**: Choose from SSH, FTP, Telnet, HTTP, SMB, RDP, and more.
3. **Configure Settings**:
   * **Username**: Enter a single username or toggle "Load User List" to pick a `.txt` file.
   * **Wordlist**: Select your custom password wordlist via the native file browser.
   * **Threads/Delay**: Adjust the concurrency (default 4) and timing to avoid service lockouts.
4. **Start Attack**: Click **Start Brute-Force**. Credential hits will appear in real-time in the results table.

### 17. Metasploit RPC Control Plane
Orchestrate the Metasploit Framework directly from NetSpecter. This requires a running `msfrpcd` daemon.

1. **Start Metasploit RPC**: Open a terminal and run `msfrpcd -P <password> -S -f`.
2. **Connect**: In NetSpecter, go to the **Pentest** tab → **Metasploit Manager**. Enter your RPC credentials and click **Connect**.
3. **Exploit Search**: Use the searchable module database to find relevant exploits.
4. **Launch & Manage**: Configure exploit options (Target, RPORT, Payload) and click **Run**. Successful exploits will populate the **Active Sessions** list, where you can interact with shells or kill sessions.

### 18. Interactive Reverse Shell Hub
A dedicated listener for incoming reverse shell connections with built-in payload generation.

1. Go to the **Pentest** tab → **Reverse Shell Listener**.
2. **Generate Payload**: Select your target shell (Bash, Python, PowerShell, PHP, or Netcat). The UI automatically populates your local IP (`LHOST`) and a default port (`4444`).
3. **Copy & Execute**: Click **Copy to Clipboard** and execute the payload on your target machine.
4. **Listen**: Click **Start Listener**. When a connection is received, a terminal session will open directly in the dashboard, allowing for live interaction.

### 19. SMB/NFS Share Explorer
Expose misconfigured network shares and sensitive file storage.

1. Right-click a host → **Pentest** → **Enumerate Shares**.
2. NetSpecter will attempt null sessions and credentialed checks for SMB and NFS exports.
3. **Browse Files**: If shares are found, they will appear in the explorer. Click a share to browse its directory structure.
4. **Download**: Right-click any file to download it to your local machine for analysis.

### 20. Web Directory Fuzzer
Discover hidden files and directories on web servers.

1. Right-click a host → **Pentest** → **Fuzz Web Directories**.
2. **Configure Wordlist**: Use the built-in "Common Paths" list or load your own large-scale wordlist.
3. **Filters**: Specify which status codes to report (e.g., 200, 301, 302, 403).
4. **Start Fuzzing**: NetSpecter will execute parallel HTTP requests, streaming hits (like `/.git/config` or `/admin/`) back to the UI results table.

## 21. Persisting Data (Saving and Loading)

Any Nmap Scans, Pentest results, and Native Port Banners queried in the current application state session are saved in the DOM.

* Click **Save Results** in the top control bar to serialize the exact state to `scan_results.json` locally.
* You can safely close the application, open it, and click **Load Results** to re-instantiate your layout perfectly, saving hours of rescanning downtime.
