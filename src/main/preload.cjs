// src/main/preload.js
var import_electron = require("electron");

// src/shared/ipc.js
var IPC_CHANNELS = {
  // Main Handlers (renderer -> main)
  GET_INTERFACES: "get-interfaces",
  SCAN_NETWORK: "scan-network",
  STOP_SCAN: "stop-scan",
  SAVE_RESULTS: "save-results",
  LOAD_RESULTS: "load-results",
  CLEAR_RESULTS: "clear-results",
  EXIT_APP: "exit-app",
  RUN_DEEP_SCAN: "deep-scan-host",
  CANCEL_DEEP_SCAN: "cancel-deep-scan",
  OPEN_EXTERNAL_ACTION: "open-external-action",
  OPEN_URL: "open-url",
  // open a full URL in the system browser
  // Renderer Listeners (main -> renderer)
  HOST_FOUND: "host-found",
  SCAN_COMPLETE: "scan-complete",
  SCAN_ERROR: "scan-error",
  DEEP_SCAN_RESULT: "deep-scan-result",
  DEEP_SCAN_PROGRESS: "deep-scan-progress",
  DEEP_SCAN_COMPLETE: "deep-scan-complete",
  // SNMP Walking
  SNMP_WALK: "snmp-walk",
  SNMP_GET: "snmp-get",
  CANCEL_SNMP_WALK: "cancel-snmp-walk",
  SNMP_WALK_RESULT: "snmp-walk-result",
  SNMP_WALK_PROGRESS: "snmp-walk-progress",
  SNMP_WALK_COMPLETE: "snmp-walk-complete",
  SNMP_WALK_ERROR: "snmp-walk-error",
  SNMP_INTEL: "snmp-intel",
  // Nmap Channels
  CHECK_NMAP: "check-nmap",
  RUN_NMAP_SCAN: "run-nmap-scan",
  CANCEL_NMAP_SCAN: "cancel-nmap-scan",
  GET_NMAP_SCRIPTS: "get-nmap-scripts",
  RUN_NCAT: "run-ncat",
  NMAP_SCAN_RESULT: "nmap-scan-result",
  NMAP_SCAN_COMPLETE: "nmap-scan-complete",
  NMAP_SCAN_ERROR: "nmap-scan-error",
  // Target Scope Management
  IMPORT_SCOPE_FILE: "import-scope-file",
  IMPORT_NMAP_XML: "import-nmap-xml",
  PING_HOST: "ping-host",
  PROBE_HOST: "probe-host",
  // Settings Management
  GET_SETTING: "get-setting",
  SET_SETTING: "set-setting",
  GET_ALL_SETTINGS: "get-all-settings",
  CHECK_DEPENDENCY: "check-dependency",
  // Tshark (VLAN Discovery)
  START_TSHARK: "start-tshark",
  STOP_TSHARK: "stop-tshark",
  TSHARK_VLAN_FOUND: "tshark-vlan-found",
  TSHARK_ERROR: "tshark-error",
  TSHARK_COMPLETE: "tshark-complete",
  // Passive Network Intelligence
  START_PASSIVE_CAPTURE: "start-passive-capture",
  STOP_PASSIVE_CAPTURE: "stop-passive-capture",
  STOP_ALL_PASSIVE: "stop-all-passive",
  // Rogue DHCP Detection
  PASSIVE_DHCP_ALERT: "passive-dhcp-alert",
  PASSIVE_DHCP_ERROR: "passive-dhcp-error",
  // Cleartext Credential Sniffing
  PASSIVE_CRED_FOUND: "passive-cred-found",
  PASSIVE_CRED_ERROR: "passive-cred-error",
  // DNS Query Harvesting
  PASSIVE_DNS_HOST: "passive-dns-host",
  PASSIVE_DNS_ERROR: "passive-dns-error",
  // Live PCAP Export
  EXPORT_PCAP: "export-pcap",
  PCAP_EXPORT_COMPLETE: "pcap-export-complete",
  PCAP_EXPORT_ERROR: "pcap-export-error",
  // ARP Spoofing Detection
  PASSIVE_ARP_ALERT: "passive-arp-alert",
  PASSIVE_ARP_ERROR: "passive-arp-error",
  // Shared
  PASSIVE_CAPTURE_COMPLETE: "passive-capture-complete",
  PASSIVE_STATUS_UPDATE: "passive-status-update",
  // Rogue DNS Detection
  PASSIVE_ROGUE_DNS_ALERT: "passive-rogue-dns-alert",
  PASSIVE_ROGUE_DNS_ERROR: "passive-rogue-dns-error",
  // PCAP Live Capture & Analysis
  START_PCAP_CAPTURE: "start-pcap-capture",
  STOP_PCAP_CAPTURE: "stop-pcap-capture",
  ANALYZE_PCAP_FILE: "analyze-pcap-file",
  PCAP_PACKET_SUMMARY: "pcap-packet-summary",
  PCAP_STATS_UPDATE: "pcap-stats-update",
  PCAP_CAPTURE_ERROR: "pcap-capture-error",
  PCAP_CAPTURE_COMPLETE: "pcap-capture-complete",
  // Offensive Pentest: Brute-Force
  BRUTEFORCE_START: "bruteforce-start",
  BRUTEFORCE_STOP: "bruteforce-stop",
  BRUTEFORCE_ATTEMPT: "bruteforce-attempt",
  BRUTEFORCE_RESULT: "bruteforce-result",
  BRUTEFORCE_PROGRESS: "bruteforce-progress",
  BRUTEFORCE_ERROR: "bruteforce-error",
  BRUTEFORCE_COMPLETE: "bruteforce-complete",
  // Generic file dialog
  BROWSE_FILE: "browse-file",
  // Offensive Pentest: Metasploit RPC
  MSF_CONNECT: "msf-connect",
  MSF_DISCONNECT: "msf-disconnect",
  MSF_RUN_EXPLOIT: "msf-run-exploit",
  MSF_LIST_EXPLOITS: "msf-list-exploits",
  MSF_SESSION_LIST: "msf-session-list",
  MSF_STATUS: "msf-status",
  MSF_RESULT: "msf-result",
  MSF_ERROR: "msf-error",
  // Offensive Pentest: Reverse Shell Listener
  REVSHELL_START: "revshell-start",
  REVSHELL_STOP: "revshell-stop",
  REVSHELL_DATA: "revshell-data",
  REVSHELL_SEND: "revshell-send",
  REVSHELL_CONNECTION: "revshell-connection",
  REVSHELL_ERROR: "revshell-error",
  // Offensive Pentest: Share Enumeration (4D)
  SHARE_ENUMERATE: "share-enumerate",
  SHARE_BROWSE: "share-browse",
  SHARE_DOWNLOAD: "share-download",
  SHARE_RESULT: "share-result",
  SHARE_ERROR: "share-error",
  // Offensive Pentest: Web Directory Fuzzing (4E)
  DIRFUZZ_START: "dirfuzz-start",
  DIRFUZZ_STOP: "dirfuzz-stop",
  DIRFUZZ_HIT: "dirfuzz-hit",
  DIRFUZZ_PROGRESS: "dirfuzz-progress",
  DIRFUZZ_COMPLETE: "dirfuzz-complete",
  DIRFUZZ_ERROR: "dirfuzz-error",
  // Feature 5A: Hardening Monitor — Continuous Delta Monitoring
  HARDENING_START_MONITOR: "hardening-start-monitor",
  HARDENING_STOP_MONITOR: "hardening-stop-monitor",
  HARDENING_SET_BASELINE: "hardening-set-baseline",
  HARDENING_GET_BASELINE: "hardening-get-baseline",
  HARDENING_GET_SCHEDULES: "hardening-get-schedules",
  HARDENING_DELTA_ALERT: "hardening-delta-alert",
  // main -> renderer
  HARDENING_DELTA_REPORT: "hardening-delta-report",
  // main -> renderer (full diff)
  HARDENING_MONITOR_STATUS: "hardening-monitor-status",
  // main -> renderer
  HARDENING_HOST_UPDATE: "hardening-host-update",
  // main -> renderer, one per host
  // Feature 5B: Default Credential Spray
  CREDSPRAY_START: "credspray-start",
  CREDSPRAY_STOP: "credspray-stop",
  CREDSPRAY_HIT: "credspray-hit",
  // main -> renderer
  CREDSPRAY_PROGRESS: "credspray-progress",
  // main -> renderer
  CREDSPRAY_COMPLETE: "credspray-complete",
  // main -> renderer
  CREDSPRAY_ERROR: "credspray-error",
  // main -> renderer
  // Feature 5C: Container & Cloud Enumeration
  CLOUDENUM_START: "cloudenum-start",
  CLOUDENUM_STOP: "cloudenum-stop",
  CLOUDENUM_FINDING: "cloudenum-finding",
  // main -> renderer
  CLOUDENUM_PROGRESS: "cloudenum-progress",
  // main -> renderer
  CLOUDENUM_COMPLETE: "cloudenum-complete",
  // main -> renderer
  CLOUDENUM_ERROR: "cloudenum-error",
  // main -> renderer
  // ─── Feature 7A — Intercepting Proxy ─────────────────────────────────────────
  PROXY_START: "proxy-start",
  PROXY_STOP: "proxy-stop",
  PROXY_STATUS: "proxy-status",
  // main -> renderer
  PROXY_REQUEST: "proxy-request",
  // main -> renderer (new entry)
  PROXY_INTERCEPTED: "proxy-intercepted",
  // main -> renderer (paused req)
  PROXY_FORWARD: "proxy-forward",
  // renderer -> main
  PROXY_DROP: "proxy-drop",
  // renderer -> main
  PROXY_SET_INTERCEPT: "proxy-set-intercept",
  PROXY_GET_HISTORY: "proxy-get-history",
  PROXY_GET_REQUEST: "proxy-get-request",
  PROXY_CLEAR_HISTORY: "proxy-clear-history",
  PROXY_INSTALL_CA: "proxy-install-ca",
  PROXY_EXPORT_HAR: "proxy-export-har",
  PROXY_WS_FRAME: "proxy-ws-frame",
  // main -> renderer
  PROXY_GET_STATUS: "proxy-get-status",
  PROXY_DELETE_REQUEST: "proxy-delete-request",
  PROXY_GET_CA_PATH: "proxy-get-ca-path",
  // ─── Feature 7B — Crawler & Attack Surface ───────────────────────────────────
  CRAWLER_START: "crawler-start",
  CRAWLER_STOP: "crawler-stop",
  CRAWLER_URL_FOUND: "crawler-url-found",
  // main -> renderer
  CRAWLER_FORM_FOUND: "crawler-form-found",
  // main -> renderer
  CRAWLER_PROGRESS: "crawler-progress",
  // main -> renderer
  CRAWLER_COMPLETE: "crawler-complete",
  // main -> renderer
  CRAWLER_ERROR: "crawler-error",
  // main -> renderer
  CRAWLER_DEPENDENCY_MISSING: "crawler-dep-missing",
  // main -> renderer
  SITEMAP_GET: "sitemap-get",
  SITEMAP_CLEAR: "sitemap-clear",
  SITEMAP_EXPORT: "sitemap-export",
  API_DETECT: "api-detect",
  API_SCHEMA_FOUND: "api-schema-found",
  // main -> renderer
  API_DETECT_COMPLETE: "api-detect-complete",
  // main -> renderer { found: number }
  PLAYWRIGHT_CHECK: "playwright-check",
  // ─── Feature 7B/7C — DNS resolution (hostname → IP for cross-workspace pivot)
  DNS_RESOLVE: "dns-resolve",
  // ─── Feature 7C — Active Vulnerability Scanner ────────────────────────────
  SCANNER_START: "scanner-start",
  SCANNER_STOP: "scanner-stop",
  SCANNER_FINDING: "scanner-finding",
  // main -> renderer
  SCANNER_PROGRESS: "scanner-progress",
  // main -> renderer
  SCANNER_COMPLETE: "scanner-complete",
  // main -> renderer
  SCANNER_ERROR: "scanner-error",
  // main -> renderer
  SCANNER_ACTIVITY: "scanner-activity",
  // main -> renderer
  SCANNER_GET_FINDINGS: "scanner-get-findings",
  SCANNER_EXPORT: "scanner-export",
  SCANNER_CLEAR: "scanner-clear",
  // ─── Feature 7D — Manual Testing Utilities ───────────────────────────────────
  REPEATER_SEND: "repeater-send",
  REPEATER_RESPONSE: "repeater-response",
  // main → renderer
  REPEATER_ERROR: "repeater-error",
  // main → renderer
  INTRUDER_START: "intruder-start",
  INTRUDER_STOP: "intruder-stop",
  INTRUDER_RESULT: "intruder-result",
  // main → renderer (one per request)
  INTRUDER_PROGRESS: "intruder-progress",
  // main → renderer
  INTRUDER_COMPLETE: "intruder-complete",
  // main → renderer
  INTRUDER_ERROR: "intruder-error",
  // main → renderer
  SEQUENCER_COLLECT: "sequencer-collect",
  SEQUENCER_TOKEN: "sequencer-token",
  // main → renderer
  SEQUENCER_ANALYZE: "sequencer-analyze",
  SEQUENCER_RESULT: "sequencer-result",
  // main → renderer
  SEQUENCER_ERROR: "sequencer-error",
  // main → renderer
  DECODER_TRANSFORM: "decoder-transform",
  DECODER_RESULT: "decoder-result"
  // main → renderer
};

// src/main/preload.js
import_electron.contextBridge.exposeInMainWorld("electronAPI", {
  getInterfaces: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.GET_INTERFACES),
  scanNetwork: (subnet) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SCAN_NETWORK, subnet),
  stopScan: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_SCAN),
  saveResults: (results) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SAVE_RESULTS, results),
  loadResults: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.LOAD_RESULTS),
  clearResults: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CLEAR_RESULTS),
  exitApp: () => import_electron.ipcRenderer.send(IPC_CHANNELS.EXIT_APP),
  // Settings Management
  settings: {
    get: (key) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.GET_SETTING, key),
    set: (key, value) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SET_SETTING, { key, value }),
    getAll: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.GET_ALL_SETTINGS),
    checkDependency: (toolName) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CHECK_DEPENDENCY, toolName)
  },
  // Deep Scan Triggers
  runDeepScan: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.RUN_DEEP_SCAN, ip),
  cancelDeepScan: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CANCEL_DEEP_SCAN, ip),
  openExternalAction: (payload) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.OPEN_EXTERNAL_ACTION, payload),
  openUrl: (url) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.OPEN_URL, { url }),
  // SNMP Walking
  snmpWalk: (targetIp, options) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SNMP_WALK, { targetIp, options }),
  snmpGet: (targetIp, oids, options) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SNMP_GET, { targetIp, oids, options }),
  cancelSnmpWalk: (targetIp) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CANCEL_SNMP_WALK, targetIp),
  onSnmpWalkResult: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SNMP_WALK_RESULT, (_event, value) => callback(value)),
  onSnmpWalkProgress: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SNMP_WALK_PROGRESS, (_event, value) => callback(value)),
  onSnmpWalkComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SNMP_WALK_COMPLETE, (_event, value) => callback(value)),
  onSnmpWalkError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SNMP_WALK_ERROR, (_event, value) => callback(value)),
  onSnmpIntel: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SNMP_INTEL, (_event, value) => callback(value)),
  // Nmap Triggers
  checkNmap: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CHECK_NMAP),
  getNmapScripts: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.GET_NMAP_SCRIPTS),
  runNmapScan: (type, targetObj) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.RUN_NMAP_SCAN, { type, target: targetObj }),
  runNcat: (payloadObj) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.RUN_NCAT, payloadObj),
  cancelNmapScan: (target) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CANCEL_NMAP_SCAN, target),
  // Target Scope Management
  importScopeFile: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.IMPORT_SCOPE_FILE),
  importNmapXml: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.IMPORT_NMAP_XML),
  pingHost: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PING_HOST, ip),
  probeHost: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROBE_HOST, ip),
  // Tshark (VLAN Discovery)
  startTsharkCapture: (interfaceId) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.START_TSHARK, interfaceId),
  stopTsharkCapture: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_TSHARK),
  onTsharkVlanFound: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.TSHARK_VLAN_FOUND, (_event, value) => callback(value)),
  onTsharkError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.TSHARK_ERROR, (_event, value) => callback(value)),
  onTsharkComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.TSHARK_COMPLETE, (_event, value) => callback(value)),
  // Event Listeners for streams
  onHostFound: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.HOST_FOUND, (_event, value) => callback(value)),
  onScanComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCAN_COMPLETE, (_event, value) => callback(value)),
  onScanError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCAN_ERROR, (_event, value) => callback(value)),
  // Deep Scan Event Streams
  onDeepScanResult: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_RESULT, (_event, value) => callback(value)),
  onDeepScanProgress: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_PROGRESS, (_event, value) => callback(value)),
  onDeepScanComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_COMPLETE, (_event, value) => callback(value)),
  // Nmap Event Streams
  onNmapScanResult: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_RESULT, (_event, value) => callback(value)),
  onNmapScanComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_COMPLETE, (_event, value) => callback(value)),
  onNmapScanError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_ERROR, (_event, value) => callback(value)),
  // Passive Network Intelligence
  startPassiveCapture: (moduleId, interfaceId, options) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.START_PASSIVE_CAPTURE, { moduleId, interfaceId, options }),
  stopPassiveCapture: (moduleId) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_PASSIVE_CAPTURE, moduleId),
  stopAllPassive: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_ALL_PASSIVE),
  exportPcap: (payload) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.EXPORT_PCAP, payload),
  // Passive Event Listeners
  onPassiveDhcpAlert: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_DHCP_ALERT, (_event, value) => callback(value)),
  onPassiveCredFound: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_CRED_FOUND, (_event, value) => callback(value)),
  onPassiveDnsHost: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_DNS_HOST, (_event, value) => callback(value)),
  onPassiveArpAlert: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_ALERT, (_event, value) => callback(value)),
  onPassiveArpResult: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_RESULT, (_e, v) => cb(v)),
  onPassiveRogueDnsAlert: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ALERT, (_e, v) => cb(v)),
  onPcapExportComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PCAP_EXPORT_COMPLETE, (_event, value) => callback(value)),
  onPassiveStatusUpdate: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_STATUS_UPDATE, (_e, v) => cb(v)),
  onPassiveError: (callback) => {
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_DHCP_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_CRED_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_DNS_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PCAP_EXPORT_ERROR, (_event, value) => callback(value));
  },
  onPassiveCaptureComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE, (_event, value) => callback(value)),
  // PCAP Live Capture & Analysis
  startPcapCapture: (interfaceId, hostIp, options) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.START_PCAP_CAPTURE, { interfaceId, hostIp, options }),
  stopPcapCapture: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_PCAP_CAPTURE),
  analyzePcapFile: (filePath) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.ANALYZE_PCAP_FILE, filePath),
  onPcapPacketSummary: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PCAP_PACKET_SUMMARY, (_event, value) => callback(value)),
  onPcapStatsUpdate: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PCAP_STATS_UPDATE, (_event, value) => callback(value)),
  onPcapCaptureError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PCAP_CAPTURE_ERROR, (_event, value) => callback(value)),
  onPcapCaptureComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PCAP_CAPTURE_COMPLETE, (_event, value) => callback(value)),
  // Offensive Pentest: Brute-Force
  startBruteForce: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.BRUTEFORCE_START, opts),
  stopBruteForce: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.BRUTEFORCE_STOP),
  onBruteForceAttempt: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_ATTEMPT, (_e, v) => cb(v)),
  onBruteForceResult: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_RESULT, (_e, v) => cb(v)),
  onBruteForceProgress: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_PROGRESS, (_e, v) => cb(v)),
  onBruteForceError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_ERROR, (_e, v) => cb(v)),
  onBruteForceComplete: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_COMPLETE, (_e, v) => cb(v)),
  // Generic file dialog
  browseFile: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.BROWSE_FILE, opts),
  // Offensive Pentest: Metasploit RPC
  msfConnect: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.MSF_CONNECT, opts),
  msfDisconnect: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.MSF_DISCONNECT),
  msfRunExploit: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.MSF_RUN_EXPLOIT, opts),
  msfListExploits: (query) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.MSF_LIST_EXPLOITS, query),
  msfSessionList: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.MSF_SESSION_LIST),
  onMsfStatus: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.MSF_STATUS, (_e, v) => cb(v)),
  onMsfResult: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.MSF_RESULT, (_e, v) => cb(v)),
  onMsfError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.MSF_ERROR, (_e, v) => cb(v)),
  // Offensive Pentest: Reverse Shell Listener
  startRevShell: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.REVSHELL_START, opts),
  stopRevShell: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.REVSHELL_STOP),
  sendRevShell: (data) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.REVSHELL_SEND, data),
  onRevShellData: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.REVSHELL_DATA, (_e, v) => cb(v)),
  onRevShellConnection: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.REVSHELL_CONNECTION, (_e, v) => cb(v)),
  onRevShellError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.REVSHELL_ERROR, (_e, v) => cb(v)),
  // Offensive Pentest: Share Enumeration (4D)
  enumerateShares: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SHARE_ENUMERATE, opts),
  browseShare: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SHARE_BROWSE, opts),
  downloadShareFile: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SHARE_DOWNLOAD, opts),
  onShareResult: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SHARE_RESULT, (_e, v) => cb(v)),
  onShareError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SHARE_ERROR, (_e, v) => cb(v)),
  // Offensive Pentest: Web Directory Fuzzing (4E)
  startDirFuzz: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.DIRFUZZ_START, opts),
  stopDirFuzz: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.DIRFUZZ_STOP),
  onDirFuzzHit: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_HIT, (_e, v) => cb(v)),
  onDirFuzzProgress: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_PROGRESS, (_e, v) => cb(v)),
  onDirFuzzComplete: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_COMPLETE, (_e, v) => cb(v)),
  onDirFuzzError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_ERROR, (_e, v) => cb(v)),
  // Feature 5A: Hardening Monitor
  hardeningMonitor: {
    start: (subnet, options) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.HARDENING_START_MONITOR, { subnet, options }),
    stop: (subnet) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.HARDENING_STOP_MONITOR, { subnet }),
    setBaseline: (subnet, hosts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.HARDENING_SET_BASELINE, { subnet, hosts }),
    getBaseline: (subnet) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.HARDENING_GET_BASELINE, { subnet }),
    getSchedules: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.HARDENING_GET_SCHEDULES),
    onDeltaAlert: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.HARDENING_DELTA_ALERT, (_e, v) => cb(v)),
    onDeltaReport: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.HARDENING_DELTA_REPORT, (_e, v) => cb(v)),
    onStatus: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.HARDENING_MONITOR_STATUS, (_e, v) => cb(v)),
    onHostUpdate: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.HARDENING_HOST_UPDATE, (_e, v) => cb(v))
  },
  // Feature 5B: Credential Spray
  startCredSpray: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CREDSPRAY_START, opts),
  stopCredSpray: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CREDSPRAY_STOP),
  onCredSprayHit: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_HIT, (_e, v) => cb(v)),
  onCredSprayProgress: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_PROGRESS, (_e, v) => cb(v)),
  onCredSprayComplete: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_COMPLETE, (_e, v) => cb(v)),
  onCredSprayError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_ERROR, (_e, v) => cb(v)),
  // Feature 5C: Container & Cloud Enumeration
  cloudEnum: {
    start: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CLOUDENUM_START, opts),
    stop: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CLOUDENUM_STOP),
    onFinding: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_FINDING, (_e, v) => cb(v)),
    onProgress: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_PROGRESS, (_e, v) => cb(v)),
    onComplete: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_COMPLETE, (_e, v) => cb(v)),
    onError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_ERROR, (_e, v) => cb(v))
  },
  // Feature 7A: Intercepting Proxy
  proxy: {
    start: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_START, opts),
    stop: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_STOP),
    getStatus: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_GET_STATUS),
    setIntercept: (enabled) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_SET_INTERCEPT, enabled),
    forward: (id, raw) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_FORWARD, { id, modifiedRaw: raw }),
    drop: (id) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_DROP, { id }),
    getHistory: (filter) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_GET_HISTORY, filter),
    getRequest: (id) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_GET_REQUEST, id),
    deleteRequest: (id) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_DELETE_REQUEST, id),
    clearHistory: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_CLEAR_HISTORY),
    exportHar: (ids) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_EXPORT_HAR, ids),
    installCa: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_INSTALL_CA),
    getCaPath: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROXY_GET_CA_PATH),
    onStatus: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.PROXY_STATUS, (_e, v) => cb(v)),
    onRequest: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.PROXY_REQUEST, (_e, v) => cb(v)),
    onIntercepted: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.PROXY_INTERCEPTED, (_e, v) => cb(v)),
    onWsFrame: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.PROXY_WS_FRAME, (_e, v) => cb(v))
  },
  // Feature 7B: Web Crawler & Attack Surface Mapping
  crawler: {
    checkPlaywright: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PLAYWRIGHT_CHECK),
    start: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CRAWLER_START, opts),
    stop: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CRAWLER_STOP),
    getSitemap: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SITEMAP_GET),
    clearSitemap: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SITEMAP_CLEAR),
    exportSitemap: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SITEMAP_EXPORT),
    detectApis: (baseUrl) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.API_DETECT, { baseUrl }),
    onUrlFound: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CRAWLER_URL_FOUND, (_e, v) => cb(v)),
    onFormFound: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CRAWLER_FORM_FOUND, (_e, v) => cb(v)),
    onProgress: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CRAWLER_PROGRESS, (_e, v) => cb(v)),
    onComplete: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CRAWLER_COMPLETE, (_e, v) => cb(v)),
    onError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CRAWLER_ERROR, (_e, v) => cb(v)),
    onDependencyMissing: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.CRAWLER_DEPENDENCY_MISSING, (_e, v) => cb(v)),
    onApiSchemaFound: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.API_SCHEMA_FOUND, (_e, v) => cb(v)),
    onApiDetectComplete: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.API_DETECT_COMPLETE, (_e, v) => cb(v))
  },
  // Feature 7B/7C: DNS resolution (hostname → IP, for cross-workspace pivot)
  resolveHostname: (hostname) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.DNS_RESOLVE, hostname),
  // Feature 7C: Active Vulnerability Scanner
  scanner: {
    start: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SCANNER_START, opts),
    stop: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SCANNER_STOP),
    getFindings: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SCANNER_GET_FINDINGS),
    clear: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SCANNER_CLEAR),
    export: (format, findings) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SCANNER_EXPORT, { format, findings }),
    onFinding: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCANNER_FINDING, (_e, v) => cb(v)),
    onProgress: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCANNER_PROGRESS, (_e, v) => cb(v)),
    onComplete: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCANNER_COMPLETE, (_e, v) => cb(v)),
    onError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCANNER_ERROR, (_e, v) => cb(v)),
    onActivity: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCANNER_ACTIVITY, (_e, v) => cb(v))
  },
  // Feature 7D: Repeater
  repeater: {
    send: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.REPEATER_SEND, opts)
  },
  // Feature 7D: Intruder
  intruder: {
    start: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.INTRUDER_START, opts),
    stop: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.INTRUDER_STOP),
    onResult: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.INTRUDER_RESULT, (_e, v) => cb(v)),
    onProgress: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.INTRUDER_PROGRESS, (_e, v) => cb(v)),
    onComplete: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.INTRUDER_COMPLETE, (_e, v) => cb(v)),
    onError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.INTRUDER_ERROR, (_e, v) => cb(v))
  },
  // Feature 7D: Sequencer
  sequencer: {
    collect: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SEQUENCER_COLLECT, opts),
    analyze: (tokens) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SEQUENCER_ANALYZE, { tokens }),
    onToken: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SEQUENCER_TOKEN, (_e, v) => cb(v)),
    onResult: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SEQUENCER_RESULT, (_e, v) => cb(v)),
    onError: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.SEQUENCER_ERROR, (_e, v) => cb(v))
  },
  // Feature 7D: Decoder (server-side heavy transforms: gzip, hashing)
  decoder: {
    transform: (transform, input) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.DECODER_TRANSFORM, { transform, input })
  },
  // Cleanup listeners
  removeListeners: () => {
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.HOST_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_VLAN_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DHCP_ALERT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CRED_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DNS_HOST);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_ALERT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ALERT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DHCP_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CRED_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DNS_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_EXPORT_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_EXPORT_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_STATUS_UPDATE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_WALK_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_WALK_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_WALK_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_WALK_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_INTEL);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_PACKET_SUMMARY);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_STATS_UPDATE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_CAPTURE_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_CAPTURE_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_ATTEMPT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.MSF_STATUS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.MSF_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.MSF_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.REVSHELL_DATA);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.REVSHELL_CONNECTION);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.REVSHELL_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SHARE_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SHARE_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DIRFUZZ_HIT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DIRFUZZ_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DIRFUZZ_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DIRFUZZ_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.HARDENING_DELTA_ALERT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.HARDENING_DELTA_REPORT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.HARDENING_MONITOR_STATUS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.HARDENING_HOST_UPDATE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CREDSPRAY_HIT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CREDSPRAY_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CREDSPRAY_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CREDSPRAY_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CLOUDENUM_FINDING);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CLOUDENUM_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CLOUDENUM_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CLOUDENUM_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PROXY_STATUS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PROXY_REQUEST);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PROXY_INTERCEPTED);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PROXY_WS_FRAME);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_URL_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_FORM_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_DEPENDENCY_MISSING);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.API_SCHEMA_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCANNER_FINDING);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCANNER_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCANNER_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCANNER_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.INTRUDER_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.INTRUDER_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.INTRUDER_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.INTRUDER_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SEQUENCER_TOKEN);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SEQUENCER_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SEQUENCER_ERROR);
  }
});
