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
  HARDENING_MONITOR_STATUS: "hardening-monitor-status"
  // main -> renderer
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
    onStatus: (cb) => import_electron.ipcRenderer.on(IPC_CHANNELS.HARDENING_MONITOR_STATUS, (_e, v) => cb(v))
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
  }
});
