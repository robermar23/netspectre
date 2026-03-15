import { contextBridge, ipcRenderer } from 'electron';
import { IPC_CHANNELS } from '#shared/ipc.js';

contextBridge.exposeInMainWorld('electronAPI', {
  getInterfaces: () => ipcRenderer.invoke(IPC_CHANNELS.GET_INTERFACES),
  scanNetwork: (subnet) => ipcRenderer.invoke(IPC_CHANNELS.SCAN_NETWORK, subnet),
  stopScan: () => ipcRenderer.invoke(IPC_CHANNELS.STOP_SCAN),
  saveResults: (results) => ipcRenderer.invoke(IPC_CHANNELS.SAVE_RESULTS, results),
  loadResults: () => ipcRenderer.invoke(IPC_CHANNELS.LOAD_RESULTS),
  clearResults: () => ipcRenderer.invoke(IPC_CHANNELS.CLEAR_RESULTS),
  exitApp: () => ipcRenderer.send(IPC_CHANNELS.EXIT_APP),

  // Settings Management
  settings: {
    get: (key) => ipcRenderer.invoke(IPC_CHANNELS.GET_SETTING, key),
    set: (key, value) => ipcRenderer.invoke(IPC_CHANNELS.SET_SETTING, { key, value }),
    getAll: () => ipcRenderer.invoke(IPC_CHANNELS.GET_ALL_SETTINGS),
    checkDependency: (toolName) => ipcRenderer.invoke(IPC_CHANNELS.CHECK_DEPENDENCY, toolName)
  },

  // Deep Scan Triggers
  runDeepScan: (ip) => ipcRenderer.invoke(IPC_CHANNELS.RUN_DEEP_SCAN, ip),
  cancelDeepScan: (ip) => ipcRenderer.invoke(IPC_CHANNELS.CANCEL_DEEP_SCAN, ip),
  openExternalAction: (payload) => ipcRenderer.invoke(IPC_CHANNELS.OPEN_EXTERNAL_ACTION, payload),
  openUrl: (url) => ipcRenderer.invoke(IPC_CHANNELS.OPEN_URL, { url }),

  // SNMP Walking
  snmpWalk: (targetIp, options) => ipcRenderer.invoke(IPC_CHANNELS.SNMP_WALK, { targetIp, options }),
  snmpGet: (targetIp, oids, options) => ipcRenderer.invoke(IPC_CHANNELS.SNMP_GET, { targetIp, oids, options }),
  cancelSnmpWalk: (targetIp) => ipcRenderer.invoke(IPC_CHANNELS.CANCEL_SNMP_WALK, targetIp),
  onSnmpWalkResult: (callback) => ipcRenderer.on(IPC_CHANNELS.SNMP_WALK_RESULT, (_event, value) => callback(value)),
  onSnmpWalkProgress: (callback) => ipcRenderer.on(IPC_CHANNELS.SNMP_WALK_PROGRESS, (_event, value) => callback(value)),
  onSnmpWalkComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.SNMP_WALK_COMPLETE, (_event, value) => callback(value)),
  onSnmpWalkError: (callback) => ipcRenderer.on(IPC_CHANNELS.SNMP_WALK_ERROR, (_event, value) => callback(value)),
  onSnmpIntel: (callback) => ipcRenderer.on(IPC_CHANNELS.SNMP_INTEL, (_event, value) => callback(value)),

  // Nmap Triggers
  checkNmap: () => ipcRenderer.invoke(IPC_CHANNELS.CHECK_NMAP),
  getNmapScripts: () => ipcRenderer.invoke(IPC_CHANNELS.GET_NMAP_SCRIPTS),
  runNmapScan: (type, targetObj) => ipcRenderer.invoke(IPC_CHANNELS.RUN_NMAP_SCAN, { type, target: targetObj }),
  runNcat: (payloadObj) => ipcRenderer.invoke(IPC_CHANNELS.RUN_NCAT, payloadObj),
  cancelNmapScan: (target) => ipcRenderer.invoke(IPC_CHANNELS.CANCEL_NMAP_SCAN, target),

  // Target Scope Management
  importScopeFile: () => ipcRenderer.invoke(IPC_CHANNELS.IMPORT_SCOPE_FILE),
  importNmapXml: () => ipcRenderer.invoke(IPC_CHANNELS.IMPORT_NMAP_XML),
  pingHost: (ip) => ipcRenderer.invoke(IPC_CHANNELS.PING_HOST, ip),
  probeHost: (ip) => ipcRenderer.invoke(IPC_CHANNELS.PROBE_HOST, ip),
  
  // Tshark (VLAN Discovery)
  startTsharkCapture: (interfaceId) => ipcRenderer.invoke(IPC_CHANNELS.START_TSHARK, interfaceId),
  stopTsharkCapture: () => ipcRenderer.invoke(IPC_CHANNELS.STOP_TSHARK),
  onTsharkVlanFound: (callback) => ipcRenderer.on(IPC_CHANNELS.TSHARK_VLAN_FOUND, (_event, value) => callback(value)),
  onTsharkError: (callback) => ipcRenderer.on(IPC_CHANNELS.TSHARK_ERROR, (_event, value) => callback(value)),
  onTsharkComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.TSHARK_COMPLETE, (_event, value) => callback(value)),

  // Event Listeners for streams
  onHostFound: (callback) => ipcRenderer.on(IPC_CHANNELS.HOST_FOUND, (_event, value) => callback(value)),
  onScanComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.SCAN_COMPLETE, (_event, value) => callback(value)),
  onScanError: (callback) => ipcRenderer.on(IPC_CHANNELS.SCAN_ERROR, (_event, value) => callback(value)),
  
  // Deep Scan Event Streams
  onDeepScanResult: (callback) => ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_RESULT, (_event, value) => callback(value)),
  onDeepScanProgress: (callback) => ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_PROGRESS, (_event, value) => callback(value)),
  onDeepScanComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_COMPLETE, (_event, value) => callback(value)),

  // Nmap Event Streams
  onNmapScanResult: (callback) => ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_RESULT, (_event, value) => callback(value)),
  onNmapScanComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_COMPLETE, (_event, value) => callback(value)),
  onNmapScanError: (callback) => ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_ERROR, (_event, value) => callback(value)),

  // Passive Network Intelligence
  startPassiveCapture: (moduleId, interfaceId, options) => ipcRenderer.invoke(IPC_CHANNELS.START_PASSIVE_CAPTURE, { moduleId, interfaceId, options }),
  stopPassiveCapture: (moduleId) => ipcRenderer.invoke(IPC_CHANNELS.STOP_PASSIVE_CAPTURE, moduleId),
  stopAllPassive: () => ipcRenderer.invoke(IPC_CHANNELS.STOP_ALL_PASSIVE),
  exportPcap: (payload) => ipcRenderer.invoke(IPC_CHANNELS.EXPORT_PCAP, payload),

  // Passive Event Listeners
  onPassiveDhcpAlert: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_DHCP_ALERT, (_event, value) => callback(value)),
  onPassiveCredFound: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_CRED_FOUND, (_event, value) => callback(value)),
  onPassiveDnsHost: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_DNS_HOST, (_event, value) => callback(value)),
  onPassiveArpAlert: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_ALERT, (_event, value) => callback(value)),
  onPassiveArpResult: (cb) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_RESULT, (_e, v) => cb(v)),
  onPassiveRogueDnsAlert: (cb) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ALERT, (_e, v) => cb(v)),
  onPcapExportComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.PCAP_EXPORT_COMPLETE, (_event, value) => callback(value)),
  onPassiveStatusUpdate: (cb) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_STATUS_UPDATE, (_e, v) => cb(v)),
  onPassiveError: (callback) => {
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_DHCP_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_CRED_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_DNS_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PCAP_EXPORT_ERROR, (_event, value) => callback(value));
  },
  onPassiveCaptureComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE, (_event, value) => callback(value)),

  // PCAP Live Capture & Analysis
  startPcapCapture: (interfaceId, hostIp, options) => ipcRenderer.invoke(IPC_CHANNELS.START_PCAP_CAPTURE, { interfaceId, hostIp, options }),
  stopPcapCapture: () => ipcRenderer.invoke(IPC_CHANNELS.STOP_PCAP_CAPTURE),
  analyzePcapFile: (filePath) => ipcRenderer.invoke(IPC_CHANNELS.ANALYZE_PCAP_FILE, filePath),
  onPcapPacketSummary: (callback) => ipcRenderer.on(IPC_CHANNELS.PCAP_PACKET_SUMMARY, (_event, value) => callback(value)),
  onPcapStatsUpdate: (callback) => ipcRenderer.on(IPC_CHANNELS.PCAP_STATS_UPDATE, (_event, value) => callback(value)),
  onPcapCaptureError: (callback) => ipcRenderer.on(IPC_CHANNELS.PCAP_CAPTURE_ERROR, (_event, value) => callback(value)),
  onPcapCaptureComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.PCAP_CAPTURE_COMPLETE, (_event, value) => callback(value)),

  // Offensive Pentest: Brute-Force
  startBruteForce: (opts) => ipcRenderer.invoke(IPC_CHANNELS.BRUTEFORCE_START, opts),
  stopBruteForce: () => ipcRenderer.invoke(IPC_CHANNELS.BRUTEFORCE_STOP),
  onBruteForceAttempt: (cb) => ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_ATTEMPT, (_e, v) => cb(v)),
  onBruteForceResult: (cb) => ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_RESULT, (_e, v) => cb(v)),
  onBruteForceProgress: (cb) => ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_PROGRESS, (_e, v) => cb(v)),
  onBruteForceError: (cb) => ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_ERROR, (_e, v) => cb(v)),
  onBruteForceComplete: (cb) => ipcRenderer.on(IPC_CHANNELS.BRUTEFORCE_COMPLETE, (_e, v) => cb(v)),

  // Generic file dialog
  browseFile: (opts) => ipcRenderer.invoke(IPC_CHANNELS.BROWSE_FILE, opts),

  // Offensive Pentest: Metasploit RPC
  msfConnect: (opts) => ipcRenderer.invoke(IPC_CHANNELS.MSF_CONNECT, opts),
  msfDisconnect: () => ipcRenderer.invoke(IPC_CHANNELS.MSF_DISCONNECT),
  msfRunExploit: (opts) => ipcRenderer.invoke(IPC_CHANNELS.MSF_RUN_EXPLOIT, opts),
  msfListExploits: (query) => ipcRenderer.invoke(IPC_CHANNELS.MSF_LIST_EXPLOITS, query),
  msfSessionList: () => ipcRenderer.invoke(IPC_CHANNELS.MSF_SESSION_LIST),
  onMsfStatus: (cb) => ipcRenderer.on(IPC_CHANNELS.MSF_STATUS, (_e, v) => cb(v)),
  onMsfResult: (cb) => ipcRenderer.on(IPC_CHANNELS.MSF_RESULT, (_e, v) => cb(v)),
  onMsfError: (cb) => ipcRenderer.on(IPC_CHANNELS.MSF_ERROR, (_e, v) => cb(v)),

  // Offensive Pentest: Reverse Shell Listener
  startRevShell: (opts) => ipcRenderer.invoke(IPC_CHANNELS.REVSHELL_START, opts),
  stopRevShell: () => ipcRenderer.invoke(IPC_CHANNELS.REVSHELL_STOP),
  sendRevShell: (data) => ipcRenderer.invoke(IPC_CHANNELS.REVSHELL_SEND, data),
  onRevShellData: (cb) => ipcRenderer.on(IPC_CHANNELS.REVSHELL_DATA, (_e, v) => cb(v)),
  onRevShellConnection: (cb) => ipcRenderer.on(IPC_CHANNELS.REVSHELL_CONNECTION, (_e, v) => cb(v)),
  onRevShellError: (cb) => ipcRenderer.on(IPC_CHANNELS.REVSHELL_ERROR, (_e, v) => cb(v)),

  // Offensive Pentest: Share Enumeration (4D)
  enumerateShares: (opts) => ipcRenderer.invoke(IPC_CHANNELS.SHARE_ENUMERATE, opts),
  browseShare: (opts) => ipcRenderer.invoke(IPC_CHANNELS.SHARE_BROWSE, opts),
  downloadShareFile: (opts) => ipcRenderer.invoke(IPC_CHANNELS.SHARE_DOWNLOAD, opts),
  onShareResult: (cb) => ipcRenderer.on(IPC_CHANNELS.SHARE_RESULT, (_e, v) => cb(v)),
  onShareError: (cb) => ipcRenderer.on(IPC_CHANNELS.SHARE_ERROR, (_e, v) => cb(v)),

  // Offensive Pentest: Web Directory Fuzzing (4E)
  startDirFuzz: (opts) => ipcRenderer.invoke(IPC_CHANNELS.DIRFUZZ_START, opts),
  stopDirFuzz: () => ipcRenderer.invoke(IPC_CHANNELS.DIRFUZZ_STOP),
  onDirFuzzHit: (cb) => ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_HIT, (_e, v) => cb(v)),
  onDirFuzzProgress: (cb) => ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_PROGRESS, (_e, v) => cb(v)),
  onDirFuzzComplete: (cb) => ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_COMPLETE, (_e, v) => cb(v)),
  onDirFuzzError: (cb) => ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_ERROR, (_e, v) => cb(v)),

  // Feature 5A: Hardening Monitor
  hardeningMonitor: {
    start:        (subnet, options) => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_START_MONITOR,  { subnet, options }),
    stop:         (subnet)         => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_STOP_MONITOR,    { subnet }),
    setBaseline:  (subnet, hosts)  => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_SET_BASELINE,   { subnet, hosts }),
    getBaseline:  (subnet)         => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_GET_BASELINE,   { subnet }),
    getSchedules: ()               => ipcRenderer.invoke(IPC_CHANNELS.HARDENING_GET_SCHEDULES),
    onDeltaAlert:    (cb) => ipcRenderer.on(IPC_CHANNELS.HARDENING_DELTA_ALERT,    (_e, v) => cb(v)),
    onDeltaReport:   (cb) => ipcRenderer.on(IPC_CHANNELS.HARDENING_DELTA_REPORT,   (_e, v) => cb(v)),
    onStatus:        (cb) => ipcRenderer.on(IPC_CHANNELS.HARDENING_MONITOR_STATUS, (_e, v) => cb(v)),
    onHostUpdate:    (cb) => ipcRenderer.on(IPC_CHANNELS.HARDENING_HOST_UPDATE,    (_e, v) => cb(v)),
  },

  // Feature 5B: Credential Spray
  startCredSpray: (opts) => ipcRenderer.invoke(IPC_CHANNELS.CREDSPRAY_START, opts),
  stopCredSpray: () => ipcRenderer.invoke(IPC_CHANNELS.CREDSPRAY_STOP),
  onCredSprayHit: (cb) => ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_HIT, (_e, v) => cb(v)),
  onCredSprayProgress: (cb) => ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_PROGRESS, (_e, v) => cb(v)),
  onCredSprayComplete: (cb) => ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_COMPLETE, (_e, v) => cb(v)),
  onCredSprayError: (cb) => ipcRenderer.on(IPC_CHANNELS.CREDSPRAY_ERROR, (_e, v) => cb(v)),

  // Feature 5C: Container & Cloud Enumeration
  cloudEnum: {
    start:      (opts) => ipcRenderer.invoke(IPC_CHANNELS.CLOUDENUM_START, opts),
    stop:       ()     => ipcRenderer.invoke(IPC_CHANNELS.CLOUDENUM_STOP),
    onFinding:  (cb)   => ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_FINDING,  (_e, v) => cb(v)),
    onProgress: (cb)   => ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_PROGRESS, (_e, v) => cb(v)),
    onComplete: (cb)   => ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_COMPLETE, (_e, v) => cb(v)),
    onError:    (cb)   => ipcRenderer.on(IPC_CHANNELS.CLOUDENUM_ERROR,    (_e, v) => cb(v)),
  },

  // Feature 7A: Intercepting Proxy
  proxy: {
    start:         (opts)        => ipcRenderer.invoke(IPC_CHANNELS.PROXY_START, opts),
    stop:          ()            => ipcRenderer.invoke(IPC_CHANNELS.PROXY_STOP),
    getStatus:     ()            => ipcRenderer.invoke(IPC_CHANNELS.PROXY_GET_STATUS),
    setIntercept:  (enabled)     => ipcRenderer.invoke(IPC_CHANNELS.PROXY_SET_INTERCEPT, enabled),
    forward:       (id, raw)     => ipcRenderer.invoke(IPC_CHANNELS.PROXY_FORWARD, { id, modifiedRaw: raw }),
    drop:          (id)          => ipcRenderer.invoke(IPC_CHANNELS.PROXY_DROP, { id }),
    getHistory:    (filter)      => ipcRenderer.invoke(IPC_CHANNELS.PROXY_GET_HISTORY, filter),
    getRequest:    (id)          => ipcRenderer.invoke(IPC_CHANNELS.PROXY_GET_REQUEST, id),
    deleteRequest: (id)          => ipcRenderer.invoke(IPC_CHANNELS.PROXY_DELETE_REQUEST, id),
    clearHistory:  ()            => ipcRenderer.invoke(IPC_CHANNELS.PROXY_CLEAR_HISTORY),
    exportHar:     (ids)         => ipcRenderer.invoke(IPC_CHANNELS.PROXY_EXPORT_HAR, ids),
    installCa:     ()            => ipcRenderer.invoke(IPC_CHANNELS.PROXY_INSTALL_CA),
    getCaPath:     ()            => ipcRenderer.invoke(IPC_CHANNELS.PROXY_GET_CA_PATH),
    onStatus:      (cb) => ipcRenderer.on(IPC_CHANNELS.PROXY_STATUS,      (_e, v) => cb(v)),
    onRequest:     (cb) => ipcRenderer.on(IPC_CHANNELS.PROXY_REQUEST,     (_e, v) => cb(v)),
    onIntercepted: (cb) => ipcRenderer.on(IPC_CHANNELS.PROXY_INTERCEPTED, (_e, v) => cb(v)),
    onWsFrame:     (cb) => ipcRenderer.on(IPC_CHANNELS.PROXY_WS_FRAME,    (_e, v) => cb(v)),
  },

  // Feature 7B: Web Crawler & Attack Surface Mapping
  crawler: {
    checkPlaywright: () => ipcRenderer.invoke(IPC_CHANNELS.PLAYWRIGHT_CHECK),
    start:        (opts)    => ipcRenderer.invoke(IPC_CHANNELS.CRAWLER_START, opts),
    stop:         ()        => ipcRenderer.invoke(IPC_CHANNELS.CRAWLER_STOP),
    getSitemap:   ()        => ipcRenderer.invoke(IPC_CHANNELS.SITEMAP_GET),
    clearSitemap: ()        => ipcRenderer.invoke(IPC_CHANNELS.SITEMAP_CLEAR),
    exportSitemap:()        => ipcRenderer.invoke(IPC_CHANNELS.SITEMAP_EXPORT),
    detectApis:   (baseUrl) => ipcRenderer.invoke(IPC_CHANNELS.API_DETECT, { baseUrl }),
    onUrlFound:         (cb) => ipcRenderer.on(IPC_CHANNELS.CRAWLER_URL_FOUND,          (_e, v) => cb(v)),
    onFormFound:        (cb) => ipcRenderer.on(IPC_CHANNELS.CRAWLER_FORM_FOUND,         (_e, v) => cb(v)),
    onProgress:         (cb) => ipcRenderer.on(IPC_CHANNELS.CRAWLER_PROGRESS,           (_e, v) => cb(v)),
    onComplete:         (cb) => ipcRenderer.on(IPC_CHANNELS.CRAWLER_COMPLETE,           (_e, v) => cb(v)),
    onError:            (cb) => ipcRenderer.on(IPC_CHANNELS.CRAWLER_ERROR,              (_e, v) => cb(v)),
    onDependencyMissing:(cb) => ipcRenderer.on(IPC_CHANNELS.CRAWLER_DEPENDENCY_MISSING, (_e, v) => cb(v)),
    onApiSchemaFound:   (cb) => ipcRenderer.on(IPC_CHANNELS.API_SCHEMA_FOUND,           (_e, v) => cb(v)),
    onApiDetectComplete:(cb) => ipcRenderer.on(IPC_CHANNELS.API_DETECT_COMPLETE,       (_e, v) => cb(v)),
  },

  // Feature 7B/7C: DNS resolution (hostname → IP, for cross-workspace pivot)
  resolveHostname: (hostname) => ipcRenderer.invoke(IPC_CHANNELS.DNS_RESOLVE, hostname),

  // Feature 7C: Active Vulnerability Scanner
  scanner: {
    start:       (opts)              => ipcRenderer.invoke(IPC_CHANNELS.SCANNER_START, opts),
    stop:        ()                  => ipcRenderer.invoke(IPC_CHANNELS.SCANNER_STOP),
    getFindings: ()                  => ipcRenderer.invoke(IPC_CHANNELS.SCANNER_GET_FINDINGS),
    clear:       ()                  => ipcRenderer.invoke(IPC_CHANNELS.SCANNER_CLEAR),
    export:      (format, findings)  => ipcRenderer.invoke(IPC_CHANNELS.SCANNER_EXPORT, { format, findings }),
    onFinding:   (cb) => ipcRenderer.on(IPC_CHANNELS.SCANNER_FINDING,   (_e, v) => cb(v)),
    onProgress:  (cb) => ipcRenderer.on(IPC_CHANNELS.SCANNER_PROGRESS,  (_e, v) => cb(v)),
    onComplete:  (cb) => ipcRenderer.on(IPC_CHANNELS.SCANNER_COMPLETE,  (_e, v) => cb(v)),
    onError:     (cb) => ipcRenderer.on(IPC_CHANNELS.SCANNER_ERROR,     (_e, v) => cb(v)),
    onActivity:  (cb) => ipcRenderer.on(IPC_CHANNELS.SCANNER_ACTIVITY,  (_e, v) => cb(v)),
  },

  // Feature 7D: Repeater
  repeater: {
    send: (opts) => ipcRenderer.invoke(IPC_CHANNELS.REPEATER_SEND, opts),
  },

  // Feature 7D: Intruder
  intruder: {
    start:      (opts) => ipcRenderer.invoke(IPC_CHANNELS.INTRUDER_START, opts),
    stop:       ()     => ipcRenderer.invoke(IPC_CHANNELS.INTRUDER_STOP),
    onResult:   (cb)   => ipcRenderer.on(IPC_CHANNELS.INTRUDER_RESULT,   (_e, v) => cb(v)),
    onProgress: (cb)   => ipcRenderer.on(IPC_CHANNELS.INTRUDER_PROGRESS, (_e, v) => cb(v)),
    onComplete: (cb)   => ipcRenderer.on(IPC_CHANNELS.INTRUDER_COMPLETE, (_e, v) => cb(v)),
    onError:    (cb)   => ipcRenderer.on(IPC_CHANNELS.INTRUDER_ERROR,    (_e, v) => cb(v)),
  },

  // Feature 7D: Sequencer
  sequencer: {
    collect: (opts)   => ipcRenderer.invoke(IPC_CHANNELS.SEQUENCER_COLLECT, opts),
    analyze: (tokens) => ipcRenderer.invoke(IPC_CHANNELS.SEQUENCER_ANALYZE, { tokens }),
    onToken:  (cb)    => ipcRenderer.on(IPC_CHANNELS.SEQUENCER_TOKEN,  (_e, v) => cb(v)),
    onResult: (cb)    => ipcRenderer.on(IPC_CHANNELS.SEQUENCER_RESULT, (_e, v) => cb(v)),
    onError:  (cb)    => ipcRenderer.on(IPC_CHANNELS.SEQUENCER_ERROR,  (_e, v) => cb(v)),
  },

  // Feature 7D: Decoder (server-side heavy transforms: gzip, hashing)
  decoder: {
    transform: (transform, input) => ipcRenderer.invoke(IPC_CHANNELS.DECODER_TRANSFORM, { transform, input }),
  },

  // Cleanup listeners
  removeListeners: () => {
    ipcRenderer.removeAllListeners(IPC_CHANNELS.HOST_FOUND);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_VLAN_FOUND);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DHCP_ALERT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CRED_FOUND);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DNS_HOST);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_ALERT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ALERT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DHCP_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CRED_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DNS_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_EXPORT_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_EXPORT_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_STATUS_UPDATE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_WALK_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_WALK_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_WALK_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_WALK_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SNMP_INTEL);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_PACKET_SUMMARY);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_STATS_UPDATE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_CAPTURE_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_CAPTURE_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_ATTEMPT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.BRUTEFORCE_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.MSF_STATUS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.MSF_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.MSF_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.REVSHELL_DATA);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.REVSHELL_CONNECTION);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.REVSHELL_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SHARE_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SHARE_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DIRFUZZ_HIT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DIRFUZZ_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DIRFUZZ_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DIRFUZZ_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.HARDENING_DELTA_ALERT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.HARDENING_DELTA_REPORT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.HARDENING_MONITOR_STATUS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.HARDENING_HOST_UPDATE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CREDSPRAY_HIT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CREDSPRAY_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CREDSPRAY_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CREDSPRAY_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CLOUDENUM_FINDING);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CLOUDENUM_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CLOUDENUM_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CLOUDENUM_ERROR);
    // Feature 7A: Proxy
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PROXY_STATUS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PROXY_REQUEST);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PROXY_INTERCEPTED);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PROXY_WS_FRAME);
    // Feature 7B: Crawler
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_URL_FOUND);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_FORM_FOUND);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.CRAWLER_DEPENDENCY_MISSING);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.API_SCHEMA_FOUND);
    // Feature 7C: Scanner
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SCANNER_FINDING);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SCANNER_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SCANNER_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SCANNER_ERROR);
    // Feature 7D: Manual Tools
    ipcRenderer.removeAllListeners(IPC_CHANNELS.INTRUDER_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.INTRUDER_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.INTRUDER_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.INTRUDER_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SEQUENCER_TOKEN);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SEQUENCER_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SEQUENCER_ERROR);
  }
});
