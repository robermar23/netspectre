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
  }
});
