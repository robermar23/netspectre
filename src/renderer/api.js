export const api = {
  checkNmap: async () => window.electronAPI.checkNmap(),
  getNmapScripts: async () => window.electronAPI.getNmapScripts(),
  getInterfaces: async () => window.electronAPI.getInterfaces(),
  scanNetwork: async (subnet) => window.electronAPI.scanNetwork(subnet),
  stopScan: async () => window.electronAPI.stopScan(),
  openExternalAction: async (payload) => window.electronAPI.openExternalAction(payload),
  runDeepScan: async (ip) => window.electronAPI.runDeepScan(ip),
  cancelDeepScan: async (ip) => window.electronAPI.cancelDeepScan(ip),
  runNmapScan: async (type, targetObj) => window.electronAPI.runNmapScan(type, targetObj),
  cancelNmapScan: async (target) => window.electronAPI.cancelNmapScan(target),
  runNcat: async (payloadObj) => window.electronAPI.runNcat(payloadObj),
  
  // SNMP Walking
  snmpWalk: async (targetIp, options) => window.electronAPI.snmpWalk(targetIp, options),
  snmpGet: async (targetIp, oids, options) => window.electronAPI.snmpGet(targetIp, oids, options),
  cancelSnmpWalk: async (targetIp) => window.electronAPI.cancelSnmpWalk(targetIp),

  saveResults: async (results) => window.electronAPI.saveResults(results),
  loadResults: async () => window.electronAPI.loadResults(),
  clearResults: async () => window.electronAPI.clearResults(),
  exitApp: () => window.electronAPI.exitApp(),
  // Target Scope Management
  importScopeFile: async () => window.electronAPI.importScopeFile(),
  importNmapXml: async () => window.electronAPI.importNmapXml(),
  pingHost: async (ip) => window.electronAPI.pingHost(ip),
  probeHost: async (ip) => window.electronAPI.probeHost(ip),
  
  // Settings
  settings: {
    get: async (key) => window.electronAPI.settings.get(key),
    set: async (key, value) => window.electronAPI.settings.set(key, value),
    getAll: async () => window.electronAPI.settings.getAll(),
    checkDependency: async (toolName) => window.electronAPI.settings.checkDependency(toolName)
  },
  
  // Tshark (VLAN Discovery)
  startTsharkCapture: async (interfaceId) => window.electronAPI.startTsharkCapture(interfaceId),
  stopTsharkCapture: async () => window.electronAPI.stopTsharkCapture(),

  // Passive Network Intelligence
  startPassiveCapture: async (moduleId, interfaceId, options) => window.electronAPI.startPassiveCapture(moduleId, interfaceId, options),
  stopPassiveCapture: async (moduleId) => window.electronAPI.stopPassiveCapture(moduleId),
  stopAllPassive: async () => window.electronAPI.stopAllPassive(),
  exportPcap: async (payload) => window.electronAPI.exportPcap(payload),

  // PCAP Live Capture & Analysis
  startPcapCapture: async (interfaceId, hostIp, options) => window.electronAPI.startPcapCapture(interfaceId, hostIp, options),
  stopPcapCapture: async () => window.electronAPI.stopPcapCapture(),
  analyzePcapFile: async (filePath) => window.electronAPI.analyzePcapFile(filePath),

  // Brute-Force
  startBruteForce: async (opts) => window.electronAPI.startBruteForce(opts),
  stopBruteForce: async () => window.electronAPI.stopBruteForce(),
  browseFile: async (opts) => window.electronAPI.browseFile(opts),

  // Metasploit RPC
  msfConnect: async (opts) => window.electronAPI.msfConnect(opts),
  msfDisconnect: async () => window.electronAPI.msfDisconnect(),
  msfRunExploit: async (opts) => window.electronAPI.msfRunExploit(opts),
  msfListExploits: async (query) => window.electronAPI.msfListExploits(query),
  msfSessionList: async () => window.electronAPI.msfSessionList(),

  // Reverse Shell
  startRevShell: async (opts) => window.electronAPI.startRevShell(opts),
  stopRevShell: async () => window.electronAPI.stopRevShell(),
  sendRevShell: async (data) => window.electronAPI.sendRevShell(data),

  // Share Enumeration (4D)
  enumerateShares: async (opts) => window.electronAPI.enumerateShares(opts),
  browseShare: async (opts) => window.electronAPI.browseShare(opts),
  downloadShareFile: async (opts) => window.electronAPI.downloadShareFile(opts),

  // Web Directory Fuzzing (4E)
  startDirFuzz: async (opts) => window.electronAPI.startDirFuzz(opts),
  stopDirFuzz: async () => window.electronAPI.stopDirFuzz(),

  // Feature 5A: Hardening Monitor
  hardeningMonitor: window.electronAPI.hardeningMonitor,

  // Feature 5B: Credential Spray
  startCredSpray: async (opts) => window.electronAPI.startCredSpray(opts),
  stopCredSpray: async () => window.electronAPI.stopCredSpray(),

  // Feature 5C: Container & Cloud Enumeration
  cloudEnum: window.electronAPI.cloudEnum,
};
