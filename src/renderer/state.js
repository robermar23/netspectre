export const state = {
  currentView: 'grid', // 'grid', 'list', 'table'
  sortDirection: 'asc', // 'asc', 'desc'
  isScanning: false,
  hosts: [], // Store host objects
  isNmapInstalled: false,
  nmapScripts: [], // Store custom Nmap scripts catalog
  blacklist: [], // Blacklisted IPs/CIDRs/MACs
  pendingHosts: [], // Staging area inside scope modal before committing
  // Passive Network Intelligence
  passiveModules: {
    dhcp: { running: false, alerts: [] },
    creds: { running: false, findings: [] },
    dns: { running: false, hosts: new Map() },
    arp: { running: false, alerts: [] },
  },
  passiveInterface: '', // Currently selected interface for passive capture
  pcapExporting: false,

  // Feature 5B: Credential Spray
  isCredSprayRunning: false,
  credSprayHits: [],

  // Feature 5C: Container & Cloud Enumeration
  isCloudEnumRunning: false,
  cloudFindings: [],         // [{ ip, service, port, severity, title, description, evidence, remediation }]

  // Feature 7A: Web App Workspace
  activeWorkspace: 'network',   // 'network' | 'webapp'
  proxy: {
    running:        false,
    port:           8888,
    interceptMode:  false,
    consentAccepted: false,
    interceptQueue: [],          // pending intercepted requests
    wsConnections:  new Map(),   // sessionId -> { hostname, frames: [] }
  },
  proxyHistory: [],              // lightweight summaries for the History table
  selectedRequest: null,         // full detail of selected row (incl. bodies)
  webAppFindings: [],            // findings from scanner (Phase 7C)
};
