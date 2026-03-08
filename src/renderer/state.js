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
  credSprayHits: []
};
