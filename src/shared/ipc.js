/**
 * Single Source of Truth for all Inter-Process Communication (IPC) channels.
 */

export const IPC_CHANNELS = {
  // Main Handlers (renderer -> main)
  GET_INTERFACES: 'get-interfaces',
  SCAN_NETWORK: 'scan-network',
  STOP_SCAN: 'stop-scan',
  SAVE_RESULTS: 'save-results',
  LOAD_RESULTS: 'load-results',
  CLEAR_RESULTS: 'clear-results',
  EXIT_APP: 'exit-app',
  
  RUN_DEEP_SCAN: 'deep-scan-host',
  CANCEL_DEEP_SCAN: 'cancel-deep-scan',
  OPEN_EXTERNAL_ACTION: 'open-external-action',

  // Renderer Listeners (main -> renderer)
  HOST_FOUND: 'host-found',
  SCAN_COMPLETE: 'scan-complete',
  SCAN_ERROR: 'scan-error',
  
  DEEP_SCAN_RESULT: 'deep-scan-result',
  DEEP_SCAN_PROGRESS: 'deep-scan-progress',
  DEEP_SCAN_COMPLETE: 'deep-scan-complete',

  // SNMP Walking
  SNMP_WALK: 'snmp-walk',
  SNMP_GET: 'snmp-get',
  CANCEL_SNMP_WALK: 'cancel-snmp-walk',
  SNMP_WALK_RESULT: 'snmp-walk-result',
  SNMP_WALK_PROGRESS: 'snmp-walk-progress',
  SNMP_WALK_COMPLETE: 'snmp-walk-complete',
  SNMP_WALK_ERROR: 'snmp-walk-error',
  SNMP_INTEL: 'snmp-intel',

  // Nmap Channels
  CHECK_NMAP: 'check-nmap',
  RUN_NMAP_SCAN: 'run-nmap-scan',
  CANCEL_NMAP_SCAN: 'cancel-nmap-scan',
  GET_NMAP_SCRIPTS: 'get-nmap-scripts',
  RUN_NCAT: 'run-ncat',
  NMAP_SCAN_RESULT: 'nmap-scan-result',
  NMAP_SCAN_COMPLETE: 'nmap-scan-complete',
  NMAP_SCAN_ERROR: 'nmap-scan-error',

  // Target Scope Management
  IMPORT_SCOPE_FILE: 'import-scope-file',
  IMPORT_NMAP_XML: 'import-nmap-xml',
  PING_HOST: 'ping-host',
  PROBE_HOST: 'probe-host',
  
  // Settings Management
  GET_SETTING: 'get-setting',
  SET_SETTING: 'set-setting',
  GET_ALL_SETTINGS: 'get-all-settings',
  CHECK_DEPENDENCY: 'check-dependency',
  
  // Tshark (VLAN Discovery)
  START_TSHARK: 'start-tshark',
  STOP_TSHARK: 'stop-tshark',
  TSHARK_VLAN_FOUND: 'tshark-vlan-found',
  TSHARK_ERROR: 'tshark-error',
  TSHARK_COMPLETE: 'tshark-complete',

  // Passive Network Intelligence
  START_PASSIVE_CAPTURE: 'start-passive-capture',
  STOP_PASSIVE_CAPTURE: 'stop-passive-capture',
  STOP_ALL_PASSIVE: 'stop-all-passive',

  // Rogue DHCP Detection
  PASSIVE_DHCP_ALERT: 'passive-dhcp-alert',
  PASSIVE_DHCP_ERROR: 'passive-dhcp-error',

  // Cleartext Credential Sniffing
  PASSIVE_CRED_FOUND: 'passive-cred-found',
  PASSIVE_CRED_ERROR: 'passive-cred-error',

  // DNS Query Harvesting
  PASSIVE_DNS_HOST: 'passive-dns-host',
  PASSIVE_DNS_ERROR: 'passive-dns-error',

  // Live PCAP Export
  EXPORT_PCAP: 'export-pcap',
  PCAP_EXPORT_COMPLETE: 'pcap-export-complete',
  PCAP_EXPORT_ERROR: 'pcap-export-error',

  // ARP Spoofing Detection
  PASSIVE_ARP_ALERT: 'passive-arp-alert',
  PASSIVE_ARP_ERROR: 'passive-arp-error',

  // Shared
  PASSIVE_CAPTURE_COMPLETE: 'passive-capture-complete',
  PASSIVE_STATUS_UPDATE: 'passive-status-update',
  
  // Rogue DNS Detection
  PASSIVE_ROGUE_DNS_ALERT: 'passive-rogue-dns-alert',
  PASSIVE_ROGUE_DNS_ERROR: 'passive-rogue-dns-error',

  // PCAP Live Capture & Analysis
  START_PCAP_CAPTURE: 'start-pcap-capture',
  STOP_PCAP_CAPTURE: 'stop-pcap-capture',
  ANALYZE_PCAP_FILE: 'analyze-pcap-file',
  PCAP_PACKET_SUMMARY: 'pcap-packet-summary',
  PCAP_STATS_UPDATE: 'pcap-stats-update',
  PCAP_CAPTURE_ERROR: 'pcap-capture-error',
  PCAP_CAPTURE_COMPLETE: 'pcap-capture-complete',

  // Offensive Pentest: Brute-Force
  BRUTEFORCE_START: 'bruteforce-start',
  BRUTEFORCE_STOP: 'bruteforce-stop',
  BRUTEFORCE_ATTEMPT: 'bruteforce-attempt',
  BRUTEFORCE_RESULT: 'bruteforce-result',
  BRUTEFORCE_PROGRESS: 'bruteforce-progress',
  BRUTEFORCE_ERROR: 'bruteforce-error',
  BRUTEFORCE_COMPLETE: 'bruteforce-complete',

  // Generic file dialog
  BROWSE_FILE: 'browse-file',

  // Offensive Pentest: Metasploit RPC
  MSF_CONNECT: 'msf-connect',
  MSF_DISCONNECT: 'msf-disconnect',
  MSF_RUN_EXPLOIT: 'msf-run-exploit',
  MSF_LIST_EXPLOITS: 'msf-list-exploits',
  MSF_SESSION_LIST: 'msf-session-list',
  MSF_STATUS: 'msf-status',
  MSF_RESULT: 'msf-result',
  MSF_ERROR: 'msf-error',

  // Offensive Pentest: Reverse Shell Listener
  REVSHELL_START: 'revshell-start',
  REVSHELL_STOP: 'revshell-stop',
  REVSHELL_DATA: 'revshell-data',
  REVSHELL_SEND: 'revshell-send',
  REVSHELL_CONNECTION: 'revshell-connection',
  REVSHELL_ERROR: 'revshell-error',
};
