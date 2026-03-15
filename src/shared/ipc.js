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
  OPEN_URL:             'open-url',              // open a full URL in the system browser

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
  BROWSE_FILE:    'browse-file',
  READ_WORDLIST:  'read-wordlist',

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

  // Offensive Pentest: Share Enumeration (4D)
  SHARE_ENUMERATE: 'share-enumerate',
  SHARE_BROWSE: 'share-browse',
  SHARE_DOWNLOAD: 'share-download',
  SHARE_RESULT: 'share-result',
  SHARE_ERROR: 'share-error',

  // Offensive Pentest: Web Directory Fuzzing (4E)
  DIRFUZZ_START: 'dirfuzz-start',
  DIRFUZZ_STOP: 'dirfuzz-stop',
  DIRFUZZ_HIT: 'dirfuzz-hit',
  DIRFUZZ_PROGRESS: 'dirfuzz-progress',
  DIRFUZZ_COMPLETE: 'dirfuzz-complete',
  DIRFUZZ_ERROR: 'dirfuzz-error',

  // Feature 5A: Hardening Monitor — Continuous Delta Monitoring
  HARDENING_START_MONITOR:  'hardening-start-monitor',
  HARDENING_STOP_MONITOR:   'hardening-stop-monitor',
  HARDENING_SET_BASELINE:   'hardening-set-baseline',
  HARDENING_GET_BASELINE:   'hardening-get-baseline',
  HARDENING_GET_SCHEDULES:  'hardening-get-schedules',
  HARDENING_DELTA_ALERT:    'hardening-delta-alert',    // main -> renderer
  HARDENING_DELTA_REPORT:   'hardening-delta-report',   // main -> renderer (full diff)
  HARDENING_MONITOR_STATUS: 'hardening-monitor-status', // main -> renderer
  HARDENING_HOST_UPDATE:    'hardening-host-update',    // main -> renderer, one per host

  // Feature 5B: Default Credential Spray
  CREDSPRAY_START:    'credspray-start',
  CREDSPRAY_STOP:     'credspray-stop',
  CREDSPRAY_HIT:      'credspray-hit',        // main -> renderer
  CREDSPRAY_PROGRESS: 'credspray-progress',   // main -> renderer
  CREDSPRAY_COMPLETE: 'credspray-complete',   // main -> renderer
  CREDSPRAY_ERROR:    'credspray-error',      // main -> renderer

  // Feature 5C: Container & Cloud Enumeration
  CLOUDENUM_START:    'cloudenum-start',
  CLOUDENUM_STOP:     'cloudenum-stop',
  CLOUDENUM_FINDING:  'cloudenum-finding',    // main -> renderer
  CLOUDENUM_PROGRESS: 'cloudenum-progress',   // main -> renderer
  CLOUDENUM_COMPLETE: 'cloudenum-complete',   // main -> renderer
  CLOUDENUM_ERROR:    'cloudenum-error',      // main -> renderer

  // ─── Feature 7A — Intercepting Proxy ─────────────────────────────────────────
  PROXY_START:             'proxy-start',
  PROXY_STOP:              'proxy-stop',
  PROXY_STATUS:            'proxy-status',            // main -> renderer
  PROXY_REQUEST:           'proxy-request',           // main -> renderer (new entry)
  PROXY_INTERCEPTED:       'proxy-intercepted',       // main -> renderer (paused req)
  PROXY_FORWARD:           'proxy-forward',           // renderer -> main
  PROXY_DROP:              'proxy-drop',              // renderer -> main
  PROXY_SET_INTERCEPT:     'proxy-set-intercept',
  PROXY_GET_HISTORY:       'proxy-get-history',
  PROXY_GET_REQUEST:       'proxy-get-request',
  PROXY_CLEAR_HISTORY:     'proxy-clear-history',
  PROXY_INSTALL_CA:        'proxy-install-ca',
  PROXY_EXPORT_HAR:        'proxy-export-har',
  PROXY_WS_FRAME:          'proxy-ws-frame',          // main -> renderer
  PROXY_GET_STATUS:        'proxy-get-status',
  PROXY_DELETE_REQUEST:    'proxy-delete-request',
  PROXY_GET_CA_PATH:       'proxy-get-ca-path',

  // ─── Feature 7B — Crawler & Attack Surface ───────────────────────────────────
  CRAWLER_START:              'crawler-start',
  CRAWLER_STOP:               'crawler-stop',
  CRAWLER_URL_FOUND:          'crawler-url-found',          // main -> renderer
  CRAWLER_FORM_FOUND:         'crawler-form-found',         // main -> renderer
  CRAWLER_PROGRESS:           'crawler-progress',           // main -> renderer
  CRAWLER_COMPLETE:           'crawler-complete',           // main -> renderer
  CRAWLER_ERROR:              'crawler-error',              // main -> renderer
  CRAWLER_DEPENDENCY_MISSING: 'crawler-dep-missing',        // main -> renderer
  SITEMAP_GET:                'sitemap-get',
  SITEMAP_CLEAR:              'sitemap-clear',
  SITEMAP_EXPORT:             'sitemap-export',
  API_DETECT:                 'api-detect',
  API_SCHEMA_FOUND:           'api-schema-found',           // main -> renderer
  API_DETECT_COMPLETE:        'api-detect-complete',        // main -> renderer { found: number }
  PLAYWRIGHT_CHECK:           'playwright-check',

  // ─── Feature 7B/7C — DNS resolution (hostname → IP for cross-workspace pivot)
  DNS_RESOLVE:                'dns-resolve',

  // ─── Feature 7C — Active Vulnerability Scanner ────────────────────────────
  SCANNER_START:              'scanner-start',
  SCANNER_STOP:               'scanner-stop',
  SCANNER_FINDING:            'scanner-finding',           // main -> renderer
  SCANNER_PROGRESS:           'scanner-progress',          // main -> renderer
  SCANNER_COMPLETE:           'scanner-complete',          // main -> renderer
  SCANNER_ERROR:              'scanner-error',             // main -> renderer
  SCANNER_ACTIVITY:           'scanner-activity',           // main -> renderer
  SCANNER_GET_FINDINGS:       'scanner-get-findings',
  SCANNER_EXPORT:             'scanner-export',
  SCANNER_CLEAR:              'scanner-clear',

  // ─── Feature 7D — Manual Testing Utilities ───────────────────────────────────
  REPEATER_SEND:              'repeater-send',
  REPEATER_RESPONSE:          'repeater-response',           // main → renderer
  REPEATER_ERROR:             'repeater-error',              // main → renderer

  INTRUDER_START:             'intruder-start',
  INTRUDER_STOP:              'intruder-stop',
  INTRUDER_RESULT:            'intruder-result',             // main → renderer (one per request)
  INTRUDER_PROGRESS:          'intruder-progress',           // main → renderer
  INTRUDER_COMPLETE:          'intruder-complete',           // main → renderer
  INTRUDER_ERROR:             'intruder-error',              // main → renderer

  SEQUENCER_COLLECT:          'sequencer-collect',
  SEQUENCER_TOKEN:            'sequencer-token',             // main → renderer
  SEQUENCER_ANALYZE:          'sequencer-analyze',
  SEQUENCER_RESULT:           'sequencer-result',            // main → renderer
  SEQUENCER_ERROR:            'sequencer-error',             // main → renderer

  DECODER_TRANSFORM:          'decoder-transform',
  DECODER_RESULT:             'decoder-result',              // main → renderer
};
