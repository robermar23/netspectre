// Basic MAC OUI vendor mappings (extensible fallback)
export const vendorMap = {
  // Apple
  'E4:5F:01': 'Apple, Inc.',
  'D4:61:9D': 'Apple, Inc.',
  '00:25:00': 'Apple, Inc.',
  'F8:FF:C2': 'Apple, Inc.',
  '00:1E:52': 'Apple, Inc.',
  '00:1C:B3': 'Apple, Inc.',
  'BC:6C:21': 'Apple, Inc.',
  
  // Virtual Machines
  '00:0C:29': 'VMware, Inc.',
  '00:50:56': 'VMware, Inc.',
  '08:00:27': 'PCS Systemtechnik (VirtualBox)',
  '00:15:5D': 'Microsoft Corporation (Hyper-V)',

  // Smart Home / Mobile / IoT
  '00:1A:11': 'Google, Inc.',
  '3C:5A:B4': 'Google, Inc.',
  'F4:F5:D8': 'Google, Inc.',
  'CC:B8:A8': 'Samsung Electronics',
  '00:16:32': 'Samsung Electronics',
  '00:24:E4': 'Withings',
  '44:65:0D': 'Amazon Technologies Inc.',
  '18:74:2E': 'Amazon Technologies Inc.',
  'B4:7C:9C': 'Amazon Technologies Inc.',
  'F4:5E:AB': 'Amazon Technologies Inc.',
  '24:18:1D': 'Amazon Technologies Inc.',
  '54:60:09': 'Google, Inc. (Nest)',

  // Gaming Consoles
  '00:24:8D': 'Sony Interactive Entertainment',
  '00:D9:D1': 'Sony Interactive Entertainment',
  '50:1A:A5': 'Microsoft Corporation (Xbox)',

  // Entertainment & IoT
  'B8:AE:6E': 'Nintendo Co., Ltd',
  '84:EA:ED': 'Roku, Inc',
  '84:E6:57': 'Sony Interactive Entertainment Inc.',
  '00:04:4B': 'NVIDIA',
  '64:52:99': 'The Chamberlain Group, Inc',
  '84:BA:3B': 'CANON INC.',

  // Network Gear & PCs
  'AC:84:C6': 'TP-Link Technologies Co.,Ltd',
  '40:ED:00': 'TP-Link Systems Inc',
  '00:14:22': 'Dell Inc.',
  '18:DB:F2': 'Dell Inc.',
  '00:1B:44': 'Intel Corporate',
  'A4:4C:C8': 'Intel Corporate',
  '00:00:0C': 'Cisco Systems, Inc',
  '00:01:42': 'Cisco Systems, Inc',
  '88:E9:FE': 'Cisco Systems, Inc',
  '00:10:5A': 'Acer Inc.',
  '00:11:0A': 'HP Inc.',
  'B8:27:EB': 'Raspberry Pi Foundation',
  'DC:A6:32': 'Raspberry Pi Foundation',
  'E4:5F:01': 'Raspberry Pi Foundation'
};

export const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 548, 993, 995, 1723, 3306, 3389, 5900, 8080
];

// Ports monitored by passive intelligence modules
export const PASSIVE_MONITORED_PORTS = {
  FTP: 21,
  TELNET: 23,
  HTTP: 80,
  POP3: 110,
  IMAP: 143,
  HTTP_ALT: 8080,
};

// Known DHCP options to identify rogue servers
export const DHCP_MESSAGE_TYPES = {
  OFFER: 2,
  ACK: 5,
};

export const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

/**
 * Expand a CIDR notation string into an array of individual IP addresses.
 * Supports /16 through /32. Caps at 65536 addresses for safety.
 * @param {string} cidr - e.g. "192.168.1.0/24"
 * @returns {string[]} Array of IP address strings
 */
export function expandCIDR(cidr) {
  const parts = cidr.trim().split('/');
  if (parts.length !== 2) return [];

  const ipParts = parts[0].split('.').map(Number);
  const prefix = parseInt(parts[1], 10);

  if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) return [];
  if (isNaN(prefix) || prefix < 16 || prefix > 32) return [];

  const ipNum = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
  const hostBits = 32 - prefix;
  const totalHosts = 1 << hostBits;
  const networkAddr = (ipNum >>> hostBits) << hostBits >>> 0;

  const ips = [];
  // Skip network address (first) and broadcast (last) for ranges > /31
  const start = prefix < 31 ? 1 : 0;
  const end = prefix < 31 ? totalHosts - 1 : totalHosts;

  for (let i = start; i < end && ips.length < 65536; i++) {
    const addr = (networkAddr + i) >>> 0;
    ips.push(`${(addr >>> 24) & 0xFF}.${(addr >>> 16) & 0xFF}.${(addr >>> 8) & 0xFF}.${addr & 0xFF}`);
  }
  return ips;
}

// Default SNMP ports
export const SNMP_PORTS = { SNMP: 161, SNMP_TRAP: 162 };

// Standard SNMP community strings to try
export const DEFAULT_COMMUNITIES = ['public', 'private', 'community'];

// Common OID prefixes with human-readable names
export const SNMP_OID_MAP = {
  // System Group
  '1.3.6.1.2.1.1.1': 'sysDescr',
  '1.3.6.1.2.1.1.2': 'sysObjectID',
  '1.3.6.1.2.1.1.3': 'sysUpTime',
  '1.3.6.1.2.1.1.4': 'sysContact',
  '1.3.6.1.2.1.1.5': 'sysName',
  '1.3.6.1.2.1.1.6': 'sysLocation',
  '1.3.6.1.2.1.1.7': 'sysServices',
  
  // Interfaces Group (ifTable)
  '1.3.6.1.2.1.2.2.1.1': 'ifIndex',
  '1.3.6.1.2.1.2.2.1.2': 'ifDescr',
  '1.3.6.1.2.1.2.2.1.3': 'ifType',
  '1.3.6.1.2.1.2.2.1.4': 'ifMtu',
  '1.3.6.1.2.1.2.2.1.5': 'ifSpeed',
  '1.3.6.1.2.1.2.2.1.6': 'ifPhysAddress',
  '1.3.6.1.2.1.2.2.1.7': 'ifAdminStatus',
  '1.3.6.1.2.1.2.2.1.8': 'ifOperStatus',
  '1.3.6.1.2.1.2.2.1.9': 'ifLastChange',
  '1.3.6.1.2.1.2.2.1.10': 'ifInOctets',
  '1.3.6.1.2.1.2.2.1.16': 'ifOutOctets',

  // IP Route Table (ipRouteTable)
  '1.3.6.1.2.1.4.21.1.1': 'ipRouteDest',
  '1.3.6.1.2.1.4.21.1.2': 'ipRouteIfIndex',
  '1.3.6.1.2.1.4.21.1.3': 'ipRouteMetric1',
  '1.3.6.1.2.1.4.21.1.7': 'ipRouteNextHop',
  '1.3.6.1.2.1.4.21.1.8': 'ipRouteType',
  '1.3.6.1.2.1.4.21.1.11': 'ipRouteMask',

  // IP Address Table (ipAddrTable)
  '1.3.6.1.2.1.4.20.1.1': 'ipAdEntAddr',
  '1.3.6.1.2.1.4.20.1.2': 'ipAdEntIfIndex',
  '1.3.6.1.2.1.4.20.1.3': 'ipAdEntNetMask',

  // ARP Table (atTable / ipNetToMediaTable)
  '1.3.6.1.2.1.3.1.1.1': 'atIfIndex',
  '1.3.6.1.2.1.3.1.1.2': 'atPhysAddress',
  '1.3.6.1.2.1.3.1.1.3': 'atNetAddress',
  '1.3.6.1.2.1.4.22.1.1': 'ipNetToMediaIfIndex',
  '1.3.6.1.2.1.4.22.1.2': 'ipNetToMediaPhysAddress',
  '1.3.6.1.2.1.4.22.1.3': 'ipNetToMediaNetAddress',
  '1.3.6.1.2.1.4.22.1.4': 'ipNetToMediaType',

  // Host Resources (hrDeviceTable)
  '1.3.6.1.2.1.25.3.2.1.1': 'hrDeviceIndex',
  '1.3.6.1.2.1.25.3.2.1.2': 'hrDeviceType',
  '1.3.6.1.2.1.25.3.2.1.3': 'hrDeviceDescr',
  '1.3.6.1.2.1.25.3.2.1.5': 'hrDeviceStatus',

  // Hardware/Firmware Entity MIB (entPhysicalTable)
  '1.3.6.1.2.1.47.1.1.1.1.1': 'entPhysicalIndex',
  '1.3.6.1.2.1.47.1.1.1.1.2': 'entPhysicalDescr',
  '1.3.6.1.2.1.47.1.1.1.1.7': 'entPhysicalName',
  '1.3.6.1.2.1.47.1.1.1.1.8': 'entPhysicalHardwareRev',
  '1.3.6.1.2.1.47.1.1.1.1.9': 'entPhysicalFirmwareRev',
  '1.3.6.1.2.1.47.1.1.1.1.10': 'entPhysicalSoftwareRev',
  '1.3.6.1.2.1.47.1.1.1.1.11': 'entPhysicalSerialNum',
  '1.3.6.1.2.1.47.1.1.1.1.12': 'entPhysicalMfgName',
  '1.3.6.1.2.1.47.1.1.1.1.13': 'entPhysicalModelName'
};

// Brute-force target protocols (Hydra service names)
export const BRUTEFORCE_PROTOCOLS = [
  'ssh', 'ftp', 'smb', 'smb2', 'rdp', 'http-get', 'http-post',
  'telnet', 'mysql', 'mssql', 'postgres', 'vnc'
];

// Default credentials for quick-spray (IoT/lab use)
export const DEFAULT_CREDENTIALS = [
  { user: 'admin', pass: 'admin' },
  { user: 'root', pass: 'root' },
  { user: 'admin', pass: 'password' },
  { user: 'root', pass: 'toor' },
  { user: 'cisco', pass: 'cisco' },
];

// Feature 5B — Default credential spray pairs (IoT / network gear)
export const IOT_DEFAULT_CREDENTIALS = [
  { user: 'admin',      pass: 'admin' },
  { user: 'admin',      pass: 'password' },
  { user: 'admin',      pass: '1234' },
  { user: 'admin',      pass: '' },
  { user: 'root',       pass: 'root' },
  { user: 'root',       pass: 'toor' },
  { user: 'root',       pass: '' },
  { user: 'cisco',      pass: 'cisco' },
  { user: 'guest',      pass: 'guest' },
  { user: 'user',       pass: 'user' },
  { user: 'support',    pass: 'support' },
  { user: 'service',    pass: 'service' },
  { user: 'supervisor', pass: 'supervisor' },
  { user: 'ubnt',       pass: 'ubnt' },     // Ubiquiti
  { user: 'pi',         pass: 'raspberry' }, // Raspberry Pi
  { user: 'admin',      pass: 'admin1234' },
  { user: 'admin',      pass: '123456' },
];

export const COMMON_WEB_PATHS = [
  '/admin', '/login', '/logout', '/dashboard', '/api', '/api/v1', '/api/v2',
  '/config', '/configuration', '/setup', '/install', '/backup', '/db',
  '/database', '/debug', '/test', '/dev', '/staging', '/old', '/archive',
  '/uploads', '/upload', '/files', '/file', '/documents', '/docs',
  '/static', '/assets', '/media', '/images', '/img', '/css', '/js',
  '/robots.txt', '/.env', '/.env.local', '/.env.production', '/.git/HEAD',
  '/web.config', '/phpinfo.php', '/info.php', '/server-status', '/server-info',
  '/health', '/healthz', '/status', '/metrics', '/actuator', '/actuator/health',
  '/swagger', '/swagger-ui', '/swagger-ui.html', '/openapi.json', '/api-docs',
  '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes',
  '/administrator', '/admin.php', '/admin.html', '/adminer.php',
  '/phpmyadmin', '/pma', '/myadmin', '/mysql', '/cpanel',
  '/console', '/manager', '/management', '/monitoring',
  '/user', '/users', '/profile', '/account', '/accounts',
  '/register', '/signup', '/forgot-password', '/reset-password',
  '/search', '/sitemap.xml', '/crossdomain.xml', '/security.txt',
];
