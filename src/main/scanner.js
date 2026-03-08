import { spawn, exec } from 'child_process';
import net from 'net';
import ping from 'ping';
import os from 'os';
import https from 'https';
import { promises as dnsPromises } from 'dns';
import { vendorMap, COMMON_PORTS } from '#shared/networkConstants.js';

let scanActive = false;

// Basic MAC OUI vendor mappings moved to shared/networkConstants.js

// In-memory cache for dynamic MAC API lookups
const ouiCache = { ...vendorMap };

// Queue system to prevent MAC API rate limiting (max 1 req/sec)
const apiQueue = [];
let isApiFetching = false;

function fetchMacVendorAPI(oui) {
  return new Promise((resolve) => {
    https.get(`https://api.macvendors.com/${oui}`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(data.trim());
        } else {
          resolve('Unknown');
        }
      });
    }).on('error', () => {
      resolve('Unknown');
    });
  });
}

async function processApiQueue() {
  if (isApiFetching || apiQueue.length === 0) return;
  isApiFetching = true;

  while (apiQueue.length > 0) {
    const { oui, resolve } = apiQueue.shift();
    
    // Check if another request fulfilled this while we waited
    if (ouiCache[oui] && ouiCache[oui] !== 'Unknown') {
      resolve(ouiCache[oui]);
      continue;
    }

    try {
      const vendorName = await fetchMacVendorAPI(oui);
      ouiCache[oui] = vendorName;
      resolve(vendorName);
    } catch {
      resolve('Unknown');
    }

    // Required 1.2s delay to dodge macvendors.com 429 Rate Limits
    await new Promise(r => setTimeout(r, 1200)); 
  }

  isApiFetching = false;
}

// Common Ports moved to shared/networkConstants.js

/**
 * Gets a list of available IPv4 network interfaces and their CIDR subnets.
 * Returns an array of objects: { name, ip, subnet, label }
 */
export function getNetworkInterfaces() {
  const interfaces = os.networkInterfaces();
  const results = [];
  
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (!iface.internal && iface.family === 'IPv4') {
        const parts = iface.address.split('.');
        parts.pop();
        const subnet = parts.join('.') + '.';
        results.push({
          name: name,
          ip: iface.address,
          subnet: subnet,
          label: `${name} - ${iface.address}`
        });
      }
    }
  }
  return results;
}

/**
 * Gets the current machine's primary IPv4 subnet.
 * Simplistic approach: assumes /24 subnet for local scanning.
 */
function getLocalSubnet() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (!iface.internal && iface.family === 'IPv4') {
        const parts = iface.address.split('.');
        parts.pop();
        return parts.join('.') + '.';
      }
    }
  }
  return '192.168.1.';
}

/**
 * Parses ARP table for MAC addresses based on OS.
 */
export function getArpTable() {
  return new Promise((resolve) => {
    exec('arp -a', (err, stdout) => {
      if (err) {
        resolve({});
        return;
      }
      
      const arpMap = {};
      const lines = stdout.split('\n');
      
      lines.forEach(line => {
        // Windows arp -a format matching
        let match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+/);
        if (!match) {
          // Linux/Mac format matching
          match = line.match(/(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})/);
        }
        
        if (match) {
          const ip = match[1];
          const mac = match[2].replace(/-/g, ':').toUpperCase();
          if (mac !== 'FF:FF:FF:FF:FF:FF') {
             arpMap[ip] = mac;
          }
        }
      });
      resolve(arpMap);
    });
  });
}

async function getVendorFromMac(mac) {
  if (!mac || mac === 'Unknown') return 'Unknown';
  
  const oui = mac.substring(0, 8).toUpperCase();
  
  // 1. Check local memory cache (which includes the hardcoded fallbacks)
  if (ouiCache[oui] && ouiCache[oui] !== 'Unknown') {
    return ouiCache[oui];
  }

  // 2. Queue for Live API Resolution if missing
  return new Promise((resolve) => {
    apiQueue.push({ oui, resolve });
    processApiQueue();
  });
}

/**
 * Scans a specific IP for common open ports.
 * Multithreaded via async Promises.
 */
async function scanPorts(ip) {
  const openPorts = [];
  
  const checkPort = (port) => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(300); // 300ms timeout for fast scanning
      
      socket.on('connect', () => {
        openPorts.push(port);
        socket.destroy();
        resolve();
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve();
      });
      
      socket.on('error', () => {
        socket.destroy();
        resolve();
      });
      
      socket.connect(port, ip);
    });
  };

  if(!scanActive) return [];

  // Concurrently scan all common ports
  const promises = COMMON_PORTS.map(port => checkPort(port));
  await Promise.all(promises);
  
  return openPorts.sort((a,b) => a - b);
}

/**
 * Advanced OS Fingerprinting combining Port Heuristics + Vendor OUI
 */
export function guessOS(ports, vendor) {
  const p = new Set(ports);

  // 1. Definitives based on distinct port signatures
  if (p.has(3389) || p.has(135) || p.has(139) || p.has(445)) {
    return 'Windows';
  }
  
  if (p.has(548) || (vendor === 'Apple, Inc.' && p.has(5900))) {
    return 'macOS';
  }

  // 2. Vendor Overrides
  if (vendor === 'Apple, Inc.') return 'iOS / macOS';
  if (vendor === 'Samsung Electronics' || vendor === 'Google, Inc.') return 'Android / ChromeOS';
  if (vendor === 'Raspberry Pi Foundation') return 'Linux (Raspbian)';
  
  // 3. Fallbacks
  if (p.has(22)) {
    return 'Linux / Unix';
  }

  return 'Unknown OS';
}

/**
 * Main Network Scanner Orchestrator
 * @param {string} subnet
 * @param {Function} onHostFoundCallback 
 * @param {Function} onCompleteCallback 
 */
export async function startNetworkScan(subnet, onHostFoundCallback, onCompleteCallback) {
  if (scanActive) return;
  scanActive = true;
  
  console.log(`Starting scan on subnet: ${subnet}0/24`);

  // Phase 1: Ping Sweep (Fast concurrent sweeps)
  const activeIps = [];
  const pingPromises = [];

  for (let i = 1; i < 255; i++) {
    if(!scanActive) break;
    const targetIp = subnet + i;
    
    // Spawn ping asynchronously
    pingPromises.push(
      ping.promise.probe(targetIp, { timeout: 1 }).then(res => {
        if (res.alive) activeIps.push(targetIp);
      })
    );
  }

  await Promise.all(pingPromises);
  if (!scanActive) return;

  // Phase 2: Resolve MACs from ARP Table
  const arpTable = await getArpTable();

  // Phase 3: Deep Scan Active Hosts Concurrently (Ports, Hostnames, OS)
  const hostPromises = activeIps.map(async (ip) => {
    if (!scanActive) return;

    let hostname = 'Unknown';
    try {
      let hostnames = await dnsPromises.reverse(ip);
      if (hostnames && hostnames.length > 0) hostname = hostnames[0];
    } catch(e) {} // DNS Reverse failure is common/expected

    const mac = arpTable[ip] || null;
    
    // Phase 4: Identify Vendor & Scan Ports concurrently
    const [vendor, ports] = await Promise.all([
      getVendorFromMac(mac),
      scanPorts(ip)
    ]);
    
    const gOS = guessOS(ports, vendor);

    const hostData = {
      ip,
      mac,
      hostname,
      vendor,
      os: gOS,
      ports
    };

    if (scanActive) {
      onHostFoundCallback(hostData);
    }
  });

  await Promise.all(hostPromises);

  if (scanActive) {
    scanActive = false;
    onCompleteCallback({ message: `Scan complete. Found ${activeIps.length} active hosts.` });
  }
}

export function stopNetworkScan() {
  scanActive = false;
}

/**
 * Shared logic to enrich a host with details like OS, hostname, mac, vendor, ports
 * @param {string} ip - IP address to enrich
 * @param {Object} options - Options context containing optional pre-fetched data (like arpTable)
 * @returns {Object} Extracted network data for the host
 */
export async function enrichHost(ip, options = {}) {
  const result = { ip };

  // Reverse DNS
  try {
    const hostnames = await dnsPromises.reverse(ip);
    if (hostnames && hostnames.length > 0) result.hostname = hostnames[0];
  } catch {}

  // ARP & Vendor
  try {
    const table = options.arpTable || await getArpTable();
    if (table[ip]) {
      result.mac = table[ip];
      result.vendor = await getVendorFromMac(result.mac);
    }
  } catch {}

  // Port scan (skippable for known hosts on lightweight monitor cycles)
  if (!options.skipPorts) {
    try {
      result.ports = await scanPorts(ip);
    } catch {
      result.ports = [];
    }
  }

  // OS guess
  result.os = guessOS(result.ports || [], result.vendor || 'Unknown');

  return result;
}

/**
 * Probe a single host to enrich it with discovery data.
 * Runs the same pipeline as network discovery: ping, reverse DNS, ARP, ports, vendor, OS.
 * @param {string} ip - Host IP to probe
 * @returns {Object} Enriched host data
 */
export async function probeHost(ip) {
  let pingData = { alive: false };

  // Ping
  try {
    const pingRes = await ping.promise.probe(ip, { timeout: 2 });
    pingData.alive = pingRes.alive;
    pingData.pingTime = pingRes.time;
  } catch {}

  // Enhance
  const enriched = await enrichHost(ip);
  return { ...enriched, ...pingData };
}
