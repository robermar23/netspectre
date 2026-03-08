import snmp from 'net-snmp';
import { SNMP_OID_MAP, SNMP_PORTS } from '../shared/networkConstants.js';

const activeWalks = new Map();

function createSession(targetIp, options) {
  const version = options.version === 'v3' ? snmp.Version3 : (options.version === 'v1' ? snmp.Version1 : snmp.Version2c);
  
  const sessionOptions = {
    port: SNMP_PORTS.SNMP,
    retries: options.retries !== undefined ? options.retries : 1,
    timeout: options.timeout !== undefined ? options.timeout : 5000,
    transport: 'udp4',
    version
  };

  if (version === snmp.Version3) {
    const user = {
      name: options.user,
      level: snmp.SecurityLevel.noAuthNoPriv
    };

    if (options.authKey) {
      user.level = snmp.SecurityLevel.authNoPriv;
      user.authProtocol = options.authProtocol === 'md5' ? snmp.AuthProtocols.md5 : snmp.AuthProtocols.sha;
      user.authKey = options.authKey;
    }

    if (options.privKey) {
      user.level = snmp.SecurityLevel.authPriv;
      user.privProtocol = options.privProtocol === 'des' ? snmp.PrivProtocols.des : snmp.PrivProtocols.aes;
      user.privKey = options.privKey;
    }
    
    return snmp.createV3Session(targetIp, user, sessionOptions);
  } else {
    return snmp.createSession(targetIp, options.community || 'public', sessionOptions);
  }
}
export function snmpWalk(targetIp, options, onResult, onProgress, onComplete, onError, onIntelligence) {
  if (activeWalks.has(targetIp)) {
    if (onError) onError({ targetIp, error: 'A walk is already in progress for this host.' });
    return false;
  }

  try {
    const session = createSession(targetIp, options);
    activeWalks.set(targetIp, session);

    // MIB-2 Subtree (covers system, interfaces, at, ip, icmp, tcp, udp, egp, and host-resources)
    // We walk 1.3.6.1.2.1 which is the standard internet management subtree
    const rootOid = options.rootOid || '1.3.6.1.2.1'; 
    let oidCount = 0;

    session.walk(rootOid, 20, (varbinds) => {
      if (!activeWalks.has(targetIp)) {
         // Cancelled
         return;
      }
      
      for (let i = 0; i < varbinds.length; i++) {
        if (snmp.isVarbindError(varbinds[i])) {
          console.error(`[SNMP Walk Error] ${snmp.varbindError(varbinds[i])}`);
          continue;
        }

        oidCount++;
        const oid = Array.isArray(varbinds[i].oid) ? varbinds[i].oid.join('.') : varbinds[i].oid;
        
        // Find best matching name from map, or use numerical
        // For table entries, we want to match the prefix
        let name = oid;
        let tableIndex = '';
        
        for (const [prefix, mapName] of Object.entries(SNMP_OID_MAP)) {
          if (oid === prefix) {
            name = mapName;
            break;
          } else if (oid.startsWith(prefix + '.')) {
            name = mapName;
            tableIndex = oid.substring(prefix.length + 1);
            break;
          }
        }

        let val = varbinds[i].value;
        if (Buffer.isBuffer(val)) {
          // Attempt to convert buffer to string or hex depending on apparent content
          // This is a naive heuristic: if it looks like all ASCII printable, string it.
          // Otherwise, hex it (like MAC addresses).
          let isAscii = true;
          for (let b of val) {
            if (b < 32 || b > 126) { isAscii = false; break; }
          }
          if (isAscii && val.length > 0) {
             val = val.toString('utf8');
          } else {
             // Hex format often used for MACs (e.g. 00:1A:2B:...)
             val = val.toString('hex').match(/.{1,2}/g)?.join(':') || '';
          }
        }

        // --- SNMP Intelligence Extraction ---
        if (onIntelligence) {
          extractIntelligence({ oid, val, targetIp, onIntelligence });
        }

        if (onResult) {
          onResult({ targetIp, oid, name, tableIndex, value: val, type: varbinds[i].type });
        }
      }

      if (onProgress && oidCount % 50 === 0) {
        onProgress({ targetIp, count: oidCount });
      }

    }, (error) => {
      activeWalks.delete(targetIp);
      if (error) {
        if (error.message && error.message.includes('Request timed out')) {
           if (onError) onError({ targetIp, error: 'Timeout: Host did not respond, or community/credentials incorrect.' });
        } else {
           if (onError) onError({ targetIp, error: error.message || 'Walk aborted with error' });
        }
      } else {
        if (onComplete) onComplete({ targetIp, totalOids: oidCount });
      }
    });

    return true;
  } catch (err) {
    activeWalks.delete(targetIp);
    if (onError) onError({ targetIp, error: err.message });
    return false;
  }
}

/**
 * --- Intelligence Helpers ---
 */
export function parseSysDescr(val) {
  let osVal = val;
  let vendorVal = '';

  if (val.includes('Hardware:') && val.includes('Software:')) {
    const parts = val.split(' - Software: ');
    vendorVal = parts[0].replace('Hardware: ', '').trim();
    if (parts.length > 1) {
      osVal = parts[1].trim();
    }
  }

  return { os: osVal, vendor: vendorVal };
}

function oidToIPv4(oid) {
  const parts = oid.split('.');
  if (parts.length < 4) return '';
  return parts.slice(-4).join('.');
}

export function extractIntelligence({ oid, val, targetIp, onIntelligence }) {
  if (!onIntelligence) return;

  if (oid === '1.3.6.1.2.1.1.1.0') { // sysDescr
    const { os, vendor } = parseSysDescr(val);
    onIntelligence({ type: 'os', targetIp, value: os });
    if (vendor) {
      onIntelligence({ type: 'vendor', targetIp, value: vendor });
    }
  } else if (oid === '1.3.6.1.2.1.1.5.0') { // sysName
    onIntelligence({ type: 'hostname', targetIp, value: val });
  } else if (oid.startsWith('1.3.6.1.2.1.4.22.1.2.') || oid.startsWith('1.3.6.1.2.1.3.1.1.2.')) { 
    // ipNetToMediaPhysAddress (Standard) or atPhysAddress (Legacy/Windows)
    const discoveredIp = oidToIPv4(oid);
    if (discoveredIp && val && !val.includes('00:00:00:00:00:00') && !val.includes('ff:ff:ff:ff:ff:ff')) {
       onIntelligence({ type: 'arp-discovery', targetIp, discoveredIp, discoveredMac: val });
    }
  } else if (oid.startsWith('1.3.6.1.2.1.25.4.2.1.2.')) {
    // hrSWRunName (Running Processes)
    if (val && typeof val === 'string' && val.trim().length > 0) {
       onIntelligence({ type: 'process-discovery', targetIp, processName: val.trim() });
    }
  } else if (oid.startsWith('1.3.6.1.2.1.4.21.1.1.')) {
    // ipRouteDest (Routing Table IPv4 Destinations)
    const destIp = oidToIPv4(oid);
    if (destIp && !['0.0.0.0', '127.0.0.0', '127.0.0.1'].includes(destIp)) {
       onIntelligence({ type: 'route-discovery', targetIp, routeIp: destIp });
    }
  }
}

export function snmpGet(targetIp, oids, options) {
  return new Promise((resolve, reject) => {
    try {
      const session = createSession(targetIp, options);
      
      session.get(oids, (error, varbinds) => {
        session.close();
        if (error) {
          reject(error);
        } else {
          const results = [];
          for (let i = 0; i < varbinds.length; i++) {
            if (snmp.isVarbindError(varbinds[i])) {
              results.push({ oid: oids[i], error: snmp.varbindError(varbinds[i]) });
            } else {
              let val = varbinds[i].value;
              if (Buffer.isBuffer(val)) val = val.toString('utf8');
              results.push({ oid: varbinds[i].oid.join('.'), value: val });
            }
          }
          resolve(results);
        }
      });
    } catch (err) {
      reject(err);
    }
  });
}

export function cancelSnmpWalk(targetIp) {
  const session = activeWalks.get(targetIp);
  if (session) {
    session.close();
    activeWalks.delete(targetIp);
    return true;
  }
  return false;
}
