import net from 'net';
import tls from 'tls';
import { checkAnonymousFtp, checkSensitiveWebDirs } from './securityAnalyzer.js';

// Reduced from 1000 to 150 to prevent aggressive SYN flooding on tiny embedded/IoT network stacks.
const CHUNK_SIZE = 150; 
const TIMEOUT_MS = 2000; // Increased to 2000ms; embedded webservers are often slow under load.
const MAX_PORT = 65535;

const activeScans = new Set();

export function cancelDeepScan(ip) {
  activeScans.delete(ip);
}

/**
 * Attempts a raw TCP connection to read the first packet (Banner Grabbing)
 */
export function grabBanner(ip, port) {
  return new Promise((resolve) => {
    let resolved = false;

    const socket = new net.Socket();
    socket.setTimeout(TIMEOUT_MS);

    const finish = (result) => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(result);
      }
    };

    socket.on('connect', () => {
      // If it's widely known as a web port, proactively send an HTTP GET to coax a response
      // Switched from HEAD to GET. Some older embedded servers outright drop HEAD requests.
      if (port === 80 || port === 8080 || port === 443 || port === 8443 || port === 8000 || port === 5000) {
        socket.write('GET / HTTP/1.0\r\nHost: ' + ip + '\r\nAccept: */*\r\n\r\n');
      }
    });

    socket.on('data', (data) => {
      const banner = data.toString('utf-8').trim();
      finish(banner);
    });

    socket.on('timeout', () => finish(null));
    socket.on('error', () => finish(null));
    
    // Safety fallback
    setTimeout(() => finish(null), TIMEOUT_MS + 200);

    socket.connect(port, ip);
  });
}

/**
 * Extracts TLS/SSL certificate information
 */
export function grabTlsCert(ip, port) {
  return new Promise((resolve) => {
    let resolved = false;

    const finish = (result) => {
      if (!resolved) {
        resolved = true;
        resolve(result);
      }
    };

    // Ignore authorization errors (self-signed certs)
    const socket = tls.connect({ port, host: ip, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      if (cert && Object.keys(cert).length > 0) {
        finish({
          subject: cert.subject ? cert.subject.CN : 'Unknown',
          issuer: cert.issuer ? cert.issuer.CN : 'Unknown',
          validFrom: cert.valid_from,
          validTo: cert.valid_to
        });
      } else {
        finish(null);
      }
      socket.end();
    });

    socket.setTimeout(TIMEOUT_MS + 500); // Handshakes take longer
    socket.on('timeout', () => { socket.destroy(); finish(null); });
    socket.on('error', () => { socket.destroy(); finish(null); });
  });
}

/**
 * Analyzes banner/cert payloads to guess the underlying service.
 */
export function analyzeService(port, banner, tlsCert) {
  let serviceName = 'Unknown TCP Service';
  let details = '';
  let vulnerable = false;
  let severity = 'info'; // info, warning, critical

  if (tlsCert) {
    serviceName = `TLS/SSL Service`;
    let expires = '';
    if (tlsCert.validTo) {
      try {
        const d = new Date(tlsCert.validTo);
        expires = ` | Expiration: ${d.toISOString().split('T')[0]}`;
      } catch (e) { }
    }
    details = `Cert Subject: ${tlsCert.subject} | Issuer: ${tlsCert.issuer}${expires}`;
    return { serviceName, details, vulnerable, severity };
  }

  if (banner) {
    // Try to parse an HTTP Server header
    const serverMatch = banner.match(/Server:\s*(.+)/i);
    if (serverMatch) {
      serviceName = 'HTTP Web Server';
      details = `Server Header: ${serverMatch[1].trim()}`;
      return { serviceName, details, vulnerable, severity };
    }

    // Try SSH
    if (banner.startsWith('SSH-')) {
      serviceName = 'SSH Server';
      details = banner.split('\r')[0];
      return { serviceName, details, vulnerable, severity };
    }

    // Try FTP
    if (banner.match(/FTP|vsFTPd|ProFTPD/i)) {
      serviceName = 'FTP Server';
      details = banner.split('\r')[0];
      return { serviceName, details, vulnerable, severity };
    }

    // Try SMTP
    if (banner.startsWith('220 ')) {
      serviceName = 'SMTP Mail Server';
      details = banner.split('\r')[0];
      return { serviceName, details, vulnerable, severity };
    }

    // Generic fallback for any other text banner
    // Clean out the HTML heavy tags to make it readable in the UI if it's a raw HTTP response.
    let snippet = banner.substring(0, 100).replace(/\n|\r/g, ' ');
    if (snippet.includes('<html') || snippet.includes('HTTP/')) {
       serviceName = 'Web Service (Unrecognized)';
       // If it threw an HTTP 301/302, capture it
       const redirect = banner.match(/Location:\s*(.+)/i);
       if (redirect) {
          details = `Redirects to: ${redirect[1].trim()}`;
       } else {
          details = `HTTP Response Code: ${banner.split(' ')[1] || 'Unknown'}`;
       }
    } else {
       serviceName = 'Custom Service';
       details = `Banner: ${snippet.substring(0, 40)}...`;
    }
    
    return { serviceName, details, vulnerable, severity };
  }

  // Pure port guessing if no payload
  if (port === 22) return { serviceName: 'SSH (Guessed)', details: 'No banner replied', vulnerable, severity };
  if (port === 23) return { serviceName: 'Telnet (Guessed)', details: 'No banner replied', vulnerable: true, severity: 'critical' };
  if (port === 3389) return { serviceName: 'RDP (Guessed)', details: 'No banner replied', vulnerable, severity };
  if (port === 53) return { serviceName: 'DNS (Guessed)', details: 'No banner replied', vulnerable, severity };
  
  // Database Exposure Checks
  if (port === 3306) return { serviceName: 'MySQL (Database)', details: 'DANGEROUS: Port exposed to local subnet.', vulnerable: true, severity: 'critical' };
  if (port === 1433) return { serviceName: 'SQL Server (Database)', details: 'DANGEROUS: Port exposed to local subnet.', vulnerable: true, severity: 'critical' };
  if (port === 27017) return { serviceName: 'MongoDB (Database)', details: 'DANGEROUS: Port exposed to local subnet.', vulnerable: true, severity: 'critical' };
  if (port === 6379) return { serviceName: 'Redis (Cache)', details: 'DANGEROUS: Port exposed to local subnet.', vulnerable: true, severity: 'critical' };
  if (port === 5432) return { serviceName: 'PostgreSQL (Database)', details: 'DANGEROUS: Port exposed to local subnet.', vulnerable: true, severity: 'critical' };

  return { serviceName, details: 'Port is open, but dropped connection before sending data.', vulnerable, severity };
}

/**
 * Main deep scan method. Chunks 65k ports to avoid EMFILE socket limits.
 */
export async function runDeepScan(ip, onPortFoundCallback, onProgressCallback) {
  console.log(`Starting Deep Scan on ${ip}`);
  activeScans.add(ip);

  for (let startPort = 1; startPort <= MAX_PORT; startPort += CHUNK_SIZE) {
    if (!activeScans.has(ip)) {
      console.log(`Deep scan manually cancelled for ${ip}`);
      break;
    }
    const promises = [];
    const endPort = Math.min(startPort + CHUNK_SIZE - 1, MAX_PORT);

    for (let port = startPort; port <= endPort; port++) {
      promises.push((async () => {
        return new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(TIMEOUT_MS);
          
          socket.on('connect', async () => {
            // Port is Open! Time to investigate it.
            
            // Remove error/timeout from original socket so it doesn't fire while we grab banner
            socket.removeAllListeners('error');
            socket.removeAllListeners('timeout');
            socket.destroy(); // Free the fast-scan socket

            // 1. Grab Text Banner
            let banner = await grabBanner(ip, port);
            
            // 2. Look for SSL/TLS if banner fails or looks like garbage bytes
            let cert = null;
            if (!banner || banner.includes('') || port === 443 || port === 8443) {
               cert = await grabTlsCert(ip, port);
            }

            // 3. Analyze Findings
            let analysis = analyzeService(port, banner, cert);

            // 4. Native Forensic Auditing (Proactive Security Probing)
            try {
              if (analysis.serviceName.includes('FTP')) {
                const ftpAudit = await checkAnonymousFtp(ip, port);
                if (ftpAudit && ftpAudit.vulnerable) {
                  analysis.vulnerable = true;
                  analysis.severity = 'critical';
                  analysis.details = ftpAudit.details;
                }
              }

              if (analysis.serviceName.includes('HTTP Web') || analysis.serviceName.includes('TLS')) {
                 const isTls = !!cert || port === 443 || port === 8443;
                 const webAudit = await checkSensitiveWebDirs(ip, port, isTls);
                 if (webAudit && webAudit.vulnerable) {
                   analysis.vulnerable = true;
                   analysis.severity = 'critical';
                   analysis.details += ` | ${webAudit.details}`;
                 }
              }
            } catch (auditErr) {
               console.error(`Audit error on port ${port}:`, auditErr);
            }

            // 5. Stream Results Back
            onPortFoundCallback({
              port,
              serviceName: analysis.serviceName,
              details: analysis.details,
              vulnerable: analysis.vulnerable,
              severity: analysis.severity,
              rawBanner: banner ? banner.substring(0, 100) : null
            });

            resolve();
          });

          // If connection fails, times out, or errors out, move on.
          socket.on('timeout', () => { socket.destroy(); resolve(); });
          socket.on('error', (err) => { socket.destroy(); resolve(); });
          
          socket.connect(port, ip);
        });
      })());
    }

    // Wait for chunk to finish before opening more sockets
    await Promise.all(promises);
    
    if (onProgressCallback) {
      const pct = Math.round((endPort / MAX_PORT) * 100);
      onProgressCallback({ ip, percent: pct });
    }
    
    // Artificial physical delay so the UI pulse finishes visibly, and to give embedded devices breathing room
    await new Promise(r => setTimeout(r, 20));
  }

  activeScans.delete(ip);
  console.log(`Deep Scan completed for ${ip}`);
}
