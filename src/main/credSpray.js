import { ipRegex } from '../shared/networkConstants.js';
import { sprayHttpBasic, sprayHttpForm, sprayTelnet } from './credSprayTransports.js';
import { getSetting } from './store.js';

// Active spray session controller
let activeController = null;

export async function startCredSpray(opts, onHit, onProgress, onComplete, onError) {
  if (activeController) {
    onError(new Error('A credential spray session is already running.'));
    return;
  }
  
  if (!getSetting('pentestConsentAccepted')) {
    onError(new Error('Explicit pentest consent is required before running this tool.'));
    return;
  }
  
  // Validate basic options
  if (!opts || !Array.isArray(opts.targets) || opts.targets.length === 0) {
    onError(new Error('No targets specified for credential spray.'));
    return;
  }
  
  if (!Array.isArray(opts.protocols) || opts.protocols.length === 0) {
    onError(new Error('No protocols specified for credential spray.'));
    return;
  }
  
  const credentialsToUse = opts.customCredentials || opts.credentials || [];
  if (credentialsToUse.length === 0) {
    onError(new Error('No credentials provided for spraying.'));
    return;
  }
  
  activeController = new AbortController();
  const { signal } = activeController;
  
  let totalHits = 0;
  let attempts = 0;
  const totalTargets = opts.targets.length;
  const totalProtocols = opts.protocols.length;
  const totalPairs = credentialsToUse.length;
  const totalExpectedAttempts = totalTargets * totalProtocols * totalPairs;

  try {
    for (const ip of opts.targets) {
      if (!ipRegex.test(ip)) continue;
      
      let hostHitCount = 0;

      for (const protocol of opts.protocols) {
        if (signal.aborted) throw new Error('Aborted');
        if (opts.stopOnFirstHit && hostHitCount > 0) break; // Skip other protocols on this host if a hit was found and setting is enabled
        
        let protocolHits = [];
        const portToUse = opts.ports[protocol] || (protocol === 'telnet' ? 23 : 80);

        // Progress emission wrapper
        onProgress({ attempt: attempts++, total: totalExpectedAttempts, currentIp: ip, currentProtocol: protocol, currentPort: portToUse });

        switch (protocol) {
          case 'http-basic': {
            protocolHits = await sprayHttpBasic(ip, portToUse, credentialsToUse, signal, opts.delayMs, opts.timeoutMs);
            break;
          }
          case 'http-form': {
            protocolHits = await sprayHttpForm(ip, portToUse, opts, credentialsToUse, signal, opts.delayMs, opts.timeoutMs);
            break;
          }
          case 'telnet': {
             protocolHits = await sprayTelnet(ip, portToUse, credentialsToUse, signal, opts.delayMs, opts.timeoutMs);
             break;
          }
          // Note: SSH would require hydra or ssh2 module, leaving out for minimum Phase 5B
        }

        for (const hit of protocolHits) {
           totalHits++;
           hostHitCount++;
           onHit({
             ip,
             protocol,
             port: portToUse,
             user: hit.user,
             pass: hit.pass,
             evidence: hit.evidence,
             severity: 'critical' // Default credentials are a critical finding
           });
        }
      }
    }
  } catch (err) {
    if (err.message !== 'Aborted') {
      onError(err);
    }
  } finally {
    const wasAborted = signal.aborted;
    activeController = null;
    onComplete({ hits: totalHits, aborted: wasAborted });
  }
}

export function stopCredSpray() {
  if (activeController) {
    activeController.abort();
    activeController = null;
  }
}

export function cleanupCredSpray() {
  stopCredSpray();
}
