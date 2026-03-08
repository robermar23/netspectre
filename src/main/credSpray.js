import { ipRegex, IOT_DEFAULT_CREDENTIALS } from '../shared/networkConstants.js';
import { sprayHttpBasic, sprayHttpForm, sprayTelnet } from './credSprayTransports.js';
import { getSetting } from './store.js';

// Active spray session controller
let activeController = null;

/**
 * Validates and normalizes the options for credential spray.
 */
function validateAndNormalizeCredSprayOpts(rawOpts) {
  if (!rawOpts || !Array.isArray(rawOpts.targets) || rawOpts.targets.length === 0) {
    throw new Error('No targets specified for credential spray.');
  }
  if (!Array.isArray(rawOpts.protocols) || rawOpts.protocols.length === 0) {
    throw new Error('No protocols specified for credential spray.');
  }

  // Fallback to IOT_DEFAULT_CREDENTIALS if none provided
  const credentialsToUse = rawOpts.customCredentials || rawOpts.credentials || (rawOpts.useDefaultCredentials !== false ? IOT_DEFAULT_CREDENTIALS : []);
  
  if (credentialsToUse.length === 0) {
    throw new Error('No credentials provided for spraying.');
  }

  return {
    ...rawOpts,
    credentialsToUse,
    ports: rawOpts.ports || {},
    delayMs: rawOpts.delayMs ?? 200,
    timeoutMs: rawOpts.timeoutMs ?? 5000,
  };
}

/**
 * Resolves the port to use for a given protocol.
 */
function resolvePort(protocol, ports) {
  if (ports && ports[protocol]) return ports[protocol];
  if (protocol === 'telnet') return 23;
  if (protocol === 'http-basic' || protocol === 'http-form') return 80;
  return 80;
}

/**
 * Dispatches the spray task to the appropriate protocol transport.
 */
async function runProtocolSpray(protocol, ip, port, opts, credentialsToUse, signal) {
  const { delayMs, timeoutMs } = opts;

  switch (protocol) {
    case 'http-basic':
      return await sprayHttpBasic(ip, port, credentialsToUse, signal, delayMs, timeoutMs);
    case 'http-form':
      return await sprayHttpForm(ip, port, opts, credentialsToUse, signal, delayMs, timeoutMs);
    case 'telnet':
      return await sprayTelnet(ip, port, credentialsToUse, signal, delayMs, timeoutMs);
    default:
      return [];
  }
}

/**
 * Emits progress to the renderer in the expected format.
 */
function emitProgress(onProgress, state) {
  const { attempts, totalExpectedAttempts, currentIp, currentProtocol, currentPort } = state;
  const percent = Math.floor((attempts / totalExpectedAttempts) * 100);
  
  onProgress({
    tested: attempts,
    total: totalExpectedAttempts,
    percent,
    currentIp,
    currentProtocol,
    currentPort
  });
}

export async function startCredSpray(opts, onHit, onProgress, onComplete, onError) {
  if (activeController) {
    onError(new Error('A credential spray session is already running.'));
    return;
  }
  
  if (!getSetting('pentestConsentAccepted')) {
    onError(new Error('Explicit pentest consent is required before running this tool.'));
    return;
  }

  let normalizedOpts;
  try {
    normalizedOpts = validateAndNormalizeCredSprayOpts(opts);
  } catch (err) {
    onError(err);
    return;
  }
  
  const { credentialsToUse, targets, protocols, ports } = normalizedOpts;
  
  activeController = new AbortController();
  const { signal } = activeController;
  
  let totalHits = 0;
  let attempts = 0;
  const totalTargets = targets.length;
  const totalProtocols = protocols.length;
  const totalPairs = credentialsToUse.length;
  const totalExpectedAttempts = totalTargets * totalProtocols * totalPairs;

  const startTime = Date.now();

  try {
    for (const ip of targets) {
      if (!ipRegex.test(ip)) continue;
      
      let hostHitCount = 0;

      for (const protocol of protocols) {
        if (signal.aborted) throw new Error('Aborted');
        if (normalizedOpts.stopOnFirstHit && hostHitCount > 0) break;
        
        const portToUse = resolvePort(protocol, ports);

        // Emit progress before starting the task
        emitProgress(onProgress, { 
          attempts, 
          totalExpectedAttempts, 
          currentIp: ip, 
          currentProtocol: protocol, 
          currentPort: portToUse 
        });

        const protocolHits = await runProtocolSpray(
          protocol,
          ip,
          portToUse,
          normalizedOpts,
          credentialsToUse,
          signal
        );

        // Every credential tried in runProtocolSpray counts towards attempts
        attempts += totalPairs; 

        for (const hit of protocolHits) {
          totalHits++;
          hostHitCount++;
          onHit({
            target: ip,
            protocol,
            port: portToUse,
            user: hit.user,
            pass: hit.pass,
            evidence: hit.evidence,
            severity: 'critical',
            time: Date.now()
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
    const elapsed = Date.now() - startTime;
    activeController = null;
    onComplete({ hits: totalHits, total: totalExpectedAttempts, elapsed, aborted: wasAborted });
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

import { IPC_CHANNELS } from '../shared/ipc.js';

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.CREDSPRAY_START, async (_event, options) => {
    console.log(`CredSpray requested`);

    if (!options || typeof options !== 'object') {
      return { status: 'error', error: 'Invalid options payload' };
    }

    // startCredSpray is async but we don't await the whole loop here
    startCredSpray(
      options,
      (hit)      => getWindow()?.webContents.send(IPC_CHANNELS.CREDSPRAY_HIT, hit),
      (progress) => getWindow()?.webContents.send(IPC_CHANNELS.CREDSPRAY_PROGRESS, progress),
      (complete) => getWindow()?.webContents.send(IPC_CHANNELS.CREDSPRAY_COMPLETE, complete),
      (err)      => getWindow()?.webContents.send(IPC_CHANNELS.CREDSPRAY_ERROR, err)
    );

    return { status: 'started' };
  });

  ipcMain.handle(IPC_CHANNELS.CREDSPRAY_STOP, async () => {
    console.log('CredSpray stop requested');
    stopCredSpray();
    return { status: 'stopped' };
  });
}
