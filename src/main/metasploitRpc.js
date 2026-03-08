/**
 * Metasploit RPC Integration Module
 *
 * HTTP JSON-RPC client connecting to a local `msfrpcd` daemon.
 * Uses Node.js http/https modules — no external npm dependency required.
 *
 * Security:
 * - Connection defaults to 127.0.0.1 (non-localhost triggers warning)
 * - Auth token stored only in memory, never persisted to disk
 * - All inputs validated before RPC calls
 */

import http from 'http';
import https from 'https';
import { ipRegex } from '../shared/networkConstants.js';

// ─── Connection State ────────────────────────────────────────────────────────

/** @enum {string} */
const MSF_STATES = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  ERROR: 'error',
};

/** Module-scope connection state */
let state = MSF_STATES.DISCONNECTED;
let authToken = null;
let connectionConfig = null;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Send a JSON-RPC request to the msfrpcd daemon.
 * @param {string} method - The RPC method name (e.g. 'auth.login')
 * @param {Array} params - Ordered parameters array
 * @returns {Promise<object>} Parsed JSON response
 */
function rpcCall(method, params = []) {
  return new Promise((resolve, reject) => {
    if (!connectionConfig) {
      reject(new Error('Not connected to Metasploit RPC'));
      return;
    }

    const body = JSON.stringify({
      jsonrpc: '2.0',
      method,
      id: Date.now(),
      params,
    });

    const transport = connectionConfig.ssl ? https : http;

    const options = {
      hostname: connectionConfig.host,
      port: connectionConfig.port,
      path: '/api/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 15000,
      // Allow self-signed certs in dev/lab environments
      rejectUnauthorized: false,
    };

    const req = transport.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) {
            reject(new Error(parsed.error.message || 'RPC error'));
          } else {
            resolve(parsed);
          }
        } catch (e) {
          reject(new Error(`Failed to parse RPC response: ${e.message}`));
        }
      });
    });

    req.on('error', (err) => {
      reject(new Error(`RPC connection error: ${err.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('RPC request timed out (15s)'));
    });

    req.write(body);
    req.end();
  });
}

/**
 * Validate connection options.
 * @param {object} opts
 * @returns {{ valid: boolean, error?: string, warning?: string }}
 */
function validateConnectOptions(opts) {
  if (!opts || typeof opts !== 'object') {
    return { valid: false, error: 'Invalid connection options' };
  }

  const host = (opts.host || '').trim();
  if (!host) {
    return { valid: false, error: 'Host is required' };
  }

  // Check if host looks like an IP; if so, validate format
  if (ipRegex.test(host) || host === 'localhost') {
    // Valid
  } else if (/^[a-zA-Z0-9.-]+$/.test(host)) {
    // Hostname format, allow it
  } else {
    return { valid: false, error: 'Invalid host format' };
  }

  const port = parseInt(opts.port, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    return { valid: false, error: 'Port must be between 1 and 65535' };
  }

  if (!opts.password) {
    return { valid: false, error: 'Password is required' };
  }

  // Security warning for non-localhost connections
  let warning = null;
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    warning = 'Connecting to a non-localhost msfrpcd daemon. Ensure the connection is secure and authorized.';
  }

  return { valid: true, warning };
}

/**
 * Validate exploit execution options.
 * @param {object} opts
 * @returns {{ valid: boolean, error?: string }}
 */
function validateExploitOptions(opts) {
  if (!opts || typeof opts !== 'object') {
    return { valid: false, error: 'Invalid exploit options' };
  }

  if (!opts.modulePath || typeof opts.modulePath !== 'string') {
    return { valid: false, error: 'Module path is required' };
  }

  // Sanitize: module path must look like a valid MSF module path
  if (!/^[a-zA-Z0-9_/.-]+$/.test(opts.modulePath)) {
    return { valid: false, error: 'Module path contains invalid characters' };
  }

  if (!opts.targetIp || !ipRegex.test(opts.targetIp)) {
    return { valid: false, error: 'Valid target IP is required' };
  }

  if (opts.targetPort) {
    const port = parseInt(opts.targetPort, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      return { valid: false, error: 'Target port must be between 1 and 65535' };
    }
  }

  return { valid: true };
}

// ─── Exported Functions ──────────────────────────────────────────────────────

/**
 * Connect to a Metasploit RPC daemon.
 * @param {{ host: string, port: number, username?: string, password: string, ssl?: boolean }} opts
 * @returns {Promise<{ status: string, warning?: string }>}
 */
export async function msfConnect(opts) {
  if (state === MSF_STATES.CONNECTED) {
    throw new Error('Already connected to Metasploit RPC. Disconnect first.');
  }

  const validation = validateConnectOptions(opts);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  state = MSF_STATES.CONNECTING;
  connectionConfig = {
    host: (opts.host || '127.0.0.1').trim(),
    port: parseInt(opts.port, 10) || 55553,
    ssl: !!opts.ssl,
  };

  try {
    const username = (opts.username || 'msf').trim();
    const result = await rpcCall('auth.login', [username, opts.password]);

    if (result && result.token) {
      authToken = result.token;
      state = MSF_STATES.CONNECTED;
      console.log('[MetasploitRPC] Connected successfully');
      return { status: 'connected', warning: validation.warning || null };
    }

    // Some MSF versions return result: 'success' with token elsewhere
    if (result && result.result === 'success') {
      authToken = result.token || `msf-${Date.now()}`;
      state = MSF_STATES.CONNECTED;
      console.log('[MetasploitRPC] Connected successfully');
      return { status: 'connected', warning: validation.warning || null };
    }

    throw new Error('Authentication failed: no token received');
  } catch (err) {
    state = MSF_STATES.ERROR;
    authToken = null;
    throw err;
  }
}

/**
 * Disconnect from the Metasploit RPC daemon.
 * @returns {Promise<{ status: string }>}
 */
export async function msfDisconnect() {
  if (state !== MSF_STATES.CONNECTED || !authToken) {
    state = MSF_STATES.DISCONNECTED;
    authToken = null;
    connectionConfig = null;
    return { status: 'disconnected' };
  }

  try {
    await rpcCall('auth.logout', [authToken]);
  } catch (err) {
    console.warn('[MetasploitRPC] Logout RPC call failed (ignoring):', err.message);
  }

  authToken = null;
  connectionConfig = null;
  state = MSF_STATES.DISCONNECTED;
  console.log('[MetasploitRPC] Disconnected');
  return { status: 'disconnected' };
}

/**
 * Search for exploit modules.
 * @param {string} searchQuery - Search terms (e.g., 'smb', 'ms17-010')
 * @returns {Promise<Array<{ name: string, fullname: string, description: string, rank: string, date: string }>>}
 */
export async function msfListExploits(searchQuery) {
  if (state !== MSF_STATES.CONNECTED || !authToken) {
    throw new Error('Not connected to Metasploit RPC');
  }

  if (!searchQuery || typeof searchQuery !== 'string' || searchQuery.trim().length === 0) {
    throw new Error('Search query is required');
  }

  // Sanitize search query: allow alphanumeric, spaces, hyphens, underscores, dots
  const sanitized = searchQuery.trim().replace(/[^a-zA-Z0-9 \-_.]/g, '');
  if (!sanitized) {
    throw new Error('Search query contains only invalid characters');
  }

  const result = await rpcCall('module.search', [authToken, sanitized]);

  // Normalize to array of module descriptors
  if (Array.isArray(result)) {
    return result.map(mod => ({
      name: mod.name || '',
      fullname: mod.fullname || mod.name || '',
      description: mod.description || mod.desc || '',
      rank: mod.rank || 'unknown',
      date: mod.disclosure_date || mod.date || '',
      type: mod.type || 'exploit',
    }));
  }

  return [];
}

/**
 * Execute an exploit module.
 * @param {{ modulePath: string, targetIp: string, targetPort?: number, payload?: string, options?: object }} opts
 * @returns {Promise<object>} Job/session result
 */
export async function msfRunExploit(opts) {
  if (state !== MSF_STATES.CONNECTED || !authToken) {
    throw new Error('Not connected to Metasploit RPC');
  }

  const validation = validateExploitOptions(opts);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  // Build MSF module options
  const moduleOpts = {
    RHOSTS: opts.targetIp,
    ...(opts.targetPort ? { RPORT: String(opts.targetPort) } : {}),
    ...(opts.payload ? { PAYLOAD: opts.payload } : {}),
  };

  // Merge any additional options (sanitize keys)
  if (opts.options && typeof opts.options === 'object') {
    for (const [key, val] of Object.entries(opts.options)) {
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) && typeof val === 'string') {
        moduleOpts[key] = val;
      }
    }
  }

  console.log(`[MetasploitRPC] Running exploit: ${opts.modulePath} against ${opts.targetIp}`);

  const result = await rpcCall('module.execute', [
    authToken,
    'exploit',
    opts.modulePath,
    moduleOpts,
  ]);

  return {
    jobId: result?.job_id ?? null,
    uuid: result?.uuid ?? null,
    raw: result,
  };
}

/**
 * List active Metasploit sessions.
 * @returns {Promise<Array<{ id: string, type: string, info: string, target: string, via: string }>>}
 */
export async function msfGetSessions() {
  if (state !== MSF_STATES.CONNECTED || !authToken) {
    throw new Error('Not connected to Metasploit RPC');
  }

  const result = await rpcCall('session.list', [authToken]);

  // MSF returns sessions as { "1": { ... }, "2": { ... } }
  if (result && typeof result === 'object' && !Array.isArray(result)) {
    return Object.entries(result).map(([id, sess]) => ({
      id,
      type: sess.type || 'unknown',
      info: sess.info || '',
      target: sess.target_host || sess.session_host || '',
      port: sess.session_port || '',
      via: sess.via_exploit || '',
      platform: sess.platform || '',
    }));
  }

  return [];
}

/**
 * Get the current MSF connection status.
 * @returns {{ state: string, host?: string, port?: number }}
 */
export function getMsfStatus() {
  return {
    state,
    host: connectionConfig?.host || null,
    port: connectionConfig?.port || null,
  };
}

/**
 * Cleanup on app shutdown — disconnect if connected.
 */
export async function cleanupMsf() {
  if (state === MSF_STATES.CONNECTED) {
    try {
      await msfDisconnect();
    } catch (_) { /* ignore */ }
  }
  authToken = null;
  connectionConfig = null;
  state = MSF_STATES.DISCONNECTED;
}

import { IPC_CHANNELS } from '#shared/ipc.js';

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.MSF_CONNECT, async (event, options) => {
    console.log(`MSF connect requested to ${options?.host}:${options?.port}`);
    if (!options || typeof options !== 'object') {
      return { status: 'error', error: 'Invalid options payload' };
    }
    try {
      const result = await msfConnect(options);
      getWindow()?.webContents.send(IPC_CHANNELS.MSF_STATUS, { state: 'connected', ...result });
      return result;
    } catch (err) {
      getWindow()?.webContents.send(IPC_CHANNELS.MSF_ERROR, { message: err.message });
      return { status: 'error', error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.MSF_DISCONNECT, async () => {
    console.log('MSF disconnect requested');
    try {
      const result = await msfDisconnect();
      getWindow()?.webContents.send(IPC_CHANNELS.MSF_STATUS, { state: 'disconnected' });
      return result;
    } catch (err) {
      return { status: 'error', error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.MSF_LIST_EXPLOITS, async (event, query) => {
    console.log(`MSF exploit search: ${query}`);
    try {
      const exploits = await msfListExploits(query);
      return { status: 'success', exploits };
    } catch (err) {
      getWindow()?.webContents.send(IPC_CHANNELS.MSF_ERROR, { message: err.message });
      return { status: 'error', error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.MSF_RUN_EXPLOIT, async (event, options) => {
    console.log(`MSF run exploit: ${options?.modulePath} against ${options?.targetIp}`);
    if (!options || typeof options !== 'object') {
      return { status: 'error', error: 'Invalid exploit options' };
    }
    try {
      const result = await msfRunExploit(options);
      getWindow()?.webContents.send(IPC_CHANNELS.MSF_RESULT, result);
      return { status: 'started', ...result };
    } catch (err) {
      getWindow()?.webContents.send(IPC_CHANNELS.MSF_ERROR, { message: err.message });
      return { status: 'error', error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.MSF_SESSION_LIST, async () => {
    try {
      const sessions = await msfGetSessions();
      return { status: 'success', sessions };
    } catch (err) {
      getWindow()?.webContents.send(IPC_CHANNELS.MSF_ERROR, { message: err.message });
      return { status: 'error', error: err.message };
    }
  });
}
