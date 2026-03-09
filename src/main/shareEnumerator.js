/**
 * shareEnumerator.js
 * SMB/NFS Share Enumeration — Phase 4D
 *
 * Enumerates SMB shares via smbclient and NFS exports via showmount.
 * Supports null sessions, authenticated sessions, directory browsing,
 * and file download to a user-chosen local path.
 *
 * Security controls:
 *  - All IPC payloads validated (IP regex, share name allowlist regex, path traversal check)
 *  - spawn() called with arg arrays — never shell string concatenation
 *  - Credentials never logged or persisted beyond the call lifetime
 *  - Active processes tracked in a Map for forced cleanup on exit
 */

import { spawn } from 'child_process';
import { getSetting, resolvePython } from './store.js';
import { ipRegex } from '#shared/networkConstants.js';

// ---- Active process registry ----------------------------------------
const activeProcesses = new Map();

// ---- Path resolution ------------------------------------------------
function getSmbclientPath() {
  return getSetting('smbclient.path') || 'smbclient';
}

function getShowmountPath() {
  return getSetting('showmount.path') || 'showmount';
}

// ---- Input validation -----------------------------------------------

/** SMB share names: letters, digits, underscore, hyphen, dollar (admin shares) */
const SHARE_NAME_RE = /^[a-zA-Z0-9_\-$]{1,80}$/;

function isValidShareName(name) {
  return SHARE_NAME_RE.test(name);
}

function isValidRemotePath(remotePath) {
  if (!remotePath) return true;
  const norm = remotePath.replace(/\\/g, '/');
  return !norm.includes('../') && !norm.includes('..');
}



// ---- Helper -----------------------------------------------------------
// ---- Helper -----------------------------------------------------------
function isImpacket() {
  const p = getSmbclientPath().toLowerCase();
  const base = p.split(/[/\\]/).pop() || '';
  return base.includes('impacket-smbclient') || base.includes('smbclient.py');
}

/**
 * Build the connection spec for Impacket: [domain/]user[:pass]@host
 */
function buildImpacketConnectionSpec(targetIp, credentials) {
  let user = '';
  let pass = '';
  let domain = '';

  if (credentials && credentials.username) {
    user = String(credentials.username).replace(/[%"]/g, '');
    pass = String(credentials.password || '').replace(/[%"]/g, '');
    if (credentials.domain) {
      domain = String(credentials.domain).replace(/[^a-zA-Z0-9._-]/g, '');
    }
  }

  if (!user) return [`""@${targetIp}`];

  const prefix = domain ? `${domain}/${user}` : user;
  const auth = pass ? `${prefix}:${pass}` : prefix;
  return [`${auth}@${targetIp}`];
}

/**
 * Build the credential args for standard smbclient: -U user%pass or -N
 */
function buildSmbclientCredArgs(credentials) {
  const args = [];
  if (credentials && credentials.username) {
    const user = String(credentials.username).replace(/[%"]/g, '');
    const pass = String(credentials.password || '').replace(/[%"]/g, '');
    args.push('-U', `${user}%${pass}`);
    if (credentials.domain) {
      const domain = String(credentials.domain).replace(/[^a-zA-Z0-9._-]/g, '');
      args.push('--workgroup', domain);
    }
  } else {
    args.push('-N');
  }
  return args;
}

/**
 * Centralized helper to spawn the appropriate SMB tool.
 */
async function spawnSmbTool({ targetIp, credentials, baseArgs, impacketCmd, timeoutMs, key }) {
  const smbPath = getSmbclientPath();
  const impacketMode = isImpacket();

  let args = [...baseArgs];

  if (impacketMode) {
    args = [...buildImpacketConnectionSpec(targetIp, credentials)];
    if (!credentials || !credentials.password) args.push('-no-pass');
  }

  const isPython = smbPath.toLowerCase().endsWith('.py');
  const pyInterpreter = isPython ? await resolvePython() : ''; 
  const finalCmd = isPython ? pyInterpreter : smbPath;
  const finalArgs = isPython ? [smbPath, ...args] : args;

  const proc = spawn(finalCmd, finalArgs, { timeout: timeoutMs || 30000 });
  if (key) activeProcesses.set(key, proc);

  if (impacketMode && impacketCmd) {
    proc.stdin.write(impacketCmd + '\n');
    proc.stdin.end();
  }

  return { proc, impacketMode };
}


// ---- Output parsers -------------------------------------------------

/**
 * Parse share list output. Handles both `smbclient` and `impacket-smbclient`.
 */
function parseSmbList(combined, impacketMode) {
  const shares = [];
  
  if (impacketMode) {
    // Impacket `shares` command output looks like:
    // [-] ADMIN$
    // [-] C$
    // [-] IPC$
    for (const line of combined.split('\n')) {
      const match = line.match(/^\[-\]\s+(.+?)\s*$/);
      if (match) {
        shares.push({
          name: match[1].trim(),
          type: 'disk', // Impacket doesn't easily expose type in list view
          comment: '',
          permissions: null,
        });
      }
    }
    return shares;
  }

  let inSection = false;
  for (const line of combined.split('\n')) {
    if (/^\s*Sharename\s+Type\s+Comment/i.test(line)) {
      inSection = true;
      continue;
    }
    if (/^\s*-+\s+-+/.test(line)) continue;
    if (!inSection) continue;
    if (/^\s*$/.test(line)) { inSection = false; continue; }

    const m = line.match(/^\s*(\S+)\s+(Disk|IPC|Printer|Print-Queue|Device|Comm)\s*(.*)?$/i);
    if (m) {
      shares.push({
        name: m[1],
        type: m[2].toLowerCase(),
        comment: (m[3] || '').trim(),
        permissions: null,
      });
    }
  }
  return shares;
}

/**
 * Parse `showmount -e <ip>` stdout.
 *
 * Sample:
 *   Export list for 192.168.1.5:
 *   /data   192.168.0.0/24
 *   /backup *
 */
function parseNfsExports(output) {
  const shares = [];
  let started = false;

  for (const line of output.split('\n')) {
    if (/^Export list/i.test(line)) { started = true; continue; }
    if (!started || !line.trim()) continue;
    const parts = line.trim().split(/\s+/);
    if (parts[0]) {
      shares.push({
        name: parts[0],
        type: 'nfs',
        comment: parts.slice(1).join(', '),
        permissions: null,
      });
    }
  }
  return shares;
}

function parseSmbDirectory(output, impacketMode) {
  return impacketMode
    ? parseSmbDirectoryImpacket(output)
    : parseSmbDirectorySmbclient(output);
}

function parseSmbDirectoryImpacket(output) {
  const entries = [];
  for (const line of output.split('\n')) {
    // Impacket ls format:
    // drw-rw-rw-          0  Sun Jan 12 11:22:33 2025 folder_name
    // -rw-rw-rw-     123456  Mon Feb 03 04:05:06 2025 file.txt
    const m = line.match(/^([d\-])[rwx\-]{9}\s+(\d+)\s+([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/);
    if (!m) continue;
    const name = m[4].trim();
    if (name === '.' || name === '..') continue;
    entries.push({
      name,
      type: m[1] === 'd' ? 'dir' : 'file',
      size: parseInt(m[2], 10) || 0,
      modified: m[3]
    });
  }
  return entries;
}

function parseSmbDirectorySmbclient(output) {
  const entries = [];
  for (const line of output.split('\n')) {
    // Original smbclient format
    const m = line.match(/^\s{2}(.+?)\s{2,}([ADRHS]+)\s+(\d+)\s+(.+)$/);
    if (!m) continue;
    const name = m[1].trimEnd();
    if (name === '.' || name === '..') continue;
    entries.push({
      name,
      type: m[2].includes('D') ? 'dir' : 'file',
      size: parseInt(m[3], 10),
      modified: m[4].trim(),
    });
  }
  return entries;
}

// ---- Public API -----------------------------------------------------

/**
 * Enumerate both SMB shares and NFS exports on a target host.
 * Results streamed to onResult({ type, shares[] }) per protocol.
 *
 * @param {string}   targetIp
 * @param {object}   credentials  { username, password, domain } or null
 * @param {Function} onResult
 * @param {Function} onError
 */
export async function enumerateShares(targetIp, credentials, onResult, onError) {
  if (!ipRegex.test(targetIp)) {
    onError({ message: 'Invalid IP address format' });
    return;
  }

  // --- SMB ---
  await new Promise((resolve) => {
    const impacketMode = isImpacket();
    const baseArgs = impacketMode ? [] : ['-L', `//${targetIp}`, ...buildSmbclientCredArgs(credentials)];
    const key = `smb-list-${targetIp}-${Date.now()}`;

    spawnSmbTool({
      targetIp,
      credentials,
      baseArgs,
      impacketCmd: impacketMode ? 'shares' : '',
      timeoutMs: 30000,
      key
    }).then(({ proc }) => {
      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (d) => { stdout += d.toString(); });
      proc.stderr.on('data', (d) => { stderr += d.toString(); });

      proc.on('close', () => {
        activeProcesses.delete(key);
        const combined = stdout + '\n' + stderr;
        const shares = parseSmbList(combined, impacketMode);
        const errLower = combined.toLowerCase();
        
        const isConnectionError = (shares.length === 0 && (
          errLower.includes('connection refused') || 
          errLower.includes('network unreachable') || 
          errLower.includes('bad file') || 
          errLower.includes('error') || 
          errLower.includes('failure')
        ));

        if (isConnectionError) {
          const parsedStderr = stderr.split('\n').find(l => l.trim() && !l.includes('Impacket'));
          const parsedStdout = stdout.split('\n').find(l => l.includes('[-]'));
          const msg = `SMB error: ${parsedStderr || parsedStdout || 'Connection failed'}`;
          
          // Notify of error but also send empty result for UI note consistency
          onResult({ type: 'smb', shares: [], note: msg });
          // Retain onError for transport failures if callers need it
          if (errLower.includes('refused') || errLower.includes('unreachable')) {
            onError({ message: msg });
          }
        } else {
          onResult({ type: 'smb', shares });
        }
        resolve();
      });

      proc.on('error', (err) => {
        activeProcesses.delete(key);
        if (err.code === 'ENOENT') {
          onError({ message: 'smbclient not found. Install Samba tools and configure the path in Settings.' });
        } else {
          onError({ message: `smbclient error: ${err.message}` });
        }
        resolve();
      });
    });
  });

  // --- NFS ---
  await new Promise((resolve) => {
    const showmountPath = getShowmountPath();
    const proc = spawn(showmountPath, ['-e', targetIp], { timeout: 15000 });
    const key = `nfs-list-${targetIp}-${Date.now()}`;
    activeProcesses.set(key, proc);

    let stdout = '';
    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', () => {});

    proc.on('close', () => {
      activeProcesses.delete(key);
      const shares = parseNfsExports(stdout);
      onResult({ type: 'nfs', shares });
      resolve();
    });

    proc.on('error', () => {
      activeProcesses.delete(key);
      // showmount is optional — silently send empty NFS result
      onResult({ type: 'nfs', shares: [], note: 'showmount not available on this system' });
      resolve();
    });
  });
}

/**
 * List the contents of a directory within an SMB share.
 *
 * @param {string}   targetIp
 * @param {string}   shareName
 * @param {string}   remotePath   path within the share, e.g. "Documents/Reports"
 * @param {object}   credentials
 * @param {Function} onResult     called with { path, entries[] }
 * @param {Function} onError
 */
export async function browseShare(targetIp, shareName, remotePath, credentials, onResult, onError) {
  if (!ipRegex.test(targetIp)) { onError({ message: 'Invalid IP address' }); return; }
  if (!isValidShareName(shareName)) { onError({ message: 'Invalid share name' }); return; }

  const safePath = (remotePath || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!isValidRemotePath(safePath)) {
    onError({ message: 'Path traversal detected — rejected' });
    return;
  }

  const key = `smb-browse-${targetIp}-${shareName}-${Date.now()}`;
  const impacketMode = isImpacket();
  
  let baseArgs = [];
  let impacketCmd = '';
  if (impacketMode) {
    const useCmd = `use ${shareName}`;
    const cdCmd = safePath ? `cd "${safePath}"` : '';
    impacketCmd = [useCmd, cdCmd, 'ls'].filter(Boolean).join('\n');
  } else {
    const shareUNC = `//${targetIp}/${shareName}`;
    const lsCmd = safePath ? `cd "${safePath}"; ls` : 'ls';
    baseArgs = [shareUNC, '-c', lsCmd, ...buildSmbclientCredArgs(credentials)];
  }

  return new Promise((resolve) => {
    spawnSmbTool({
      targetIp,
      credentials,
      baseArgs,
      impacketCmd,
      timeoutMs: 30000,
      key
    }).then(({ proc }) => {
      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (d) => { stdout += d.toString(); });
      proc.stderr.on('data', (d) => { stderr += d.toString(); });

      proc.on('close', () => {
        activeProcesses.delete(key);
        const entries = parseSmbDirectory(stdout, impacketMode);
        onResult({ path: safePath ? `/${safePath}` : '/', entries });
        resolve();
      });

      proc.on('error', (err) => {
        activeProcesses.delete(key);
        onError({ message: `Failed to browse share: ${err.message}` });
        resolve();
      });
    });
  });
}

/**
 * Download a single file from an SMB share to a local path.
 *
 * @param {string}   targetIp
 * @param {string}   shareName
 * @param {string}   remoteFile   path within the share to the file
 * @param {string}   localPath    absolute path where file will be saved
 * @param {object}   credentials
 * @param {Function} onError
 * @returns {Promise<boolean>}
 */
export async function downloadFile(targetIp, shareName, remoteFile, localPath, credentials, onError) {
  if (!ipRegex.test(targetIp)) { onError({ message: 'Invalid IP address' }); return false; }
  if (!isValidShareName(shareName)) { onError({ message: 'Invalid share name' }); return false; }

  const safeRemote = remoteFile.replace(/\\/g, '/').replace(/^\/+/, '');
  if (!isValidRemotePath(safeRemote)) {
    onError({ message: 'Path traversal detected — rejected' });
    return false;
  }

  const filename = safeRemote.split('/').filter(Boolean).pop();
  const dir = safeRemote.includes('/')
    ? safeRemote.substring(0, safeRemote.lastIndexOf('/'))
    : '';

  const key = `smb-get-${targetIp}-${shareName}-${filename}-${Date.now()}`;
  const impacketMode = isImpacket();
  
  let baseArgs = [];
  let impacketCmd = '';
  if (impacketMode) {
    const useCmd = `use ${shareName}`;
    const cdCmd = dir ? `cd "${dir}"` : '';
    const getCmd = `get "${filename}" "${localPath}"`;
    impacketCmd = [useCmd, cdCmd, getCmd].filter(Boolean).join('\n');
  } else {
    const shareUNC = `//${targetIp}/${shareName}`;
    const getCmd = dir
      ? `cd "${dir}"; get "${filename}" "${localPath}"`
      : `get "${filename}" "${localPath}"`;
    baseArgs = [shareUNC, '-c', getCmd, ...buildSmbclientCredArgs(credentials)];
  }

  return new Promise((resolve) => {
    spawnSmbTool({
      targetIp,
      credentials,
      baseArgs,
      impacketCmd,
      timeoutMs: 120000,
      key
    }).then(({ proc }) => {
      let stderr = '';
      proc.stderr.on('data', (d) => { stderr += d.toString(); });

      proc.on('close', (code) => {
        activeProcesses.delete(key);
        if (code === 0 || code === null) {
          resolve(true);
        } else {
          const msg = stderr.split('\n').find(l => l.trim()) || 'Unknown download error';
          onError({ message: `Download failed: ${msg}` });
          resolve(false);
        }
      });

      proc.on('error', (err) => {
        activeProcesses.delete(key);
        onError({ message: `smbclient error: ${err.message}` });
        resolve(false);
      });
    });
  });
}

/**
 * Kill all running share enumeration processes.
 * Called on app quit / window close.
 */
export function cleanupShares() {
  for (const proc of activeProcesses.values()) {
    try { proc.kill('SIGTERM'); } catch (_) {}
  }
  activeProcesses.clear();
}

import { app, dialog } from 'electron';
import path from 'path';
import { IPC_CHANNELS } from '#shared/ipc.js';
import { isPathWithinRoot } from '#shared/validate.js';

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.SHARE_ENUMERATE, async (event, options) => {
    const { targetIp, credentials } = options || {};
    console.log(`Share enumeration requested on ${targetIp}`);

    if (!options || typeof options !== 'object') {
      return { status: 'error', error: 'Invalid options payload' };
    }

    enumerateShares(
      targetIp,
      credentials || null,
      (result) => getWindow()?.webContents.send(IPC_CHANNELS.SHARE_RESULT, result),
      (err)    => getWindow()?.webContents.send(IPC_CHANNELS.SHARE_ERROR, err)
    );
    return { status: 'started' };
  });

  ipcMain.handle(IPC_CHANNELS.SHARE_BROWSE, async (event, options) => {
    const { targetIp, shareName, remotePath, credentials } = options || {};
    console.log(`Share browse requested: //${targetIp}/${shareName}${remotePath || '/'}`);

    if (!options || !targetIp || !shareName) {
      return { status: 'error', error: 'targetIp and shareName are required' };
    }

    await browseShare(
      targetIp,
      shareName,
      remotePath || '',
      credentials || null,
      (result) => getWindow()?.webContents.send(IPC_CHANNELS.SHARE_RESULT, { type: 'browse', ...result }),
      (err)    => getWindow()?.webContents.send(IPC_CHANNELS.SHARE_ERROR, err)
    );
    return { status: 'done' };
  });

  ipcMain.handle(IPC_CHANNELS.SHARE_DOWNLOAD, async (event, options) => {
    const { targetIp, shareName, remoteFile, credentials } = options || {};
    console.log(`Share download requested: //${targetIp}/${shareName}/${remoteFile}`);

    if (!targetIp || !shareName || !remoteFile) {
      return { status: 'error', error: 'targetIp, shareName, and remoteFile are required' };
    }

    // Prompt user to choose save location
    const filename = remoteFile.split(/[/\\]/).filter(Boolean).pop() || 'download';
    const downloadsDir = app.getPath('downloads');
    const { canceled, filePath } = await dialog.showSaveDialog(getWindow(), {
      title: 'Save Downloaded File',
      defaultPath: path.join(downloadsDir, filename),
    });

    if (canceled || !filePath) return { status: 'cancelled' };

    // Validate the chosen save path stays within the downloads directory
    if (!isPathWithinRoot(filePath, downloadsDir)) {
      return { status: 'error', error: 'Save path is outside the allowed downloads directory' };
    }

    const ok = await downloadFile(
      targetIp,
      shareName,
      remoteFile,
      filePath,
      credentials || null,
      (err) => getWindow()?.webContents.send(IPC_CHANNELS.SHARE_ERROR, err)
    );

    if (ok) {
      return { status: 'downloaded', localPath: filePath };
    }
    return { status: 'error', error: 'Download failed — check share error stream' };
  });
}
