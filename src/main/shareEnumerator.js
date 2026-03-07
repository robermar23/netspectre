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
import { getSetting } from './store.js';
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

// ---- Output parsers -------------------------------------------------

/**
 * Parse `smbclient -L //<ip> -N` stdout.
 * smbclient prints share list to stderr on some builds; accept both.
 *
 * Sample output:
 *   Sharename       Type      Comment
 *   ---------       ----      -------
 *   ADMIN$          Disk      Remote Admin
 *   C$              Disk      Default share
 *   IPC$            IPC       Remote IPC
 */
function parseSmbList(combined) {
  const shares = [];
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

/**
 * Parse `smbclient //<ip>/<share> -c 'ls'` stdout.
 *
 * Sample lines:
 *   "  Documents           D        0  Wed Mar  5 09:00:00 2025"
 *   "  report.pdf          A   124032  Tue Jan 14 14:22:00 2025"
 */
function parseSmbDirectory(output) {
  const entries = [];
  for (const line of output.split('\n')) {
    // Two leading spaces, then name (padded), attrs, size, date
    const m = line.match(/^\s{2}(.+?)\s{2,}([ADRHS]+)\s+(\d+)\s+(.+)$/);
    if (m) {
      const name = m[1].trimEnd();
      if (name === '.' || name === '..') continue;
      entries.push({
        name,
        type: m[2].includes('D') ? 'dir' : 'file',
        size: parseInt(m[3], 10),
        modified: m[4].trim(),
      });
    }
  }
  return entries;
}

// ---- Credential arg builder -----------------------------------------

/**
 * Build the smbclient credential args without shell injection.
 * smbclient accepts "-U username%password" as a single flag value.
 */
function buildCredArgs(credentials) {
  const args = [];
  if (credentials && credentials.username) {
    const user = String(credentials.username).replace(/[%"]/g, '');  // sanitize separator chars
    const pass = String(credentials.password || '').replace(/[%"]/g, '');
    args.push('-U', `${user}%${pass}`);
    if (credentials.domain) {
      const domain = String(credentials.domain).replace(/[^a-zA-Z0-9._-]/g, '');
      args.push('--workgroup', domain);
    }
  } else {
    args.push('-N');   // null session
  }
  return args;
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
    const smbPath = getSmbclientPath();
    const args = ['-L', `//${targetIp}`, ...buildCredArgs(credentials)];

    const proc = spawn(smbPath, args, { timeout: 30000 });
    const key = `smb-list-${targetIp}-${Date.now()}`;
    activeProcesses.set(key, proc);

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => { stderr += d.toString(); });

    proc.on('close', () => {
      activeProcesses.delete(key);
      // smbclient writes share list to stdout, but some builds use stderr
      const combined = stdout + '\n' + stderr;
      const shares = parseSmbList(combined);
      const errLower = combined.toLowerCase();
      if (shares.length === 0 && (errLower.includes('connection refused') || errLower.includes('network unreachable') || errLower.includes('bad file'))) {
        onError({ message: `SMB error: ${stderr.split('\n').find(l => l.trim()) || 'Connection failed'}` });
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

  const smbPath = getSmbclientPath();
  const shareUNC = `//${targetIp}/${shareName}`;
  const lsCmd = safePath ? `cd "${safePath}"; ls` : 'ls';
  const args = [shareUNC, '-c', lsCmd, ...buildCredArgs(credentials)];

  return new Promise((resolve) => {
    const proc = spawn(smbPath, args, { timeout: 30000 });
    const key = `smb-browse-${targetIp}-${shareName}-${Date.now()}`;
    activeProcesses.set(key, proc);

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => { stderr += d.toString(); });

    proc.on('close', () => {
      activeProcesses.delete(key);
      const entries = parseSmbDirectory(stdout);
      onResult({ path: safePath ? `/${safePath}` : '/', entries });
      resolve();
    });

    proc.on('error', (err) => {
      activeProcesses.delete(key);
      onError({ message: `Failed to browse share: ${err.message}` });
      resolve();
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

  const smbPath = getSmbclientPath();
  const shareUNC = `//${targetIp}/${shareName}`;
  const filename = safeRemote.split('/').filter(Boolean).pop();
  const dir = safeRemote.includes('/')
    ? safeRemote.substring(0, safeRemote.lastIndexOf('/'))
    : '';

  // Build the smbclient -c command string carefully
  // Local path is validated by Electron's save dialog — passed as-is
  const getCmd = dir
    ? `cd "${dir}"; get "${filename}" "${localPath}"`
    : `get "${filename}" "${localPath}"`;

  const args = [shareUNC, '-c', getCmd, ...buildCredArgs(credentials)];

  return new Promise((resolve) => {
    const proc = spawn(smbPath, args, { timeout: 120000 });
    const key = `smb-get-${targetIp}-${shareName}-${filename}-${Date.now()}`;
    activeProcesses.set(key, proc);

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
