/**
 * webappIpc.js — IPC handlers for the Web App workspace (Feature 7A)
 * Registers all PROXY_* channel handlers and bridges proxyServer + requestStore.
 */

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { app, shell } from 'electron';
import { IPC_CHANNELS } from '#shared/ipc.js';
import {
  startProxy, stopProxy, setInterceptMode,
  forwardInterceptedRequest, dropInterceptedRequest,
  isProxyRunning, getProxyPort, getCaPath,
} from '../proxyServer.js';
import {
  initRequestStore, insertRequest, getRequests, getRequest,
  deleteRequest, clearAll, exportHar, getRequestCount, closeRequestStore,
} from '../requestStore.js';

export function registerIpcHandlers(ipcMain, getWindow) {

  // ─── Proxy Lifecycle ─────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.PROXY_START, async (_event, opts = {}) => {
    if (!_validateProxyPort(opts.port)) {
      return { success: false, error: 'Invalid port. Must be 1024–65535.' };
    }

    initRequestStore();

    const result = await startProxy({
      port:      opts.port ?? 8888,
      intercept: opts.intercept ?? false,

      onRequest: (record) => {
        // Persist to DB
        try { insertRequest(record); } catch (err) {
          console.error('[WebappIpc] Failed to insert request:', err.message);
        }
        // Push to renderer (lightweight summary, no bodies)
        getWindow()?.webContents.send(IPC_CHANNELS.PROXY_REQUEST, _toSummary(record));
      },

      onIntercepted: (record) => {
        getWindow()?.webContents.send(IPC_CHANNELS.PROXY_INTERCEPTED, _toSummary(record));
      },

      onWsFrame: (frame) => {
        getWindow()?.webContents.send(IPC_CHANNELS.PROXY_WS_FRAME, frame);
      },
    });

    if (result.success) {
      getWindow()?.webContents.send(IPC_CHANNELS.PROXY_STATUS, {
        running: true,
        port: result.port,
      });
    }

    return result;
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_STOP, async () => {
    stopProxy();
    getWindow()?.webContents.send(IPC_CHANNELS.PROXY_STATUS, { running: false });
    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_GET_STATUS, async () => {
    return {
      running: isProxyRunning(),
      port:    getProxyPort(),
      count:   isProxyRunning() ? getRequestCount() : 0,
    };
  });

  // ─── Intercept Mode ──────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.PROXY_SET_INTERCEPT, async (_event, enabled) => {
    setInterceptMode(!!enabled);
    return { success: true, intercept: !!enabled };
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_FORWARD, async (_event, { id, modifiedRaw }) => {
    forwardInterceptedRequest(id, modifiedRaw ?? null);
    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_DROP, async (_event, { id }) => {
    dropInterceptedRequest(id);
    return { success: true };
  });

  // ─── History ─────────────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.PROXY_GET_HISTORY, async (_event, filter = {}) => {
    try {
      initRequestStore();
      return { success: true, rows: getRequests(filter) };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_GET_REQUEST, async (_event, id) => {
    try {
      initRequestStore();
      const row = getRequest(id);
      if (!row) return { success: false, error: 'Not found' };
      // Convert Buffers to base64 for IPC serialization
      return {
        success: true,
        row: {
          ...row,
          requestBody:  row.requestBody  ? row.requestBody.toString('base64')  : null,
          responseBody: row.responseBody ? row.responseBody.toString('base64') : null,
          _bodyEncoding: 'base64',
        },
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_DELETE_REQUEST, async (_event, id) => {
    try {
      deleteRequest(id);
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_CLEAR_HISTORY, async () => {
    try {
      initRequestStore();
      clearAll();
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_EXPORT_HAR, async (_event, ids = []) => {
    try {
      initRequestStore();
      const har = exportHar(ids);
      return { success: true, har };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ─── CA Certificate ───────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.PROXY_GET_CA_PATH, async () => {
    const paths = getCaPath();
    return { certPath: paths.cert, keyPath: paths.key };
  });

  ipcMain.handle(IPC_CHANNELS.PROXY_INSTALL_CA, async () => {
    const paths = getCaPath();

    if (!fs.existsSync(paths.cert)) {
      return { success: false, error: 'CA cert not found. Start the proxy first to generate it.' };
    }

    const certPath = paths.cert;
    const platform = process.platform;

    try {
      if (platform === 'win32') {
        // certutil -addstore Root requires elevation. Use PowerShell Start-Process -Verb RunAs
        // to trigger a UAC prompt rather than failing with ERROR_ELEVATION_REQUIRED (740).
        await _spawnSafe('powershell', [
          '-NoProfile', '-NonInteractive', '-Command',
          `Start-Process certutil -ArgumentList '-addstore','Root','${certPath.replace(/'/g, "''")}' -Verb RunAs -Wait`,
        ]);
        return { success: true, message: 'CA certificate installed in Windows Root Trust Store.' };
      } else if (platform === 'darwin') {
        // security requires admin rights — use osascript to prompt the user for their password
        const cmd = `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '${certPath.replace(/'/g, "'\\''")}'`;
        await _spawnSafe('osascript', ['-e', `do shell script "${cmd.replace(/"/g, '\\"')}" with administrator privileges`]);
        return { success: true, message: 'CA certificate installed in macOS System Keychain.' };
      } else {
        // Linux: open the cert directory for the user to install manually
        shell.showItemInFolder(certPath);
        return {
          success: true,
          message: `CA certificate saved at:\n${certPath}\n\nInstall it manually using your distro's certificate manager (e.g., update-ca-certificates, trust anchor).`,
        };
      }
    } catch (err) {
      const msg = err.message || '';
      // User cancelled the UAC / admin prompt
      const cancelled = msg.includes('code 1') && !msg.includes(':') ||
                        msg.includes('cancelled') || msg.includes('canceled') ||
                        msg.includes('The operation was canceled');
      return {
        success: false,
        error: cancelled
          ? 'Installation cancelled. Administrator approval is required to install a trusted CA certificate.'
          : msg,
      };
    }
  });
}

/** Clean up on app exit. */
export function cleanupWebapp() {
  stopProxy();
  closeRequestStore();
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function _validateProxyPort(port) {
  if (port === undefined || port === null) return true; // default allowed
  const p = Number(port);
  return Number.isInteger(p) && p >= 1024 && p <= 65535;
}

/** Strip large bodies from IPC push — renderer fetches full detail on demand. */
function _toSummary(record) {
  return {
    id:             record.id,
    timestamp:      record.timestamp,
    method:         record.method,
    url:            record.url,
    host:           record.host,
    path:           record.path,
    query:          record.query,
    statusCode:     record.statusCode,
    mimeType:       record.mimeType,
    responseLength: record.responseLength,
    durationMs:     record.durationMs,
    isWebSocket:    record.isWebSocket,
    notes:          record.notes,
    requestHeaders: record.requestHeaders,
    responseHeaders: record.responseHeaders,
  };
}

function _spawnSafe(cmd, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { shell: false });
    let stderr = '';
    child.stderr?.on('data', d => { stderr += d.toString(); });
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} exited with code ${code}: ${stderr.trim()}`));
    });
    child.on('error', reject);
  });
}
