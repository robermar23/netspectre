/**
 * webappIpc.js — IPC handlers for the Web App workspace (Feature 7A + 7B)
 * Registers all PROXY_* and CRAWLER_* / SITEMAP_* / API_* channel handlers.
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
import {
  observeRequest, getSitemap, clearSitemap, exportSitemapJson, getSitemapStats,
} from '../crawler.js';
import {
  startActiveCrawl, stopActiveCrawl, isActiveCrawlRunning, isPlaywrightAvailable,
} from '../activeCrawler.js';
import { detectApiSchemas } from '../apiDetector.js';

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

        // Feed into passive spider — setImmediate avoids blocking the proxy event loop
        setImmediate(() => {
          try {
            const { newUrls, newForms } = observeRequest(record);
            const win = getWindow();
            if (!win) return;
            for (const url of newUrls) {
              win.webContents.send(IPC_CHANNELS.CRAWLER_URL_FOUND, { url, source: 'passive' });
            }
            for (const form of newForms) {
              win.webContents.send(IPC_CHANNELS.CRAWLER_FORM_FOUND, { form, source: 'passive' });
            }
          } catch (err) {
            console.error('[WebappIpc] Passive spider error:', err.message);
          }
        });
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

  // ─── Feature 7B — Active Crawler ─────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.CRAWLER_START, async (_event, opts = {}) => {
    if (isActiveCrawlRunning()) {
      return { success: false, error: 'Crawl already running.' };
    }
    if (!opts.startUrl) {
      return { success: false, error: 'startUrl is required.' };
    }

    // Validate URL
    try { new URL(opts.startUrl); } catch {
      return { success: false, error: 'Invalid startUrl.' };
    }

    const win = getWindow();

    // Start the crawl; use the proxy port from running proxy (if any)
    // Only route through the proxy when it is actually running.
    // Passing a dead proxy address causes every page.goto to fail immediately.
    const proxyUrl = isProxyRunning()
      ? `http://127.0.0.1:${getProxyPort()}`
      : null;

    startActiveCrawl(
      { ...opts, proxyUrl, extraModulePaths: [app.getPath('userData')] },
      // onUrl
      (url) => {
        win?.webContents.send(IPC_CHANNELS.CRAWLER_URL_FOUND, { url, source: 'active' });
      },
      // onForm
      (form) => {
        win?.webContents.send(IPC_CHANNELS.CRAWLER_FORM_FOUND, { form, source: 'active' });
      },
      // onProgress
      (progress) => {
        win?.webContents.send(IPC_CHANNELS.CRAWLER_PROGRESS, progress);
      },
      // onComplete
      () => {
        win?.webContents.send(IPC_CHANNELS.CRAWLER_COMPLETE, getSitemapStats());
      },
      // onError
      (err) => {
        if (err.code === 'DEPENDENCY_MISSING') {
          win?.webContents.send(IPC_CHANNELS.CRAWLER_DEPENDENCY_MISSING, {
            message: 'playwright-core is not installed. Install it to use active crawling.',
          });
        } else {
          win?.webContents.send(IPC_CHANNELS.CRAWLER_ERROR, { message: err.message });
        }
      },
    );

    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.CRAWLER_STOP, async () => {
    stopActiveCrawl();
    return { success: true };
  });

  // ─── Feature 7B — Sitemap ─────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.SITEMAP_GET, async () => {
    return { success: true, sitemap: getSitemap(), stats: getSitemapStats() };
  });

  ipcMain.handle(IPC_CHANNELS.SITEMAP_CLEAR, async () => {
    clearSitemap();
    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.SITEMAP_EXPORT, async () => {
    try {
      const json = exportSitemapJson();
      return { success: true, json };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ─── Feature 7B — API Detection ───────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.API_DETECT, async (_event, { baseUrl } = {}) => {
    if (!baseUrl) return { success: false, error: 'baseUrl is required.' };
    try { new URL(baseUrl); } catch {
      return { success: false, error: 'Invalid baseUrl.' };
    }

    const win = getWindow();
    const ctrl = new AbortController();

    detectApiSchemas(baseUrl, ctrl.signal)
      .then((results) => {
        for (const schema of results) {
          win?.webContents.send(IPC_CHANNELS.API_SCHEMA_FOUND, schema);
        }
        win?.webContents.send(IPC_CHANNELS.API_DETECT_COMPLETE, { found: results.length });
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          win?.webContents.send(IPC_CHANNELS.CRAWLER_ERROR, { message: err.message });
        }
        win?.webContents.send(IPC_CHANNELS.API_DETECT_COMPLETE, { found: 0 });
      });

    return { success: true };
  });

  // ─── Playwright availability check ────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.PLAYWRIGHT_CHECK, async () => {
    const userData    = app.getPath('userData');
    const isPackaged  = app.isPackaged;
    // In dev the project root is writable; in packaged builds the ASAR is not.
    const installPath = isPackaged ? userData : app.getAppPath();
    const installed   = await isPlaywrightAvailable([userData]);
    return { installed, installPath, isPackaged };
  });
}

/** Clean up on app exit. */
export function cleanupWebapp() {
  stopProxy();
  stopActiveCrawl();
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
