/**
 * webappIpc.js — IPC handlers for the Web App workspace (Feature 7A + 7B)
 * Registers all PROXY_* and CRAWLER_* / SITEMAP_* / API_* channel handlers.
 */

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import dns from 'dns';
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
import {
  startScan, stopScan, isScanRunning, cleanupScan,
  getFindings, clearFindings,
} from '../scanner/index.js';
import { sendRepeaterRequest }                      from '../repeaterEngine.js';
import {
  startIntruder, stopIntruder, isIntruderRunning, cleanupIntruder,
} from '../intruderEngine.js';
import {
  collectTokens, stopCollection, analyzeTokens,
} from '../sequencerEngine.js';
import zlib from 'zlib';
import crypto from 'crypto';

// ─── Decoder size limits ──────────────────────────────────────────────────────
const MAX_DECODER_INPUT   = 4 * 1024 * 1024; // 4 MB for any transform
const MAX_GZIP_COMPRESSED = 1 * 1024 * 1024; // 1 MB base64 input before gzip-decompress

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

  // ─── Feature 7C — Active Vulnerability Scanner ────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.SCANNER_START, async (_event, opts = {}) => {
    if (isScanRunning()) {
      return { success: false, error: 'Scan already running.' };
    }

    // Validate targets
    if (!Array.isArray(opts.targets) || !opts.targets.length) {
      return { success: false, error: 'No scan targets provided.' };
    }
    for (const t of opts.targets) {
      try { new URL(t.url); } catch {
        return { success: false, error: `Invalid target URL: ${t.url}` };
      }
    }

    const win = getWindow();

    startScan(
      opts,
      // onFinding
      (finding) => {
        win?.webContents.send(IPC_CHANNELS.SCANNER_FINDING, finding);
      },
      // onProgress
      (progress) => {
        win?.webContents.send(IPC_CHANNELS.SCANNER_PROGRESS, progress);
      },
      // onComplete
      (result) => {
        win?.webContents.send(IPC_CHANNELS.SCANNER_COMPLETE, result);
      },
      // onError
      (err) => {
        const message = err instanceof Error ? err.message : String(err);
        win?.webContents.send(IPC_CHANNELS.SCANNER_ERROR, { message });
      },
      // onActivity
      (activity) => {
        win?.webContents.send(IPC_CHANNELS.SCANNER_ACTIVITY, activity);
      },
    );

    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.SCANNER_STOP, async () => {
    stopScan();
    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.SCANNER_GET_FINDINGS, async () => {
    return { success: true, findings: getFindings() };
  });

  // ─── DNS Resolution (hostname → IP for cross-workspace pivot) ────────────────

  ipcMain.handle(IPC_CHANNELS.DNS_RESOLVE, async (_event, hostname) => {
    if (!hostname || typeof hostname !== 'string') {
      return { success: false, error: 'Invalid hostname' };
    }
    // Already an IPv4 address — return as-is
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname)) {
      return { success: true, ip: hostname, hostname };
    }
    try {
      const result = await dns.promises.lookup(hostname, { family: 4 });
      return { success: true, ip: result.address, hostname };
    } catch (err) {
      return { success: false, error: err.message, hostname };
    }
  });

  ipcMain.handle(IPC_CHANNELS.SCANNER_CLEAR, async () => {
    clearFindings();
    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.SCANNER_EXPORT, async (_event, { format = 'json', findings = [] } = {}) => {
    try {
      let content;
      if (format === 'csv') {
        content = _findingsToCsv(findings);
      } else if (format === 'html') {
        content = _findingsToHtml(findings);
      } else {
        content = JSON.stringify(findings, null, 2);
      }
      return { success: true, content };
    } catch (err) {
      return { success: false, error: err.message };
    }
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

  // ─── Feature 7D — Repeater ────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.REPEATER_SEND, async (_event, opts = {}) => {
    const { ok, error } = _validateUrlField(opts, 'url');
    if (!ok) return { success: false, error };
    try {
      const result = await sendRepeaterRequest(opts);
      return { success: true, ...result };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ─── Feature 7D — Intruder ────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.INTRUDER_START, async (_event, opts = {}) => {
    if (isIntruderRunning()) {
      return { success: false, error: 'Intruder already running.' };
    }
    if (!opts.rawTemplate) return { success: false, error: 'rawTemplate is required' };
    const { ok, error } = _validateUrlField(opts, 'targetUrl', 'targetUrl');
    if (!ok) return { success: false, error };
    // Hard cap on the computed request count for the selected attack type
    const requestCount = _computeIntruderRequestCount(
      opts.attackType, opts.rawTemplate, opts.payloadLists ?? [[]],
    );
    if (requestCount > 1_000_000) {
      return { success: false, error: `Request count (${requestCount.toLocaleString()}) exceeds maximum (1,000,000).` };
    }

    const win = getWindow();

    startIntruder(
      opts,
      (result)   => win?.webContents.send(IPC_CHANNELS.INTRUDER_RESULT,   result),
      (progress) => win?.webContents.send(IPC_CHANNELS.INTRUDER_PROGRESS, progress),
      (summary)  => win?.webContents.send(IPC_CHANNELS.INTRUDER_COMPLETE, summary),
      (err)      => win?.webContents.send(IPC_CHANNELS.INTRUDER_ERROR,    { message: err.message }),
    );

    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.INTRUDER_STOP, async () => {
    stopIntruder();
    return { success: true };
  });

  // ─── Feature 7D — Sequencer ───────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.SEQUENCER_COLLECT, async (_event, opts = {}) => {
    const { ok, error } = _validateUrlField(opts, 'url');
    if (!ok) return { success: false, error };
    const count = Math.max(1, Math.min(Math.floor(Number(opts.count) || 100), 1000));
    const win = getWindow();
    collectTokens(
      { ...opts, count },
      (token)   => win?.webContents.send(IPC_CHANNELS.SEQUENCER_TOKEN,  token),
      (summary) => win?.webContents.send(IPC_CHANNELS.SEQUENCER_RESULT, { type: 'collect', ...summary }),
      (err)     => win?.webContents.send(IPC_CHANNELS.SEQUENCER_ERROR,  { message: err.message }),
    );
    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.SEQUENCER_ANALYZE, async (_event, { tokens } = {}) => {
    if (!Array.isArray(tokens) || tokens.length < 2) {
      return { success: false, error: 'Need at least 2 tokens to analyze.' };
    }
    try {
      const result = analyzeTokens(tokens);
      return { success: true, result };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ─── Feature 7D — Decoder (server-side transforms) ────────────────────────────

  ipcMain.handle(IPC_CHANNELS.DECODER_TRANSFORM, async (_event, { transform, input } = {}) => {
    if (typeof input !== 'string') return { success: false, error: 'input must be a string' };
    if (input.length > MAX_DECODER_INPUT) {
      return { success: false, error: `Input too large (max ${MAX_DECODER_INPUT / 1024 / 1024} MB).` };
    }
    try {
      let output;
      switch (transform) {
        case 'gzip-compress':
          output = await _gzipCompressToBase64(input);
          break;
        case 'gzip-decompress':
          if (input.length > MAX_GZIP_COMPRESSED) {
            return { success: false, error: `Compressed input too large (max ${MAX_GZIP_COMPRESSED / 1024} KB).` };
          }
          output = await _gzipDecompressFromBase64(input);
          break;
        case 'md5':
        case 'sha1':
        case 'sha256':
        case 'sha512':
          output = _hashTransform(transform, input);
          break;
        default:
          return { success: false, error: `Unknown server-side transform: ${transform}` };
      }
      return { success: true, output };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });
}

/** Clean up on app exit. */
export function cleanupWebapp() {
  stopProxy();
  stopActiveCrawl();
  cleanupScan();
  cleanupIntruder();
  stopCollection();
  closeRequestStore();
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Validate that opts[field] is a non-empty, parseable URL.
 * Returns { ok: true, value } or { ok: false, error }.
 */
function _validateUrlField(opts, field, label = field) {
  const value = opts?.[field];
  if (!value) return { ok: false, error: `${label} is required` };
  try { new URL(value); } catch {
    return { ok: false, error: `Invalid ${label}: ${value}` };
  }
  return { ok: true, value };
}

/**
 * Compute the number of HTTP requests that will be sent for a given intruder
 * configuration, so the cap can be enforced on actual requests rather than raw
 * payload list lengths (which under-counts for cluster-bomb and over-counts for
 * pitchfork).
 */
function _computeIntruderRequestCount(attackType, rawTemplate, payloadLists) {
  // Count §…§ pairs to find the number of injection positions.
  const posCount = ((rawTemplate ?? '').match(/§/g) ?? []).length >> 1;
  if (posCount === 0) return 0;
  const lists = (payloadLists ?? [[]]).map(l => l ?? []);
  switch (attackType) {
    case 'sniper':       return posCount * (lists[0]?.length ?? 0);
    case 'battering-ram': return lists[0]?.length ?? 0;
    case 'pitchfork':    return lists.length ? Math.min(...lists.map(l => l.length)) : 0;
    case 'cluster-bomb': return lists.reduce((p, l) => p * l.length, 1);
    default:             return lists.reduce((s, l) => s + l.length, 0);
  }
}

// ─── Decoder helpers ──────────────────────────────────────────────────────────

const _gzip   = (buf) => new Promise((res, rej) => zlib.gzip(buf,   (err, out) => err ? rej(err) : res(out)));
const _gunzip = (buf) => new Promise((res, rej) => zlib.gunzip(buf, (err, out) => err ? rej(err) : res(out)));

async function _gzipCompressToBase64(input) {
  const compressed = await _gzip(Buffer.from(input, 'utf8'));
  return compressed.toString('base64');
}

async function _gzipDecompressFromBase64(input) {
  const decompressed = await _gunzip(Buffer.from(input, 'base64'));
  return decompressed.toString('utf8');
}

function _hashTransform(algorithm, input) {
  return crypto.createHash(algorithm).update(input).digest('hex');
}

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

function _findingsToCsv(findings) {
  const headers = ['id','severity','type','title','url','parameter','payload','timestamp'];
  const rows = findings.map(f => headers.map(h => {
    const v = f[h] ?? '';
    return `"${String(v).replace(/"/g, '""')}"`;
  }).join(','));
  return [headers.join(','), ...rows].join('\r\n');
}

function _findingsToHtml(findings) {
  const SEVERITY_COLORS = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308',
    low: '#3b82f6', info: '#6b7280',
  };
  const rows = findings.map(f => {
    const color = SEVERITY_COLORS[f.severity] || '#6b7280';
    return `<tr>
      <td><span style="background:${color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700">${f.severity.toUpperCase()}</span></td>
      <td>${_esc(f.type)}</td>
      <td>${_esc(f.title)}</td>
      <td style="word-break:break-all">${_esc(f.url)}</td>
      <td>${_esc(f.parameter || '')}</td>
      <td>${_esc(f.remediation || '')}</td>
    </tr>`;
  }).join('');
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NetSpecter Scan Report</title>
<style>body{font-family:system-ui,sans-serif;background:#0f0f14;color:#e2e8f0;padding:24px}
h1{color:#8b5cf6;margin-bottom:4px}
.meta{color:#6b7280;font-size:13px;margin-bottom:24px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#1e1e2e;color:#a0aec0;padding:8px 12px;text-align:left;border-bottom:1px solid #2d2d3f}
td{padding:8px 12px;border-bottom:1px solid #1a1a2e;vertical-align:top}
tr:hover td{background:rgba(139,92,246,.08)}</style></head>
<body>
<h1>🕷️ NetSpecter Vulnerability Report</h1>
<div class="meta">Generated: ${new Date().toISOString()} — ${findings.length} finding(s)</div>
<table><thead><tr><th>Severity</th><th>Type</th><th>Title</th><th>URL</th><th>Parameter</th><th>Remediation</th></tr></thead>
<tbody>${rows}</tbody></table></body></html>`;
}

function _esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

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
