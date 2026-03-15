/**
 * proxyServer.js — MITM Intercepting HTTP/S Proxy
 *
 * Handles:
 *  - Plain HTTP proxy requests
 *  - HTTPS CONNECT tunnelling with dynamic TLS certificates signed by local CA
 *  - Request interception (pause / forward / drop)
 *  - WebSocket frame capture
 *
 * Dependencies: node-forge (cert generation), Node built-ins (net, tls, http, crypto)
 */

import http from 'http';
import https from 'https';
import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { app } from 'electron';
import forge from 'node-forge';
import { PROXY_CA_DIR, PROXY_CERT_CACHE_SIZE } from '#shared/webConstants.js';

// ─── State ─────────────────────────────────────────────────────────────────────

let proxyServer = null;
let isRunning   = false;
let interceptMode = false;
let currentPort = 8888;

/** Paused requests waiting for forward/drop: Map<id, { resolve, reject, rawRequest }> */
const pendingIntercepts = new Map();

/** LRU cache for dynamically signed leaf certs: Map<hostname, { cert, key }> */
const certCache = new Map();

/** All open client sockets — tracked so stopProxy() can destroy them immediately. */
const openSockets = new Set();

/** Callbacks set by webappIpc.js */
let onRequestCallback  = null;
let onResponseCallback = null;
let onInterceptedCallback = null;
let onWsFrameCallback  = null;

/** CA cert + key (loaded once at startup) */
let caCert = null;
let caKey  = null;

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Start the proxy server.
 * @param {object} opts
 * @param {number}   opts.port
 * @param {boolean}  opts.intercept
 * @param {Function} opts.onRequest    - Called with serializable request record
 * @param {Function} opts.onIntercepted - Called when a request is paused
 * @param {Function} opts.onWsFrame    - Called with a WebSocket frame record
 */
export async function startProxy(opts = {}) {
  if (isRunning) return { success: false, error: 'Proxy already running' };

  currentPort       = opts.port ?? 8888;
  interceptMode     = opts.intercept ?? false;
  onRequestCallback = opts.onRequest ?? null;
  onInterceptedCallback = opts.onIntercepted ?? null;
  onWsFrameCallback = opts.onWsFrame ?? null;

  // Ensure CA is ready
  await _ensureCa();

  return new Promise((resolve) => {
    proxyServer = http.createServer();

    // Track every client socket so stopProxy() can destroy them immediately
    proxyServer.on('connection', (socket) => {
      openSockets.add(socket);
      socket.once('close', () => openSockets.delete(socket));
    });

    // Plain HTTP requests
    proxyServer.on('request', _handleHttpRequest);

    // HTTPS CONNECT + raw TCP (WebSocket via HTTP)
    proxyServer.on('connect', _handleConnectTunnel);

    // Upgrade header (plain HTTP WebSocket)
    proxyServer.on('upgrade', _handleHttpUpgrade);

    proxyServer.on('error', (err) => {
      console.error('[Proxy] Server error:', err.message);
      resolve({ success: false, error: err.message });
    });

    proxyServer.listen(currentPort, '127.0.0.1', () => {
      isRunning = true;
      console.log(`[Proxy] Listening on 127.0.0.1:${currentPort}`);
      resolve({ success: true, port: currentPort });
    });
  });
}

/** Stop the proxy server and clean up pending intercepts. */
export function stopProxy() {
  if (!isRunning || !proxyServer) return;

  // Reject all pending intercepts
  for (const [id, pending] of pendingIntercepts) {
    try { pending.socket?.destroy(); } catch {}
    pendingIntercepts.delete(id);
  }

  // Null callbacks immediately so any in-flight requests aren't recorded
  onRequestCallback     = null;
  onInterceptedCallback = null;
  onWsFrameCallback     = null;

  // Force-close all open client sockets so keep-alive connections don't linger
  for (const socket of openSockets) {
    try { socket.destroy(); } catch {}
  }
  openSockets.clear();

  proxyServer.close(() => {
    console.log('[Proxy] Stopped.');
  });
  proxyServer = null;
  isRunning = false;
  caCert = null;
  caKey  = null;
  certCache.clear();
}

/** Toggle intercept mode. */
export function setInterceptMode(enabled) {
  interceptMode = !!enabled;
  if (!interceptMode) {
    // Auto-forward all pending
    for (const [id] of pendingIntercepts) {
      forwardInterceptedRequest(id, null);
    }
  }
}

/**
 * Forward a previously intercepted request (optionally with modifications).
 * @param {string} id - The intercept ID
 * @param {string|null} modifiedRaw - Modified raw HTTP request text, or null to forward as-is
 */
export function forwardInterceptedRequest(id, modifiedRaw) {
  const pending = pendingIntercepts.get(id);
  if (!pending) return;
  pendingIntercepts.delete(id);
  pending.resolve(modifiedRaw);
}

/** Drop an intercepted request (close the connection). */
export function dropInterceptedRequest(id) {
  const pending = pendingIntercepts.get(id);
  if (!pending) return;
  pendingIntercepts.delete(id);
  pending.reject(new Error('Dropped by user'));
}

export function isProxyRunning() { return isRunning; }
export function getProxyPort()   { return currentPort; }
export function getCaPath()      { return _getCaPath(); }

// ─── CA Certificate Management ─────────────────────────────────────────────────

function _getCaDir() {
  return path.join(app.getPath('userData'), PROXY_CA_DIR);
}

function _getCaPath() {
  return {
    cert: path.join(_getCaDir(), 'ca.crt'),
    key:  path.join(_getCaDir(), 'ca.key'),
  };
}

async function _ensureCa() {
  if (caCert && caKey) return;

  const dir  = _getCaDir();
  const paths = _getCaPath();

  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  if (fs.existsSync(paths.cert) && fs.existsSync(paths.key)) {
    // Load existing CA
    const certPem = fs.readFileSync(paths.cert, 'utf8');
    const keyPem  = fs.readFileSync(paths.key, 'utf8');
    caCert = forge.pki.certificateFromPem(certPem);
    caKey  = forge.pki.privateKeyFromPem(keyPem);
    console.log('[Proxy] Loaded existing CA certificate.');
    return;
  }

  // Generate a new Root CA
  console.log('[Proxy] Generating new Root CA certificate...');
  const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert    = forge.pki.createCertificate();

  cert.publicKey   = keyPair.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: 'commonName',         value: 'NetSpecter Proxy CA' },
    { name: 'organizationName',   value: 'NetSpecter' },
    { name: 'countryName',        value: 'US' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(keyPair.privateKey, forge.md.sha256.create());

  caCert = cert;
  caKey  = keyPair.privateKey;

  fs.writeFileSync(paths.cert, forge.pki.certificateToPem(cert));
  fs.writeFileSync(paths.key,  forge.pki.privateKeyToPem(keyPair.privateKey));
  console.log('[Proxy] Root CA generated and saved.');
}

/**
 * Get (or create) a dynamically signed TLS leaf certificate for a hostname.
 * Uses a simple LRU-style Map eviction when cache exceeds limit.
 */
function _getLeafCert(hostname) {
  if (certCache.has(hostname)) return certCache.get(hostname);

  const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert    = forge.pki.createCertificate();

  cert.publicKey    = keyPair.publicKey;
  cert.serialNumber = crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date();
  cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + 30);

  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    {
      name: 'subjectAltName',
      altNames: [
        hostname.match(/^\d+\.\d+\.\d+\.\d+$/)
          ? { type: 7, ip: hostname }      // IP SAN
          : { type: 2, value: hostname },  // DNS SAN
      ],
    },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  const entry = {
    cert: forge.pki.certificateToPem(cert),
    key:  forge.pki.privateKeyToPem(keyPair.privateKey),
  };

  // Evict oldest entry if over limit
  if (certCache.size >= PROXY_CERT_CACHE_SIZE) {
    certCache.delete(certCache.keys().next().value);
  }
  certCache.set(hostname, entry);
  return entry;
}

// ─── Plain HTTP Handler ────────────────────────────────────────────────────────

function _handleHttpRequest(clientReq, clientRes) {
  const startTime = Date.now();
  const id = _uuid();

  let targetUrl;
  try {
    targetUrl = new URL(clientReq.url);
  } catch {
    clientRes.writeHead(400);
    clientRes.end('Bad Request');
    return;
  }

  // Security: only allow http/https
  if (targetUrl.protocol !== 'http:' && targetUrl.protocol !== 'https:') {
    clientRes.writeHead(400);
    clientRes.end('Bad Request: unsupported scheme');
    return;
  }

  const chunks = [];
  clientReq.on('data', chunk => chunks.push(chunk));
  clientReq.on('end', () => {
    const requestBody = chunks.length > 0 ? Buffer.concat(chunks) : null;
    _proxyRequest({
      id,
      startTime,
      method:         clientReq.method,
      url:            targetUrl.href,
      host:           targetUrl.hostname,
      path:           targetUrl.pathname,
      query:          targetUrl.search.slice(1),
      requestHeaders: clientReq.rawHeaders,
      requestBody,
      useTls:         targetUrl.protocol === 'https:',
      port:           parseInt(targetUrl.port, 10) || (targetUrl.protocol === 'https:' ? 443 : 80),
      clientRes,
    });
  });
}

function _proxyRequest({ id, startTime, method, url, host, path: urlPath, query,
                          requestHeaders, requestBody, useTls, port, clientRes }) {
  const parsedHeaders = _parseRawHeaders(requestHeaders);
  // Remove proxy-specific headers
  const cleanHeaders = parsedHeaders.filter(([k]) =>
    !['proxy-connection', 'proxy-authorization'].includes(k.toLowerCase())
  );
  const headersObj = Object.fromEntries(cleanHeaders);

  const options = {
    hostname: host,
    port,
    path: urlPath + (query ? `?${query}` : ''),
    method,
    headers: headersObj,
  };

  const transport = useTls ? https : http;
  const responseChunks = [];

  const upstreamReq = transport.request(options, (upstreamRes) => {
    const resHeaders = _parseRawHeaders(upstreamRes.rawHeaders);
    upstreamRes.on('data', chunk => responseChunks.push(chunk));
    upstreamRes.on('end', () => {
      const responseBody   = responseChunks.length > 0 ? Buffer.concat(responseChunks) : null;
      const durationMs     = Date.now() - startTime;
      const contentType    = upstreamRes.headers['content-type'] ?? '';
      const mimeType       = contentType.split(';')[0].trim();

      const record = {
        id,
        timestamp:       startTime,
        method,
        url,
        host,
        path:            urlPath,
        query,
        statusCode:      upstreamRes.statusCode,
        mimeType,
        requestHeaders:  cleanHeaders,
        requestBody,
        responseHeaders: resHeaders,
        responseBody,
        responseLength:  responseBody ? responseBody.length : 0,
        durationMs,
        isWebSocket:     false,
      };

      onRequestCallback?.(record);

      if (clientRes && !clientRes.destroyed) {
        clientRes.writeHead(upstreamRes.statusCode, Object.fromEntries(resHeaders));
        if (responseBody) clientRes.end(responseBody);
        else clientRes.end();
      }
    });
  });

  upstreamReq.on('error', (err) => {
    console.error(`[Proxy] Upstream error for ${url}:`, err.message);
    if (clientRes && !clientRes.destroyed) {
      clientRes.writeHead(502);
      clientRes.end('Bad Gateway');
    }
  });

  if (requestBody) upstreamReq.write(requestBody);
  upstreamReq.end();
}

// ─── HTTPS CONNECT Tunnel ──────────────────────────────────────────────────────

function _handleConnectTunnel(clientReq, clientSocket, head) {
  const [hostname, portStr] = clientReq.url.split(':');
  const upstreamPort = parseInt(portStr, 10) || 443;

  // Respond 200 to the client to establish the tunnel
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

  // Build a TLS server that impersonates the target hostname
  const leafCert = _getLeafCert(hostname);

  let tlsServer;
  try {
    tlsServer = new tls.TLSSocket(clientSocket, {
      isServer:    true,
      cert:        leafCert.cert,
      key:         leafCert.key,
      SNICallback: (serverName, cb) => {
        try {
          const lc = _getLeafCert(serverName || hostname);
          cb(null, tls.createSecureContext({ cert: lc.cert, key: lc.key }));
        } catch (e) { cb(e); }
      },
    });
  } catch (err) {
    clientSocket.destroy();
    return;
  }
  tlsServer.on('error', () => tlsServer.destroy());

  // Detect WebSocket upgrade on this TLS stream
  let headerBuf = Buffer.alloc(0);
  let isWs = false;
  let wsSessionId = null;

  tlsServer.on('data', (chunk) => {
    if (isWs) {
      _captureWsFrame({ sessionId: wsSessionId, direction: 'client->server', payload: chunk, hostname });
      // Forward to upstream if we have a live upstream socket
      tlsServer._upstreamSocket?.write(chunk);
      return;
    }

    headerBuf = Buffer.concat([headerBuf, chunk]);
    const headerEnd = headerBuf.indexOf('\r\n\r\n');
    if (headerEnd === -1) return; // Wait for complete headers

    const headerText  = headerBuf.slice(0, headerEnd).toString('utf8');
    const bodyStart   = headerBuf.slice(headerEnd + 4);
    const firstLine   = headerText.split('\r\n')[0];
    const [method]    = firstLine.split(' ');

    // Check for WebSocket upgrade
    if (/upgrade:\s*websocket/i.test(headerText)) {
      isWs = true;
      wsSessionId = _uuid();
      _handleWsUpgradeViaConnect({ tlsServer, hostname, upstreamPort, headerText, bodyStart, wsSessionId });
      return;
    }

    // Regular HTTPS request
    _handleDecryptedHttps({ tlsServer, hostname, upstreamPort, headerText, bodyStart });
  });

  tlsServer.on('error', (err) => {
    // SSL alert 46 = certificate_unknown — client rejected our cert (CA not yet trusted).
    // SSL alert 42 = bad_certificate_status_response — pinned cert app (e.g. OS telemetry).
    // These are expected until the CA is installed; suppress to avoid console spam.
    const isExpectedClientRejection =
      err.message?.includes('SSLV3_ALERT_CERTIFICATE_UNKNOWN') ||
      err.message?.includes('SSL alert number 46') ||
      err.message?.includes('SSL alert number 42') ||
      err.code === 'ECONNRESET' ||
      err.code === 'EPIPE';
    if (!isExpectedClientRejection) {
      console.error(`[Proxy] TLS tunnel error (${hostname}):`, err.message);
    }
  });

  if (head && head.length > 0) tlsServer.emit('data', head);
}

function _handleDecryptedHttps({ tlsServer, hostname, upstreamPort, headerText, bodyStart }) {
  const id = _uuid();
  const startTime = Date.now();

  const lines      = headerText.split('\r\n');
  const firstLine  = lines[0];
  const [method, reqPath] = firstLine.split(' ');
  const rawHeaders = lines.slice(1).join('\r\n');
  const parsedHeaders = _parseHeaderBlock(rawHeaders);

  // Collect body if Content-Length present
  const contentLenHeader = parsedHeaders.find(([k]) => k.toLowerCase() === 'content-length');
  const contentLen = contentLenHeader ? parseInt(contentLenHeader[1], 10) : 0;

  const processRequest = (requestBody) => {
    const [urlPath, queryStr = ''] = reqPath.split('?');
    const fullUrl = `https://${hostname}:${upstreamPort}${reqPath}`;

    const record = {
      id,
      timestamp:       startTime,
      method,
      url:             fullUrl,
      host:            hostname,
      path:            urlPath,
      query:           queryStr,
      requestHeaders:  parsedHeaders,
      requestBody:     requestBody || null,
      responseHeaders: null,
      responseBody:    null,
      statusCode:      null,
      mimeType:        null,
      durationMs:      null,
      isWebSocket:     false,
    };

    if (interceptMode) {
      // Pause and notify renderer
      _pauseRequest(id, record, (modifiedRaw) => {
        // Build (possibly modified) request to send upstream
        const rawToSend = modifiedRaw || _buildRawRequest(method, reqPath, parsedHeaders, requestBody);
        _forwardDecryptedRequest({ id, startTime, hostname, upstreamPort, rawRequest: rawToSend, baseRecord: record, tlsServer });
      }, () => {
        tlsServer.destroy();
      });
    } else {
      _forwardDecryptedRequest({ id, startTime, hostname, upstreamPort,
        rawRequest: _buildRawRequest(method, reqPath, parsedHeaders, requestBody),
        baseRecord: record, tlsServer });
    }
  };

  if (contentLen > 0) {
    let body = bodyStart;
    if (body.length >= contentLen) {
      processRequest(body.slice(0, contentLen));
    } else {
      // Need more data
      const needed = contentLen - body.length;
      let remaining = needed;
      const bodyChunks = [body];
      const onData = (chunk) => {
        bodyChunks.push(chunk);
        remaining -= chunk.length;
        if (remaining <= 0) {
          tlsServer.removeListener('data', onData);
          processRequest(Buffer.concat(bodyChunks));
        }
      };
      tlsServer.on('data', onData);
    }
  } else {
    processRequest(bodyStart.length > 0 ? bodyStart : null);
  }
}

function _forwardDecryptedRequest({ id, startTime, hostname, upstreamPort, rawRequest, baseRecord, tlsServer }) {
  const upstreamSocket = tls.connect(
    { host: hostname, port: upstreamPort, rejectUnauthorized: false },
    () => {
      upstreamSocket.write(rawRequest);
    }
  );

  let responseRaw = Buffer.alloc(0);

  upstreamSocket.on('data', (chunk) => {
    responseRaw = Buffer.concat([responseRaw, chunk]);
    // Forward to client
    tlsServer.write(chunk);
  });

  upstreamSocket.on('end', () => {
    const durationMs = Date.now() - startTime;
    _parseAndEmitResponse(id, baseRecord, responseRaw, durationMs);
    tlsServer.end();
  });

  upstreamSocket.on('error', (err) => {
    if (err.code !== 'ECONNRESET') {
      console.error(`[Proxy] Upstream TLS error (${hostname}):`, err.message);
    }
    tlsServer.destroy();
  });
}

// ─── WebSocket Handling ────────────────────────────────────────────────────────

function _handleHttpUpgrade(req, socket, head) {
  // Plain HTTP → WebSocket upgrade
  const targetUrl = new URL(req.url);
  const wsSessionId = _uuid();

  const upstreamSocket = net.connect(
    parseInt(targetUrl.port, 10) || 80,
    targetUrl.hostname,
    () => {
      upstreamSocket.write(
        `${req.method} ${targetUrl.pathname}${targetUrl.search} HTTP/1.1\r\n` +
        req.rawHeaders.reduce((acc, v, i) => i % 2 === 0 ? acc : acc + `${req.rawHeaders[i-1]}: ${v}\r\n`, '') +
        '\r\n'
      );
      if (head.length) upstreamSocket.write(head);
    }
  );

  upstreamSocket.on('data', (chunk) => {
    socket.write(chunk);
    _captureWsFrame({ sessionId: wsSessionId, direction: 'server->client', payload: chunk, hostname: targetUrl.hostname });
  });
  socket.on('data', (chunk) => {
    upstreamSocket.write(chunk);
    _captureWsFrame({ sessionId: wsSessionId, direction: 'client->server', payload: chunk, hostname: targetUrl.hostname });
  });

  upstreamSocket.on('error', () => socket.destroy());
  socket.on('error', () => upstreamSocket.destroy());
}

function _handleWsUpgradeViaConnect({ tlsServer, hostname, upstreamPort, headerText, bodyStart, wsSessionId }) {
  const upstreamSocket = tls.connect(
    { host: hostname, port: upstreamPort, rejectUnauthorized: false },
    () => {
      upstreamSocket.write(headerText + '\r\n\r\n');
      if (bodyStart.length > 0) upstreamSocket.write(bodyStart);
    }
  );

  tlsServer._upstreamSocket = upstreamSocket;

  upstreamSocket.on('data', (chunk) => {
    tlsServer.write(chunk);
    _captureWsFrame({ sessionId: wsSessionId, direction: 'server->client', payload: chunk, hostname });
  });

  upstreamSocket.on('error', () => tlsServer.destroy());
  tlsServer.on('error', () => upstreamSocket.destroy());
}

function _captureWsFrame({ sessionId, direction, payload, hostname }) {
  onWsFrameCallback?.({
    sessionId,
    direction,
    hostname,
    timestamp: Date.now(),
    length:    payload.length,
    // Only include first 4KB as preview to avoid IPC bloat
    preview:   payload.slice(0, 4096).toString('utf8'),
    isBinary:  !_isUtf8(payload),
  });
}

// ─── Intercept Mode ─────────────────────────────────────────────────────────────

function _pauseRequest(id, record, onForward, onDrop) {
  pendingIntercepts.set(id, {
    resolve: onForward,
    reject:  onDrop,
  });
  onInterceptedCallback?.({ ...record, pendingIntercepts: pendingIntercepts.size });
}

// ─── Response Parsing ──────────────────────────────────────────────────────────

function _parseAndEmitResponse(id, baseRecord, rawResponse, durationMs) {
  try {
    const headerEnd = rawResponse.indexOf('\r\n\r\n');
    if (headerEnd === -1) return;

    const headerText = rawResponse.slice(0, headerEnd).toString('utf8');
    const body       = rawResponse.slice(headerEnd + 4);
    const lines      = headerText.split('\r\n');
    const statusLine = lines[0];
    const statusCode = parseInt(statusLine.split(' ')[1], 10);

    const parsedHeaders = _parseHeaderBlock(lines.slice(1).join('\r\n'));
    const contentType   = parsedHeaders.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? '';
    const mimeType      = contentType.split(';')[0].trim();

    const record = {
      ...baseRecord,
      statusCode,
      mimeType,
      responseHeaders: parsedHeaders,
      responseBody:    body.length > 0 ? body : null,
      responseLength:  body.length,
      durationMs,
    };
    onRequestCallback?.(record);
  } catch (err) {
    console.error('[Proxy] Failed to parse upstream response:', err.message);
  }
}

// ─── Utilities ─────────────────────────────────────────────────────────────────

function _uuid() {
  return crypto.randomUUID();
}

function _parseRawHeaders(rawHeaders) {
  const result = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    result.push([rawHeaders[i], rawHeaders[i + 1]]);
  }
  return result;
}

function _parseHeaderBlock(block) {
  return block.split('\r\n')
    .filter(Boolean)
    .map(line => {
      const idx = line.indexOf(':');
      if (idx === -1) return null;
      return [line.slice(0, idx).trim(), line.slice(idx + 1).trim()];
    })
    .filter(Boolean);
}

function _buildRawRequest(method, path, headers, body) {
  let raw = `${method} ${path} HTTP/1.1\r\n`;
  for (const [k, v] of headers) {
    raw += `${k}: ${v}\r\n`;
  }
  raw += '\r\n';
  if (body) {
    return Buffer.concat([Buffer.from(raw), body]);
  }
  return Buffer.from(raw);
}

function _isUtf8(buf) {
  try {
    Buffer.from(buf).toString('utf8');
    return true;
  } catch {
    return false;
  }
}
