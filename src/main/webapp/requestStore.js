/**
 * requestStore.js — HTTP Proxy Request History
 * Persistent SQLite store for all HTTP/HTTPS requests intercepted by the proxy.
 * Uses better-sqlite3 (synchronous, no native addon issues on Electron).
 */

import Database from 'better-sqlite3';
import { app } from 'electron';
import path from 'path';
import { PROXY_HISTORY_MAX_ROWS } from '#shared/webConstants.js';

let db = null;

/** Initialize the database, creating tables and indexes if needed. */
export function initRequestStore() {
  if (db) return;

  const dbPath = path.join(app.getPath('userData'), 'proxy-history.db');
  db = new Database(dbPath);

  // Enable WAL for better concurrent read performance
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT PRIMARY KEY,
      timestamp INTEGER NOT NULL,
      method TEXT,
      url TEXT,
      host TEXT,
      path TEXT,
      query TEXT,
      status_code INTEGER,
      mime_type TEXT,
      request_headers TEXT,
      request_body BLOB,
      response_headers TEXT,
      response_body BLOB,
      response_length INTEGER,
      duration_ms INTEGER,
      is_websocket INTEGER DEFAULT 0,
      notes TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_host      ON requests(host);
    CREATE INDEX IF NOT EXISTS idx_timestamp ON requests(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_method    ON requests(method);
    CREATE INDEX IF NOT EXISTS idx_status    ON requests(status_code);
  `);
}

/**
 * Insert a captured request/response record.
 * @param {object} r - Request record matching the DB schema.
 */
export function insertRequest(r) {
  _ensureInit();
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO requests
      (id, timestamp, method, url, host, path, query, status_code, mime_type,
       request_headers, request_body, response_headers, response_body,
       response_length, duration_ms, is_websocket, notes)
    VALUES
      (@id, @timestamp, @method, @url, @host, @path, @query, @status_code, @mime_type,
       @request_headers, @request_body, @response_headers, @response_body,
       @response_length, @duration_ms, @is_websocket, @notes)
  `);
  stmt.run({
    id:               r.id,
    timestamp:        r.timestamp ?? Date.now(),
    method:           r.method ?? 'GET',
    url:              r.url ?? '',
    host:             r.host ?? '',
    path:             r.path ?? '/',
    query:            r.query ?? '',
    status_code:      r.statusCode ?? null,
    mime_type:        r.mimeType ?? null,
    request_headers:  r.requestHeaders ? JSON.stringify(r.requestHeaders) : null,
    request_body:     r.requestBody ?? null,
    response_headers: r.responseHeaders ? JSON.stringify(r.responseHeaders) : null,
    response_body:    r.responseBody ?? null,
    response_length:  r.responseLength ?? null,
    duration_ms:      r.durationMs ?? null,
    is_websocket:     r.isWebSocket ? 1 : 0,
    notes:            r.notes ?? null,
  });
  _pruneIfNeeded();
}

/**
 * Get a list of requests matching an optional filter.
 * @param {object} [filter]
 * @param {string}  [filter.host]
 * @param {string}  [filter.method]
 * @param {number}  [filter.statusCode]
 * @param {string}  [filter.search]   - Regex match against url
 * @param {number}  [filter.limit]    - Max rows (default 500)
 * @param {number}  [filter.offset]   - Pagination offset
 * @returns {object[]}
 */
export function getRequests(filter = {}) {
  _ensureInit();
  const { host, method, statusCode, search, limit = 500, offset = 0 } = filter;

  let sql = `SELECT id, timestamp, method, url, host, path, query, status_code,
                    mime_type, response_length, duration_ms, is_websocket, notes
             FROM requests WHERE 1=1`;
  const params = [];

  if (host) {
    sql += ' AND host = ?';
    params.push(host);
  }
  if (method) {
    sql += ' AND method = ?';
    params.push(method.toUpperCase());
  }
  if (statusCode != null) {
    sql += ' AND status_code = ?';
    params.push(statusCode);
  }
  if (search) {
    sql += ' AND url LIKE ?';
    params.push(`%${search}%`);
  }

  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const rows = db.prepare(sql).all(...params);
  return rows.map(_deserializeRow);
}

/**
 * Get a single request by ID, including full bodies.
 * @param {string} id
 * @returns {object|null}
 */
export function getRequest(id) {
  _ensureInit();
  const row = db.prepare('SELECT * FROM requests WHERE id = ?').get(id);
  if (!row) return null;
  return _deserializeRow(row, true);
}

/**
 * Delete a single request record.
 * @param {string} id
 */
export function deleteRequest(id) {
  _ensureInit();
  db.prepare('DELETE FROM requests WHERE id = ?').run(id);
}

/** Delete all history. */
export function clearAll() {
  _ensureInit();
  db.prepare('DELETE FROM requests').run();
}

/**
 * Export selected requests as HAR 1.2 format.
 * @param {string[]} ids - Array of request IDs; if empty, exports all.
 * @returns {object} HAR object
 */
export function exportHar(ids = []) {
  _ensureInit();
  let rows;
  if (ids.length > 0) {
    const placeholders = ids.map(() => '?').join(',');
    rows = db.prepare(`SELECT * FROM requests WHERE id IN (${placeholders}) ORDER BY timestamp ASC`).all(...ids);
  } else {
    rows = db.prepare('SELECT * FROM requests ORDER BY timestamp ASC').all();
  }

  const entries = rows.map(row => {
    const r = _deserializeRow(row, true);
    const reqHeaders = (r.requestHeaders || []).map(([name, value]) => ({ name, value }));
    const resHeaders = (r.responseHeaders || []).map(([name, value]) => ({ name, value }));

    return {
      startedDateTime: new Date(r.timestamp).toISOString(),
      time: r.durationMs ?? -1,
      request: {
        method: r.method,
        url: r.url,
        httpVersion: 'HTTP/1.1',
        headers: reqHeaders,
        queryString: _parseQueryString(r.query),
        cookies: [],
        headersSize: -1,
        bodySize: r.requestBody ? r.requestBody.length : 0,
        postData: r.requestBody ? { mimeType: 'application/octet-stream', text: r.requestBody.toString('utf8') } : undefined,
      },
      response: {
        status: r.statusCode ?? 0,
        statusText: '',
        httpVersion: 'HTTP/1.1',
        headers: resHeaders,
        cookies: [],
        content: {
          size: r.responseLength ?? -1,
          mimeType: r.mimeType ?? 'application/octet-stream',
          text: r.responseBody ? r.responseBody.toString('utf8') : '',
        },
        redirectURL: '',
        headersSize: -1,
        bodySize: r.responseLength ?? -1,
      },
      cache: {},
      timings: { send: 0, wait: r.durationMs ?? -1, receive: 0 },
    };
  });

  return {
    log: {
      version: '1.2',
      creator: { name: 'NetSpecter', version: '1.0' },
      entries,
    },
  };
}

/** Get total request count */
export function getRequestCount() {
  _ensureInit();
  return db.prepare('SELECT COUNT(*) as count FROM requests').get().count;
}

/** Close the database (called on app exit). */
export function closeRequestStore() {
  if (db) {
    db.close();
    db = null;
  }
}

// ─── Private Helpers ──────────────────────────────────────────────────────────

function _ensureInit() {
  if (!db) initRequestStore();
}

function _deserializeRow(row, includeBody = false) {
  const result = {
    id:             row.id,
    timestamp:      row.timestamp,
    method:         row.method,
    url:            row.url,
    host:           row.host,
    path:           row.path,
    query:          row.query,
    statusCode:     row.status_code,
    mimeType:       row.mime_type,
    responseLength: row.response_length,
    durationMs:     row.duration_ms,
    isWebSocket:    row.is_websocket === 1,
    notes:          row.notes,
  };

  if (row.request_headers) {
    try { result.requestHeaders = JSON.parse(row.request_headers); } catch { result.requestHeaders = []; }
  }
  if (row.response_headers) {
    try { result.responseHeaders = JSON.parse(row.response_headers); } catch { result.responseHeaders = []; }
  }

  if (includeBody) {
    result.requestBody  = row.request_body ?? null;
    result.responseBody = row.response_body ?? null;
  }

  return result;
}

function _parseQueryString(query) {
  if (!query) return [];
  try {
    return [...new URLSearchParams(query).entries()].map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

function _pruneIfNeeded() {
  const row = db.prepare('SELECT COUNT(*) as count FROM requests').get();
  const count = row ? row.count : 0;
  if (count > PROXY_HISTORY_MAX_ROWS) {
    const excess = count - PROXY_HISTORY_MAX_ROWS;
    db.prepare(`
      DELETE FROM requests WHERE id IN (
        SELECT id FROM requests ORDER BY timestamp ASC LIMIT ?
      )
    `).run(excess);
  }
}
