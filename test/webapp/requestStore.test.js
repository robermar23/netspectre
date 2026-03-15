/**
 * test/webapp/requestStore.test.js
 * Tests for the SQLite proxy request history store.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Mock better-sqlite3 ────────────────────────────────────────────────────────

const mockRun    = vi.fn(() => ({}));
const mockGet    = vi.fn();
const mockAll    = vi.fn(() => []);
const mockExec   = vi.fn();
const mockPragma = vi.fn();
const mockPrepare = vi.fn(() => ({
  run:  mockRun,
  get:  mockGet,
  all:  mockAll,
}));

const mockDbInstance = {
  pragma:  mockPragma,
  exec:    mockExec,
  prepare: mockPrepare,
  close:   vi.fn(),
};

function MockDatabase() { return mockDbInstance; }

vi.mock('better-sqlite3', () => ({ default: MockDatabase }));

// ── Mock electron app ──────────────────────────────────────────────────────────

vi.mock('electron', () => ({
  app: { getPath: vi.fn(() => '/tmp/test-userdata') },
}));

// ── Mock #shared/webConstants.js ───────────────────────────────────────────────

vi.mock('#shared/webConstants.js', () => ({
  PROXY_HISTORY_MAX_ROWS: 100,
}));

// ── Import module under test ───────────────────────────────────────────────────

import {
  initRequestStore,
  insertRequest,
  getRequests,
  getRequest,
  deleteRequest,
  clearAll,
  exportHar,
  getRequestCount,
  closeRequestStore,
} from '../../src/main/webapp/requestStore.js';

// ─── Tests ─────────────────────────────────────────────────────────────────────

describe('requestStore', () => {
  beforeEach(() => {
    vi.resetAllMocks();

    // Default mock returns
    mockGet.mockReturnValue(null);
    mockAll.mockReturnValue([]);
    mockPrepare.mockReturnValue({ run: mockRun, get: mockGet, all: mockAll });

    // Reset the module's internal db state between tests
    initRequestStore();
  });

  afterEach(() => {
    closeRequestStore();
    vi.resetAllMocks();
  });

  // ── initRequestStore ─────────────────────────────────────────────────────────

  describe('initRequestStore', () => {
    it('sets WAL journal mode', () => {
      expect(mockPragma).toHaveBeenCalledWith('journal_mode = WAL');
    });

    it('creates tables and indexes', () => {
      expect(mockExec).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS requests'));
      expect(mockExec).toHaveBeenCalledWith(expect.stringContaining('CREATE INDEX IF NOT EXISTS idx_host'));
    });
  });

  // ── insertRequest ─────────────────────────────────────────────────────────────

  describe('insertRequest', () => {
    it('calls prepare and run with normalized fields', () => {
      const record = {
        id:              'abc-123',
        timestamp:       1700000000000,
        method:          'GET',
        url:             'https://example.com/api',
        host:            'example.com',
        path:            '/api',
        query:           '',
        statusCode:      200,
        mimeType:        'application/json',
        requestHeaders:  [['Host', 'example.com']],
        requestBody:     null,
        responseHeaders: [['Content-Type', 'application/json']],
        responseBody:    Buffer.from('{"ok":true}'),
        responseLength:  11,
        durationMs:      45,
        isWebSocket:     false,
      };

      insertRequest(record);

      expect(mockPrepare).toHaveBeenCalledWith(expect.stringContaining('INSERT OR REPLACE INTO requests'));
      expect(mockRun).toHaveBeenCalledWith(expect.objectContaining({
        id:         'abc-123',
        method:     'GET',
        host:       'example.com',
        status_code: 200,
        is_websocket: 0,
      }));
    });

    it('serializes requestHeaders as JSON string', () => {
      insertRequest({ id: 'x', requestHeaders: [['Accept', '*/*']], isWebSocket: false });
      const runCall = mockRun.mock.calls[0][0];
      expect(runCall.request_headers).toBe('[["Accept","*/*"]]');
    });

    it('sets is_websocket to 1 for WebSocket records', () => {
      insertRequest({ id: 'ws1', isWebSocket: true });
      const runCall = mockRun.mock.calls[0][0];
      expect(runCall.is_websocket).toBe(1);
    });

    it('calls pruning check after insert', () => {
      // prune query uses COUNT(*) — ensure prepare is called for it
      mockPrepare.mockReturnValue({ run: mockRun, get: vi.fn(() => ({ count: 50 })), all: mockAll });
      insertRequest({ id: 'prune-test', isWebSocket: false });
      // pruning happens if count > MAX_ROWS (100); count=50 means no DELETE called
      const prepCalls = mockPrepare.mock.calls.map(c => c[0]);
      expect(prepCalls.some(q => q.includes('COUNT(*)'))).toBe(true);
    });

    it('triggers prune DELETE when count exceeds max', () => {
      mockPrepare.mockImplementation((sql) => {
        if (sql.includes('COUNT(*)')) {
          return { get: vi.fn(() => ({ count: 150 })), run: mockRun, all: mockAll };
        }
        if (sql.includes('DELETE FROM requests WHERE id IN')) {
          return { run: mockRun, get: mockGet, all: mockAll };
        }
        return { run: mockRun, get: mockGet, all: mockAll };
      });
      insertRequest({ id: 'over-limit', isWebSocket: false });
      const deletePrepared = mockPrepare.mock.calls.some(c => c[0].includes('DELETE FROM requests WHERE id IN'));
      expect(deletePrepared).toBe(true);
    });
  });

  // ── getRequests ───────────────────────────────────────────────────────────────

  describe('getRequests', () => {
    it('returns empty array when no rows', () => {
      mockAll.mockReturnValue([]);
      const rows = getRequests();
      expect(rows).toEqual([]);
    });

    it('deserializes rows with parsed headers', () => {
      mockAll.mockReturnValue([{
        id:              'r1',
        timestamp:       1000,
        method:          'POST',
        url:             'http://test.com/submit',
        host:            'test.com',
        path:            '/submit',
        query:           '',
        status_code:     201,
        mime_type:       'application/json',
        response_length: 5,
        duration_ms:     20,
        is_websocket:    0,
        notes:           null,
        request_headers:  '[["Content-Type","application/json"]]',
        response_headers: '[["X-RateLimit","100"]]',
      }]);

      const rows = getRequests();
      expect(rows).toHaveLength(1);
      expect(rows[0].statusCode).toBe(201);
      expect(rows[0].isWebSocket).toBe(false);
      expect(rows[0].requestHeaders).toEqual([['Content-Type', 'application/json']]);
    });

    it('builds SQL with host filter', () => {
      getRequests({ host: 'target.com' });
      const sql = mockPrepare.mock.calls[0][0];
      expect(sql).toContain('AND host = ?');
    });

    it('builds SQL with method filter', () => {
      getRequests({ method: 'post' });
      const sql = mockPrepare.mock.calls[0][0];
      expect(sql).toContain('AND method = ?');
    });

    it('builds SQL with search filter using LIKE', () => {
      getRequests({ search: 'admin' });
      const sql = mockPrepare.mock.calls[0][0];
      expect(sql).toContain('AND url LIKE ?');
    });
  });

  // ── getRequest ────────────────────────────────────────────────────────────────

  describe('getRequest', () => {
    it('returns null when row not found', () => {
      mockGet.mockReturnValue(null);
      const row = getRequest('nonexistent-id');
      expect(row).toBeNull();
    });

    it('returns full row including body', () => {
      const bodyBuf = Buffer.from('hello');
      mockGet.mockReturnValue({
        id:              'full-id',
        timestamp:       2000,
        method:          'GET',
        url:             'http://a.com/',
        host:            'a.com',
        path:            '/',
        query:           '',
        status_code:     200,
        mime_type:       'text/html',
        response_length: 5,
        duration_ms:     10,
        is_websocket:    0,
        notes:           null,
        request_headers:  null,
        response_headers: null,
        request_body:    bodyBuf,
        response_body:   bodyBuf,
      });
      const row = getRequest('full-id');
      expect(row).not.toBeNull();
      expect(row.id).toBe('full-id');
      expect(row.requestBody).toEqual(bodyBuf);
    });
  });

  // ── deleteRequest ─────────────────────────────────────────────────────────────

  describe('deleteRequest', () => {
    it('calls prepare + run with correct id', () => {
      deleteRequest('del-123');
      expect(mockPrepare).toHaveBeenCalledWith('DELETE FROM requests WHERE id = ?');
      expect(mockRun).toHaveBeenCalledWith('del-123');
    });
  });

  // ── clearAll ──────────────────────────────────────────────────────────────────

  describe('clearAll', () => {
    it('executes DELETE FROM requests', () => {
      clearAll();
      expect(mockPrepare).toHaveBeenCalledWith('DELETE FROM requests');
      expect(mockRun).toHaveBeenCalled();
    });
  });

  // ── getRequestCount ───────────────────────────────────────────────────────────

  describe('getRequestCount', () => {
    it('returns count from DB', () => {
      mockGet.mockReturnValue({ count: 42 });
      const count = getRequestCount();
      expect(count).toBe(42);
    });
  });

  // ── exportHar ─────────────────────────────────────────────────────────────────

  describe('exportHar', () => {
    it('returns HAR 1.2 structure', () => {
      mockAll.mockReturnValue([{
        id:              'h1',
        timestamp:       1700000000000,
        method:          'GET',
        url:             'https://example.com/',
        host:            'example.com',
        path:            '/',
        query:           '',
        status_code:     200,
        mime_type:       'text/html',
        response_length: 100,
        duration_ms:     50,
        is_websocket:    0,
        notes:           null,
        request_headers:  '[["Host","example.com"]]',
        response_headers: '[["Content-Type","text/html"]]',
        request_body:    null,
        response_body:   Buffer.from('<html/>'),
      }]);

      const har = exportHar();
      expect(har.log.version).toBe('1.2');
      expect(har.log.entries).toHaveLength(1);
      expect(har.log.entries[0].request.method).toBe('GET');
      expect(har.log.entries[0].response.status).toBe(200);
    });

    it('returns empty entries when no rows', () => {
      mockAll.mockReturnValue([]);
      const har = exportHar();
      expect(har.log.entries).toHaveLength(0);
    });
  });
});
