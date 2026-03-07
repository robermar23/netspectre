import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  msfConnect,
  msfDisconnect,
  msfListExploits,
  msfRunExploit,
  msfGetSessions,
  getMsfStatus,
  cleanupMsf,
} from '../src/main/metasploitRpc.js';
import http from 'http';

// Mock http module
vi.mock('http', () => {
  const mockRequest = vi.fn();
  return {
    default: { request: mockRequest },
    request: mockRequest,
  };
});

vi.mock('https', () => {
  const mockRequest = vi.fn();
  return {
    default: { request: mockRequest },
    request: mockRequest,
  };
});

/**
 * Helper: simulate an http.request that returns a given JSON body.
 */
function mockHttpResponse(responseBody, statusCode = 200) {
  const mockReq = {
    on: vi.fn(),
    write: vi.fn(),
    end: vi.fn(),
    destroy: vi.fn(),
  };

  http.request.mockImplementation((options, callback) => {
    // Simulate async response
    const res = {
      statusCode,
      on: vi.fn((event, handler) => {
        if (event === 'data') {
          handler(JSON.stringify(responseBody));
        }
        if (event === 'end') {
          handler();
        }
      }),
    };
    // Call the callback asynchronously (like real http)
    setTimeout(() => callback(res), 0);
    return mockReq;
  });

  return mockReq;
}

/**
 * Helper: simulate an http.request that triggers an error.
 */
function mockHttpError(errorMessage) {
  const mockReq = {
    on: vi.fn((event, handler) => {
      if (event === 'error') {
        setTimeout(() => handler(new Error(errorMessage)), 0);
      }
    }),
    write: vi.fn(),
    end: vi.fn(),
    destroy: vi.fn(),
  };

  http.request.mockImplementation((options, callback) => {
    return mockReq;
  });

  return mockReq;
}

describe('Metasploit RPC Module', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    // Ensure we start disconnected
    await cleanupMsf();
  });

  // ── Input Validation ──────────────────────────────────────────────────────

  describe('Input Validation — msfConnect', () => {
    it('should reject null options', async () => {
      await expect(msfConnect(null)).rejects.toThrow('Invalid connection options');
    });

    it('should reject empty host', async () => {
      await expect(msfConnect({ host: '', port: 55553, password: 'pass' }))
        .rejects.toThrow('Host is required');
    });

    it('should reject invalid host format with special characters', async () => {
      await expect(msfConnect({ host: 'evil;<script>', port: 55553, password: 'pass' }))
        .rejects.toThrow('Invalid host format');
    });

    it('should reject invalid port (too high)', async () => {
      await expect(msfConnect({ host: '127.0.0.1', port: 99999, password: 'pass' }))
        .rejects.toThrow('Port must be between 1 and 65535');
    });

    it('should reject invalid port (zero)', async () => {
      await expect(msfConnect({ host: '127.0.0.1', port: 0, password: 'pass' }))
        .rejects.toThrow('Port must be between 1 and 65535');
    });

    it('should reject missing password', async () => {
      await expect(msfConnect({ host: '127.0.0.1', port: 55553, password: '' }))
        .rejects.toThrow('Password is required');
    });

    it('should warn for non-localhost connections', async () => {
      mockHttpResponse({ result: 'success', token: 'abc123' });

      const result = await msfConnect({
        host: '10.0.0.5', port: 55553, password: 'pass',
      });
      expect(result.warning).toContain('non-localhost');
    });

    it('should not warn for localhost connections', async () => {
      mockHttpResponse({ result: 'success', token: 'abc123' });

      const result = await msfConnect({
        host: '127.0.0.1', port: 55553, password: 'pass',
      });
      expect(result.warning).toBeNull();
    });
  });

  describe('Input Validation — msfRunExploit', () => {
    it('should reject if not connected', async () => {
      await expect(msfRunExploit({
        modulePath: 'exploit/test',
        targetIp: '192.168.1.1',
      })).rejects.toThrow('Not connected');
    });

    it('should reject invalid module path characters (after connecting)', async () => {
      // First connect
      mockHttpResponse({ result: 'success', token: 'tok123' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      // Then try to run with bad module path
      await expect(msfRunExploit({
        modulePath: 'exploit/test; rm -rf /',
        targetIp: '192.168.1.1',
      })).rejects.toThrow('invalid characters');
    });

    it('should reject missing target IP (after connecting)', async () => {
      mockHttpResponse({ result: 'success', token: 'tok123' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      await expect(msfRunExploit({
        modulePath: 'exploit/test/foo',
        targetIp: '',
      })).rejects.toThrow('Valid target IP is required');
    });

    it('should reject invalid target port (after connecting)', async () => {
      mockHttpResponse({ result: 'success', token: 'tok123' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      await expect(msfRunExploit({
        modulePath: 'exploit/test/foo',
        targetIp: '192.168.1.1',
        targetPort: 99999,
      })).rejects.toThrow('Target port must be between 1 and 65535');
    });
  });

  describe('Input Validation — msfListExploits', () => {
    it('should reject if not connected', async () => {
      await expect(msfListExploits('smb')).rejects.toThrow('Not connected');
    });

    it('should reject empty search query (after connecting)', async () => {
      mockHttpResponse({ result: 'success', token: 'tok123' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      await expect(msfListExploits('')).rejects.toThrow('Search query is required');
    });

    it('should reject query with only invalid characters (after connecting)', async () => {
      mockHttpResponse({ result: 'success', token: 'tok123' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      await expect(msfListExploits('!@#$%^&*()')).rejects.toThrow('invalid characters');
    });
  });

  // ── Connection Lifecycle ──────────────────────────────────────────────────

  describe('Connection Lifecycle', () => {
    it('should connect successfully with valid token response', async () => {
      mockHttpResponse({ token: 'valid-token-123' });

      const result = await msfConnect({
        host: '127.0.0.1', port: 55553, password: 'pass',
      });

      expect(result.status).toBe('connected');
      expect(getMsfStatus().state).toBe('connected');
    });

    it('should connect successfully with result:success response', async () => {
      mockHttpResponse({ result: 'success', token: 'tk-abc' });

      const result = await msfConnect({
        host: '127.0.0.1', port: 55553, password: 'pass',
      });

      expect(result.status).toBe('connected');
    });

    it('should reject double connect', async () => {
      mockHttpResponse({ token: 'tok-1' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      await expect(msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass2' }))
        .rejects.toThrow('Already connected');
    });

    it('should disconnect successfully', async () => {
      mockHttpResponse({ token: 'tok-dc' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      mockHttpResponse({ result: 'success' });
      const result = await msfDisconnect();

      expect(result.status).toBe('disconnected');
      expect(getMsfStatus().state).toBe('disconnected');
    });

    it('should handle disconnect when already disconnected', async () => {
      const result = await msfDisconnect();
      expect(result.status).toBe('disconnected');
    });

    it('should set error state on connection failure', async () => {
      mockHttpError('ECONNREFUSED');

      await expect(msfConnect({
        host: '127.0.0.1', port: 55553, password: 'pass',
      })).rejects.toThrow('ECONNREFUSED');

      expect(getMsfStatus().state).toBe('error');
    });

    it('should fail when no token received', async () => {
      mockHttpResponse({ result: 'failure' });

      await expect(msfConnect({
        host: '127.0.0.1', port: 55553, password: 'pass',
      })).rejects.toThrow('Authentication failed');
    });
  });

  // ── getMsfStatus ──────────────────────────────────────────────────────────

  describe('getMsfStatus', () => {
    it('should return disconnected state initially', () => {
      const status = getMsfStatus();
      expect(status.state).toBe('disconnected');
      expect(status.host).toBeNull();
      expect(status.port).toBeNull();
    });

    it('should return connected state with host/port after connecting', async () => {
      mockHttpResponse({ token: 'status-tok' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      const status = getMsfStatus();
      expect(status.state).toBe('connected');
      expect(status.host).toBe('127.0.0.1');
      expect(status.port).toBe(55553);
    });
  });

  // ── cleanupMsf ────────────────────────────────────────────────────────────

  describe('cleanupMsf', () => {
    it('should disconnect and reset state', async () => {
      mockHttpResponse({ token: 'cleanup-tok' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      // Mock the disconnect RPC call
      mockHttpResponse({ result: 'success' });
      await cleanupMsf();

      expect(getMsfStatus().state).toBe('disconnected');
    });

    it('should be safe to call when already disconnected', async () => {
      await cleanupMsf();
      expect(getMsfStatus().state).toBe('disconnected');
    });
  });

  // ── HTTP Request Construction ─────────────────────────────────────────────

  describe('HTTP Request Construction', () => {
    it('should POST to /api/ with correct headers', async () => {
      mockHttpResponse({ token: 'req-tok' });

      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'testpass' });

      expect(http.request).toHaveBeenCalledWith(
        expect.objectContaining({
          hostname: '127.0.0.1',
          port: 55553,
          path: '/api/',
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        }),
        expect.any(Function)
      );
    });

    it('should send JSON body with method and params', async () => {
      const mockReq = mockHttpResponse({ token: 'write-tok' });

      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      // Verify the request body was written
      expect(mockReq.write).toHaveBeenCalled();
      const body = JSON.parse(mockReq.write.mock.calls[0][0]);
      expect(body.method).toBe('auth.login');
      expect(body.params).toContain('pass');
    });

    it('should use default username msf', async () => {
      const mockReq = mockHttpResponse({ token: 'user-tok' });

      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      const body = JSON.parse(mockReq.write.mock.calls[0][0]);
      expect(body.params).toEqual(['msf', 'pass']);
    });

    it('should use custom username when provided', async () => {
      const mockReq = mockHttpResponse({ token: 'cuser-tok' });

      await msfConnect({ host: '127.0.0.1', port: 55553, username: 'admin', password: 'pass' });

      const body = JSON.parse(mockReq.write.mock.calls[0][0]);
      expect(body.params[0]).toBe('admin');
    });
  });

  // ── Exploit Search ────────────────────────────────────────────────────────

  describe('Exploit Search', () => {
    it('should return parsed exploit array', async () => {
      // Connect first
      mockHttpResponse({ token: 'search-tok' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      // Mock search response
      mockHttpResponse([
        { name: 'ms17_010', fullname: 'exploit/windows/smb/ms17_010_eternalblue', description: 'EternalBlue', rank: 'great', disclosure_date: '2017-03-14' },
        { name: 'psexec', fullname: 'exploit/windows/smb/psexec', description: 'PsExec', rank: 'normal', disclosure_date: '2004-01-01' },
      ]);

      const results = await msfListExploits('smb');
      expect(results).toHaveLength(2);
      expect(results[0].fullname).toBe('exploit/windows/smb/ms17_010_eternalblue');
      expect(results[0].rank).toBe('great');
      expect(results[0].date).toBe('2017-03-14');
    });

    it('should return empty array when no results', async () => {
      mockHttpResponse({ token: 'empty-tok' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      mockHttpResponse([]);
      const results = await msfListExploits('nonexistent');
      expect(results).toEqual([]);
    });

    it('should return empty array for non-array response', async () => {
      mockHttpResponse({ token: 'nona-tok' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      mockHttpResponse({ result: 'no modules' });
      const results = await msfListExploits('test');
      expect(results).toEqual([]);
    });

    it('should sanitize search query', async () => {
      mockHttpResponse({ token: 'san-tok' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      const mockReq = mockHttpResponse([]);
      await msfListExploits('test<script>alert(1)</script>');

      const body = JSON.parse(mockReq.write.mock.calls[0][0]);
      // Query should have special chars stripped
      expect(body.params[1]).not.toContain('<');
      expect(body.params[1]).not.toContain('>');
    });
  });

  // ── Session List ──────────────────────────────────────────────────────────

  describe('Session List', () => {
    it('should parse session objects', async () => {
      mockHttpResponse({ token: 'sess-tok' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      mockHttpResponse({
        '1': { type: 'meterpreter', info: 'NT AUTHORITY\\SYSTEM', target_host: '192.168.1.10', session_port: '445', via_exploit: 'exploit/windows/smb/ms17_010_eternalblue', platform: 'windows' },
        '2': { type: 'shell', info: 'root@target', target_host: '10.0.0.5', session_port: '22', via_exploit: 'exploit/linux/ssh/foo', platform: 'linux' },
      });

      const sessions = await msfGetSessions();
      expect(sessions).toHaveLength(2);
      expect(sessions[0].id).toBe('1');
      expect(sessions[0].type).toBe('meterpreter');
      expect(sessions[0].target).toBe('192.168.1.10');
      expect(sessions[1].platform).toBe('linux');
    });

    it('should return empty array when no sessions', async () => {
      mockHttpResponse({ token: 'nosess-tok' });
      await msfConnect({ host: '127.0.0.1', port: 55553, password: 'pass' });

      mockHttpResponse({});
      const sessions = await msfGetSessions();
      expect(sessions).toEqual([]);
    });

    it('should reject if not connected', async () => {
      await expect(msfGetSessions()).rejects.toThrow('Not connected');
    });
  });

  // ── Error Handling ────────────────────────────────────────────────────────

  describe('Error Handling', () => {
    it('should handle RPC error responses', async () => {
      mockHttpResponse({ error: { message: 'Auth token invalid' } });

      await expect(msfConnect({
        host: '127.0.0.1', port: 55553, password: 'pass',
      })).rejects.toThrow('Auth token invalid');
    });

    it('should handle malformed JSON response', async () => {
      // Simulate a broken JSON response
      const mockReq = {
        on: vi.fn(),
        write: vi.fn(),
        end: vi.fn(),
        destroy: vi.fn(),
      };

      http.request.mockImplementation((options, callback) => {
        const res = {
          statusCode: 200,
          on: vi.fn((event, handler) => {
            if (event === 'data') handler('not-json{{{');
            if (event === 'end') handler();
          }),
        };
        setTimeout(() => callback(res), 0);
        return mockReq;
      });

      await expect(msfConnect({
        host: '127.0.0.1', port: 55553, password: 'pass',
      })).rejects.toThrow('Failed to parse RPC response');
    });

    it('should handle connection error', async () => {
      mockHttpError('connect ECONNREFUSED 127.0.0.1:55553');

      await expect(msfConnect({
        host: '127.0.0.1', port: 55553, password: 'pass',
      })).rejects.toThrow('ECONNREFUSED');
    });
  });
});
