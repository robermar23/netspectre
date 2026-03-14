/**
 * Feature 5C — Container & Cloud Enumeration — Tests
 * Tests for all probe functions, severity classification, fingerprinting,
 * cancellation, concurrency, and IPC handler registration.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─── Module mocks ──────────────────────────────────────────────────────────────

vi.mock('http',  () => ({ default: { request: vi.fn() } }));
vi.mock('https', () => ({ default: { request: vi.fn() } }));
vi.mock('net',   () => ({ default: { Socket: vi.fn() } }));

import http  from 'http';
import https from 'https';
import net   from 'net';

import {
  probeDockerDaemon,
  probeDockerDaemonTLS,
  probeKubelet,
  probeKubeAPI,
  probeEtcd,
  probeCloudMetadata,
  probeConsul,
  probeVault,
  probePrometheus,
  probePortainer,
  probeGrafana,
  fingerprint,
  startCloudEnum,
  stopCloudEnum,
  cleanupCloudEnum,
  isCloudEnumRunning,
  registerIpcHandlers,
} from '../src/main/cloudEnum.js';

// ─── HTTP mock helpers ─────────────────────────────────────────────────────────

/**
 * Creates a mock HTTP response EventEmitter with the given status and body.
 */
function mockHttpResponse(statusCode, body, headers = {}) {
  const chunks = [Buffer.from(body)];
  const res = {
    statusCode,
    headers,
    on: vi.fn((event, handler) => {
      if (event === 'data') { for (const c of chunks) handler(c); }
      if (event === 'end')  handler();
      return res;
    }),
  };
  return res;
}

/**
 * Sets up http.request or https.request to call back with a mock response.
 */
function mockHttpRequest(lib, statusCode, body, headers = {}) {
  const req = {
    on: vi.fn((event, handler) => {
      // Don't trigger timeout/error automatically
      return req;
    }),
    end:     vi.fn(),
    destroy: vi.fn(),
  };
  lib.request.mockImplementation((opts, cb) => {
    // Call the response callback immediately
    cb(mockHttpResponse(statusCode, body, headers));
    return req;
  });
  return req;
}

/**
 * Sets up http/https.request to trigger a connection error.
 */
function mockHttpRequestError(lib, errorMsg = 'ECONNREFUSED') {
  const req = {
    on: vi.fn((event, handler) => {
      if (event === 'error') handler(new Error(errorMsg));
      return req;
    }),
    end:     vi.fn(),
    destroy: vi.fn(),
  };
  lib.request.mockImplementation(() => req);
  return req;
}

// ─── probeDockerDaemon ────────────────────────────────────────────────────────

describe('probeDockerDaemon', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns critical finding when port 2375 returns Docker version JSON', async () => {
    mockHttpRequest(http, 200, '{"ApiVersion":"1.41","Version":"20.10.7"}');
    const result = await probeDockerDaemon('192.168.1.1', null);
    expect(result).not.toBeNull();
    expect(result.severity).toBe('critical');
    expect(result.service).toBe('docker-daemon');
    expect(result.port).toBe(2375);
    expect(result.ip).toBe('192.168.1.1');
    expect(result.title).toMatch(/Docker/);
    expect(result.remediation).toBeTruthy();
    expect(result.references.length).toBeGreaterThan(0);
  });

  it('returns null when port 2375 returns non-Docker JSON', async () => {
    mockHttpRequest(http, 200, '{"message":"not docker"}');
    const result = await probeDockerDaemon('192.168.1.1', null);
    expect(result).toBeNull();
  });

  it('returns null when port 2375 returns HTTP 404', async () => {
    mockHttpRequest(http, 404, 'Not Found');
    const result = await probeDockerDaemon('192.168.1.1', null);
    expect(result).toBeNull();
  });

  it('returns null when connection is refused', async () => {
    mockHttpRequestError(http, 'ECONNREFUSED');
    const result = await probeDockerDaemon('192.168.1.1', null);
    expect(result).toBeNull();
  });

  it('returns null immediately when signal is already aborted', async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    const result = await probeDockerDaemon('192.168.1.1', ctrl.signal);
    expect(result).toBeNull();
    expect(http.request).not.toHaveBeenCalled();
  });

  it('rawResponse is capped at 500 characters', async () => {
    const longBody = '{"ApiVersion":"1.41","data":"' + 'x'.repeat(1000) + '"}';
    mockHttpRequest(http, 200, longBody);
    const result = await probeDockerDaemon('192.168.1.1', null);
    expect(result).not.toBeNull();
    expect(result.rawResponse.length).toBeLessThanOrEqual(500);
  });
});

// ─── probeDockerDaemonTLS ─────────────────────────────────────────────────────

describe('probeDockerDaemonTLS', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns warning finding when port 2376 returns Docker version JSON over HTTPS', async () => {
    mockHttpRequest(https, 200, '{"ApiVersion":"1.41"}');
    const result = await probeDockerDaemonTLS('192.168.1.1', null);
    expect(result).not.toBeNull();
    expect(result.severity).toBe('warning');
    expect(result.service).toBe('docker-daemon-tls');
    expect(result.port).toBe(2376);
  });

  it('returns null when TLS connection fails', async () => {
    mockHttpRequestError(https, 'CERT_HAS_EXPIRED');
    const result = await probeDockerDaemonTLS('192.168.1.1', null);
    expect(result).toBeNull();
  });
});

// ─── probeKubelet ─────────────────────────────────────────────────────────────

describe('probeKubelet', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns critical finding when port 10250 returns pod list', async () => {
    mockHttpRequest(https, 200, '{"items":[{"kind":"Pod"}],"apiVersion":"v1"}');
    const findings = await probeKubelet('10.0.0.1', null);
    const critical = findings.find(f => f.severity === 'critical');
    expect(critical).toBeDefined();
    expect(critical.port).toBe(10250);
    expect(critical.service).toBe('kubelet');
  });

  it('returns info finding when port 10250 returns 401 (auth enforced)', async () => {
    mockHttpRequest(https, 401, 'Unauthorized');
    const findings = await probeKubelet('10.0.0.1', null);
    const info = findings.find(f => f.severity === 'info' && f.port === 10250);
    expect(info).toBeDefined();
  });

  it('returns warning finding when port 10255 returns pod list (RO API)', async () => {
    // First call (10250) gets 401, second call (10255) returns 200
    https.request
      .mockImplementationOnce((opts, cb) => {
        cb(mockHttpResponse(401, 'Unauthorized'));
        return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
      })
      .mockImplementationOnce((opts, cb) => {
        cb(mockHttpResponse(200, '{"items":[]}'));
        return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
      });
    http.request.mockImplementationOnce((opts, cb) => {
      cb(mockHttpResponse(200, '{"items":[]}'));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });
    const findings = await probeKubelet('10.0.0.1', null);
    const warning = findings.find(f => f.severity === 'warning' && f.service === 'kubelet-ro');
    expect(warning).toBeDefined();
    expect(warning.port).toBe(10255);
  });

  it('returns empty array when all kubelet ports are closed', async () => {
    mockHttpRequestError(https);
    mockHttpRequestError(http);
    const findings = await probeKubelet('10.0.0.1', null);
    expect(findings).toEqual([]);
  });
});

// ─── probeKubeAPI ─────────────────────────────────────────────────────────────

describe('probeKubeAPI', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns critical finding when port 6443 returns cluster version unauthenticated', async () => {
    mockHttpRequest(https, 200, '{"gitVersion":"v1.26.0","major":"1"}');
    const result = await probeKubeAPI('10.0.0.1', null);
    expect(result.severity).toBe('critical');
    expect(result.service).toBe('kube-api');
    expect(result.port).toBe(6443);
  });

  it('returns info finding when port 6443 returns 401 (auth required)', async () => {
    mockHttpRequest(https, 401, 'Unauthorized');
    const result = await probeKubeAPI('10.0.0.1', null);
    expect(result).not.toBeNull();
    expect(result.severity).toBe('info');
  });

  it('returns info finding when port 6443 returns 403', async () => {
    mockHttpRequest(https, 403, 'Forbidden');
    const result = await probeKubeAPI('10.0.0.1', null);
    expect(result).not.toBeNull();
    expect(result.severity).toBe('info');
  });

  it('returns null when port is closed', async () => {
    mockHttpRequestError(https);
    const result = await probeKubeAPI('10.0.0.1', null);
    expect(result).toBeNull();
  });
});

// ─── probeEtcd ────────────────────────────────────────────────────────────────

describe('probeEtcd', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns critical finding when etcd version endpoint responds', async () => {
    mockHttpRequest(http, 200, '{"etcdserver":"3.5.0","etcdcluster":"3.5.0"}');
    const result = await probeEtcd('10.0.0.1', null);
    expect(result.severity).toBe('critical');
    expect(result.service).toBe('etcd');
    expect(result.port).toBe(2379);
  });

  it('returns null when etcd port returns unexpected body', async () => {
    mockHttpRequest(http, 200, '{"some":"other-service"}');
    const result = await probeEtcd('10.0.0.1', null);
    expect(result).toBeNull();
  });

  it('returns null when etcd port is closed', async () => {
    mockHttpRequestError(http);
    const result = await probeEtcd('10.0.0.1', null);
    expect(result).toBeNull();
  });
});

// ─── probeCloudMetadata ───────────────────────────────────────────────────────

describe('probeCloudMetadata', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns critical finding when AWS metadata endpoint responds', async () => {
    mockHttpRequest(http, 200, 'ami-id\nhostname\ninstance-id\n');
    const result = await probeCloudMetadata('169.254.169.254', null);
    expect(result).not.toBeNull();
    expect(result.severity).toBe('critical');
    expect(result.service).toBe('cloud-metadata');
    expect(result.port).toBe(80);
  });

  it('returns null when metadata endpoint returns empty body', async () => {
    mockHttpRequest(http, 200, '');
    const result = await probeCloudMetadata('169.254.169.254', null);
    expect(result).toBeNull();
  });

  it('returns null when all metadata paths return 404', async () => {
    mockHttpRequest(http, 404, 'Not Found');
    const result = await probeCloudMetadata('10.0.0.1', null);
    expect(result).toBeNull();
  });

  it('returns null when all metadata endpoints are unreachable', async () => {
    mockHttpRequestError(http);
    const result = await probeCloudMetadata('10.0.0.1', null);
    expect(result).toBeNull();
  });
});

// ─── probeConsul ──────────────────────────────────────────────────────────────

describe('probeConsul', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns warning finding when Consul leader endpoint responds', async () => {
    mockHttpRequest(http, 200, '"192.168.1.1:8300"');
    const result = await probeConsul('192.168.1.1', null);
    expect(result.severity).toBe('warning');
    expect(result.service).toBe('consul');
    expect(result.port).toBe(8500);
  });

  it('returns null when Consul port is closed', async () => {
    mockHttpRequestError(http);
    const result = await probeConsul('192.168.1.1', null);
    expect(result).toBeNull();
  });
});

// ─── probeVault ───────────────────────────────────────────────────────────────

describe('probeVault', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns warning finding when Vault is unsealed and accessible', async () => {
    mockHttpRequest(http, 200, '{"initialized":true,"sealed":false,"version":"1.12.0"}');
    const result = await probeVault('192.168.1.1', null);
    expect(result).not.toBeNull();
    expect(result.severity).toBe('warning');
    expect(result.service).toBe('vault');
  });

  it('returns info finding when Vault is sealed', async () => {
    mockHttpRequest(http, 200, '{"initialized":true,"sealed":true,"version":"1.12.0"}');
    const result = await probeVault('192.168.1.1', null);
    expect(result).not.toBeNull();
    expect(result.severity).toBe('info');
    expect(result.title).toMatch(/Sealed/);
  });

  it('returns null when Vault port is closed', async () => {
    mockHttpRequestError(http);
    const result = await probeVault('192.168.1.1', null);
    expect(result).toBeNull();
  });
});

// ─── probePrometheus ──────────────────────────────────────────────────────────

describe('probePrometheus', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns info finding when Prometheus ready endpoint responds', async () => {
    mockHttpRequest(http, 200, 'Prometheus is Ready.');
    const result = await probePrometheus('192.168.1.1', null);
    expect(result.severity).toBe('info');
    expect(result.service).toBe('prometheus');
    expect(result.port).toBe(9090);
  });

  it('returns null when Prometheus port is closed', async () => {
    mockHttpRequestError(http);
    const result = await probePrometheus('192.168.1.1', null);
    expect(result).toBeNull();
  });
});

// ─── probePortainer ───────────────────────────────────────────────────────────

describe('probePortainer', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns info finding when Portainer API status responds', async () => {
    mockHttpRequest(http, 200, '{"Version":"2.16.0","Authentication":true}');
    const result = await probePortainer('192.168.1.1', null);
    expect(result.severity).toBe('info');
    expect(result.service).toBe('portainer');
    expect(result.port).toBe(9000);
  });

  it('returns null when Portainer port is closed', async () => {
    mockHttpRequestError(http);
    const result = await probePortainer('192.168.1.1', null);
    expect(result).toBeNull();
  });
});

// ─── probeGrafana ─────────────────────────────────────────────────────────────

describe('probeGrafana', () => {
  beforeEach(() => vi.resetAllMocks());

  it('returns an info finding when /api/health responds with database field', async () => {
    mockHttpRequest(http, 200, '{"database":"ok","version":"10.0.0"}');
    const result = await probeGrafana('192.168.1.1', null);
    expect(result).not.toBeNull();
    expect(result.service).toBe('grafana');
    expect(result.port).toBe(3000);
    expect(result.severity).toBe('info');
    expect(result.title).toBeTruthy();
    expect(result.evidence).toMatch(/HTTP 200/);
  });

  it('returns null when /api/health response does not include database field', async () => {
    mockHttpRequest(http, 200, '{"status":"ok"}');
    const result = await probeGrafana('192.168.1.1', null);
    expect(result).toBeNull();
  });

  it('returns null when port is closed (connection error)', async () => {
    mockHttpRequestError(http, 'ECONNREFUSED');
    const result = await probeGrafana('192.168.1.1', null);
    expect(result).toBeNull();
  });

  it('returns null when server returns a non-200 status', async () => {
    mockHttpRequest(http, 404, 'Not Found');
    const result = await probeGrafana('192.168.1.1', null);
    expect(result).toBeNull();
  });

  it('respects AbortSignal and returns null when pre-aborted', async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    // No HTTP mock needed — signal check should short-circuit before any request
    const result = await probeGrafana('192.168.1.1', ctrl.signal);
    expect(result).toBeNull();
  });
});

// ─── fingerprint (full probe suite) ──────────────────────────────────────────

describe('fingerprint', () => {
  beforeEach(() => vi.resetAllMocks());

  it('runs all probes and aggregates findings for one host', async () => {
    // Docker responds, all else closed
    http.request.mockImplementation((opts, cb) => {
      if (opts.port === 2375) {
        cb(mockHttpResponse(200, '{"ApiVersion":"1.41"}'));
      } else {
        cb(mockHttpResponse(404, 'Not Found'));
      }
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });
    https.request.mockImplementation((opts, cb) => {
      cb(mockHttpResponse(404, 'Not Found'));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });

    const findings = [];
    await fingerprint('192.168.1.20', null, (f) => findings.push(f));
    const dockerFinding = findings.find(f => f.service === 'docker-daemon');
    expect(dockerFinding).toBeDefined();
    expect(dockerFinding.severity).toBe('critical');
  });

  it('respects AbortController across all sub-probes', async () => {
    const ctrl = new AbortController();
    ctrl.abort();

    const findings = [];
    await fingerprint('192.168.1.20', ctrl.signal, (f) => findings.push(f));
    expect(findings.length).toBe(0);
    // No HTTP requests should be initiated when signal is pre-aborted
  });

  it('emits findings via onFinding callback as they arrive', async () => {
    http.request.mockImplementation((opts, cb) => {
      if (opts.port === 8500) {
        cb(mockHttpResponse(200, '"192.168.1.1:8300"'));
      } else if (opts.port === 2379) {
        cb(mockHttpResponse(200, '{"etcdserver":"3.5.0"}'));
      } else {
        cb(mockHttpResponse(404, ''));
      }
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });
    https.request.mockImplementation((opts, cb) => {
      cb(mockHttpResponse(401, 'Unauthorized'));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });

    const emitted = [];
    await fingerprint('10.0.0.5', null, (f) => emitted.push(f));
    // At least consul and etcd should have been found
    expect(emitted.some(f => f.service === 'consul')).toBe(true);
    expect(emitted.some(f => f.service === 'etcd')).toBe(true);
  });

  it('handles all probes timing out gracefully', async () => {
    // All probes throw an error (simulating timeout)
    http.request.mockImplementation(() => {
      const req = {
        on: vi.fn((event, handler) => {
          if (event === 'error') handler(new Error('Timeout'));
          return req;
        }),
        end: vi.fn(), destroy: vi.fn(),
      };
      return req;
    });
    https.request.mockImplementation(() => {
      const req = {
        on: vi.fn((event, handler) => {
          if (event === 'error') handler(new Error('Timeout'));
          return req;
        }),
        end: vi.fn(), destroy: vi.fn(),
      };
      return req;
    });

    const findings = [];
    await expect(fingerprint('10.0.0.1', null, (f) => findings.push(f))).resolves.not.toThrow();
    expect(findings.length).toBe(0);
  });

  it('runs only enabled probes when enabledProbes is specified', async () => {
    const requestSpy = vi.fn((opts, cb) => {
      cb(mockHttpResponse(200, '{"ApiVersion":"1.41"}'));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });
    http.request.mockImplementation(requestSpy);
    https.request.mockImplementation(requestSpy);

    const findings = [];
    await fingerprint('10.0.0.1', null, (f) => findings.push(f), ['docker']);
    // Only Docker probes should have been attempted
    const ports = requestSpy.mock.calls.map(c => c[0].port);
    expect(ports.includes(2375)).toBe(true);
    expect(ports.includes(9090)).toBe(false); // prometheus not requested
  });
});

// ─── startCloudEnum ───────────────────────────────────────────────────────────

describe('startCloudEnum', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stopCloudEnum(); // ensure clean state
  });

  afterEach(() => {
    stopCloudEnum();
  });

  it('calls onError when no valid targets are provided', async () => {
    const onError = vi.fn();
    await startCloudEnum({ targets: [] }, vi.fn(), vi.fn(), vi.fn(), onError);
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('No valid IP') }));
  });

  it('calls onError when targets contain only invalid IPs', async () => {
    const onError = vi.fn();
    await startCloudEnum({ targets: ['not-an-ip', 'bad'] }, vi.fn(), vi.fn(), vi.fn(), onError);
    expect(onError).toHaveBeenCalled();
  });

  it('calls onError when a second session is started while one is running', async () => {
    // Start a slow scan
    http.request.mockImplementation(() => {
      const req = { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
      // Never calls the callback (hangs)
      return req;
    });
    https.request.mockImplementation(() => {
      const req = { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
      return req;
    });

    // Fire and forget — do not await
    startCloudEnum({ targets: ['192.168.1.1'] }, vi.fn(), vi.fn(), vi.fn(), vi.fn());

    // Try to start a second session immediately
    const onError = vi.fn();
    await startCloudEnum({ targets: ['192.168.1.2'] }, vi.fn(), vi.fn(), vi.fn(), onError);
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('already running') }));

    stopCloudEnum();
  });

  it('calls onComplete with summary when enumeration finishes', async () => {
    http.request.mockImplementation((opts, cb) => {
      cb(mockHttpResponse(404, ''));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });
    https.request.mockImplementation((opts, cb) => {
      cb(mockHttpResponse(404, ''));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });

    const onComplete = vi.fn();
    await startCloudEnum({ targets: ['192.168.1.1'] }, vi.fn(), vi.fn(), onComplete, vi.fn());
    expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({
      findings: expect.any(Number),
      critical: expect.any(Number),
      warning:  expect.any(Number),
      info:     expect.any(Number),
      elapsed:  expect.any(Number),
      aborted:  false,
    }));
  });

  it('emits onFinding for each discovery and tracks progress', async () => {
    http.request.mockImplementation((opts, cb) => {
      if (opts.port === 8500) {
        cb(mockHttpResponse(200, '"192.168.1.1:8300"')); // consul hit
      } else {
        cb(mockHttpResponse(404, ''));
      }
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });
    https.request.mockImplementation((opts, cb) => {
      cb(mockHttpResponse(404, ''));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });

    const findings = [];
    const progress = [];
    const onComplete = vi.fn();
    await startCloudEnum(
      { targets: ['192.168.1.1', '192.168.1.2'] },
      (f) => findings.push(f),
      (p) => progress.push(p),
      onComplete,
      vi.fn()
    );

    expect(findings.some(f => f.service === 'consul')).toBe(true);
    expect(progress.length).toBeGreaterThan(0);
    expect(progress[progress.length - 1].percent).toBe(100);
    expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({ aborted: false }));
  });

  it('marks complete as aborted when stopCloudEnum is called mid-run', async () => {
    // Make HTTP requests hang indefinitely
    http.request.mockImplementation(() => ({
      on: vi.fn().mockReturnThis(),
      end: vi.fn(),
      destroy: vi.fn(),
    }));
    https.request.mockImplementation(() => ({
      on: vi.fn().mockReturnThis(),
      end: vi.fn(),
      destroy: vi.fn(),
    }));

    const onComplete = vi.fn();
    const enumPromise = startCloudEnum(
      { targets: ['192.168.1.1'] },
      vi.fn(), vi.fn(),
      onComplete,
      vi.fn()
    );

    // Stop immediately
    stopCloudEnum();
    await enumPromise;

    expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({ aborted: true }));
  });
});

// ─── cleanupCloudEnum ─────────────────────────────────────────────────────────

describe('cleanupCloudEnum', () => {
  it('can be called when no session is running without throwing', () => {
    stopCloudEnum();
    expect(() => cleanupCloudEnum()).not.toThrow();
  });
});

// ─── registerIpcHandlers ──────────────────────────────────────────────────────

describe('registerIpcHandlers', () => {
  let ipcMain;
  let handlers;

  beforeEach(() => {
    handlers = {};
    ipcMain = {
      handle: vi.fn((channel, handler) => { handlers[channel] = handler; }),
    };
    stopCloudEnum();
    vi.clearAllMocks();
  });

  afterEach(() => {
    stopCloudEnum();
  });

  it('registers CLOUDENUM_START and CLOUDENUM_STOP handlers', () => {
    registerIpcHandlers(ipcMain, () => null);
    expect(ipcMain.handle).toHaveBeenCalledWith('cloudenum-start', expect.any(Function));
    expect(ipcMain.handle).toHaveBeenCalledWith('cloudenum-stop', expect.any(Function));
  });

  it('CLOUDENUM_START returns error status when no options are provided', async () => {
    registerIpcHandlers(ipcMain, () => null);
    const result = await handlers['cloudenum-start']({}, null);
    expect(result.status).toBe('error');
  });

  it('CLOUDENUM_START returns error when targets list is empty', async () => {
    registerIpcHandlers(ipcMain, () => null);
    const result = await handlers['cloudenum-start']({}, { targets: [] });
    expect(result.status).toBe('error');
  });

  it('CLOUDENUM_START filters out invalid IP targets', async () => {
    http.request.mockImplementation((opts, cb) => {
      cb(mockHttpResponse(404, ''));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });
    https.request.mockImplementation((opts, cb) => {
      cb(mockHttpResponse(404, ''));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });

    const window = { webContents: { send: vi.fn() } };
    registerIpcHandlers(ipcMain, () => window);

    const result = await handlers['cloudenum-start']({}, {
      targets: ['192.168.1.1', 'not-valid', '10.0.0.1'],
    });
    expect(result.status).toBe('started');
    expect(result.targets).toBe(2); // only valid IPs counted
  });

  it('CLOUDENUM_START returns error status when a session is already running', async () => {
    // Make HTTP requests hang indefinitely so session stays active
    http.request.mockImplementation(() => ({
      on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn(),
    }));
    https.request.mockImplementation(() => ({
      on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn(),
    }));

    registerIpcHandlers(ipcMain, () => ({ webContents: { send: vi.fn() } }));

    // Start first session (do not await — it hangs)
    handlers['cloudenum-start']({}, { targets: ['192.168.1.1'] });

    // Attempt a second session while first is running
    const result = await handlers['cloudenum-start']({}, { targets: ['192.168.1.2'] });
    expect(result.status).toBe('error');
    expect(result.error).toMatch(/already running/i);

    stopCloudEnum();
  });

  it('CLOUDENUM_STOP returns stopped status', async () => {
    registerIpcHandlers(ipcMain, () => null);
    const result = await handlers['cloudenum-stop']({});
    expect(result.status).toBe('stopped');
  });

  it('CLOUDENUM_START sends CLOUDENUM_FINDING events to renderer', async () => {
    const sentEvents = [];
    const win = { webContents: { send: vi.fn((channel, data) => sentEvents.push({ channel, data })) } };

    http.request.mockImplementation((opts, cb) => {
      // Simulate consul hit
      if (opts.port === 8500) cb(mockHttpResponse(200, '"10.0.0.1:8300"'));
      else cb(mockHttpResponse(404, ''));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });
    https.request.mockImplementation((opts, cb) => {
      cb(mockHttpResponse(404, ''));
      return { on: vi.fn().mockReturnThis(), end: vi.fn(), destroy: vi.fn() };
    });

    registerIpcHandlers(ipcMain, () => win);
    await handlers['cloudenum-start']({}, { targets: ['10.0.0.1'] });

    // Wait for async work
    await new Promise(r => setTimeout(r, 50));

    const findingEvents = sentEvents.filter(e => e.channel === 'cloudenum-finding');
    expect(findingEvents.length).toBeGreaterThan(0);
    expect(findingEvents[0].data.service).toBe('consul');
  });
});
