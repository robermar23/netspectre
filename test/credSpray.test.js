import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock dependencies
vi.mock('electron', () => ({
  app: {},
  ipcMain: {},
}));

vi.mock('../src/shared/networkConstants.js', () => ({
  IOT_DEFAULT_CREDENTIALS: [
    { user: 'admin', pass: 'admin' },
    { user: 'admin', pass: 'password' },
    { user: 'root', pass: 'admin' }
  ],
  ipRegex: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/
}));

vi.mock('../src/main/store.js', () => {
  return {
    getSetting: vi.fn((key) => {
      if (key === 'pentestConsentAccepted') return true;
      return null;
    }),
    setSetting: vi.fn()
  };
});

// Mock the newly-extracted transport layer
vi.mock('../src/main/credSprayTransports.js', () => ({
  sprayHttpBasic: vi.fn(),
  sprayHttpForm: vi.fn(),
  sprayTelnet: vi.fn()
}));

describe('Credential Spray Engine Orchestrator', () => {
  let credSpray;
  let transports;
  
  beforeEach(async () => {
    vi.resetModules();
    vi.clearAllMocks();
    credSpray = await import('../src/main/credSpray.js');
    transports = await import('../src/main/credSprayTransports.js');
  });

  afterEach(() => {
    credSpray.cleanupCredSpray();
  });

  it('should initialize correctly', () => {
    expect(credSpray.startCredSpray).toBeDefined();
    expect(credSpray.stopCredSpray).toBeDefined();
  });

  it('should reject if pentest consent is missing', async () => {
    const store = await import('../src/main/store.js');
    store.getSetting.mockReturnValueOnce(false); // No consent

    const onHit = vi.fn();
    const onProgress = vi.fn();
    const onComplete = vi.fn();
    const onError = vi.fn();

    const opts = { targetIp: '127.0.0.1', protocols: ['http-basic'], ports: { 'http-basic': 80 }, targets: ['127.0.0.1'], credentials: [{user: 'admin', pass: 'password'}] };

    await credSpray.startCredSpray(opts, onHit, onProgress, onComplete, onError);

    expect(onError).toHaveBeenCalledWith(expect.objectContaining({
      message: expect.stringContaining('consent')
    }));
  });

  it('should emit progress and complete events on a successful dry string', async () => {
    transports.sprayHttpBasic.mockResolvedValue([]); // No hits

    const onHit = vi.fn();
    const onProgress = vi.fn();
    const onError = vi.fn();

    const opts = { targets: ['127.0.0.1'], protocols: ['http-basic'], ports: { 'http-basic': 80 }, concurrency: 1, credentials: [{user: 'admin', pass: 'admin'}], delayMs: 1, timeoutMs: 1 };
    
    const finalComplete = await new Promise(resolve => {
      credSpray.startCredSpray(opts, onHit, onProgress, resolve, onError);
    });

    // Should have reported 1 progress tick
    expect(onProgress).toHaveBeenCalledWith(expect.objectContaining({
      attempt: 0, total: 1
    }));

    // Should have finished with no hits
    expect(finalComplete).toEqual(expect.objectContaining({
      hits: 0, aborted: false
    }));
    expect(onHit).not.toHaveBeenCalled();
  });

  it('should map successful transport hits back to the orchestrator', async () => {
    transports.sprayHttpBasic.mockResolvedValue([{ user: 'admin', pass: 'password', evidence: 'HTTP 200 OK' }]);

    const onHit = vi.fn();
    const onProgress = vi.fn();
    const onError = vi.fn();

    const opts = { targets: ['192.168.1.1'], protocols: ['http-basic'], ports: { 'http-basic': 80 }, concurrency: 1, credentials: [{user: 'admin', pass: 'password'}], delayMs: 1, timeoutMs: 1 };

    const finalComplete = await new Promise(resolve => {
      credSpray.startCredSpray(opts, onHit, onProgress, resolve, onError);
    });

    expect(onHit).toHaveBeenCalledWith(expect.objectContaining({
      user: 'admin', pass: 'password', severity: 'critical'
    }));

    expect(finalComplete).toEqual(expect.objectContaining({
      hits: 1
    }));
  });

  it('should handle Form transport mocks', async () => {
    transports.sprayHttpForm.mockResolvedValue([{ user: 'root', pass: 'admin', evidence: 'Redirected' }]);

    const onHit = vi.fn();
    const onProgress = vi.fn();
    const onError = vi.fn();

    const opts = { targets: ['192.168.1.1'], protocols: ['http-form'], ports: { 'http-form': 80 }, path: '/login', concurrency: 1, credentials: [{user: 'root', pass: 'admin'}], delayMs: 1, timeoutMs: 1 };

    const finalComplete = await new Promise(resolve => {
      credSpray.startCredSpray(opts, onHit, onProgress, resolve, onError);
    });

    expect(onHit).toHaveBeenCalledWith(expect.objectContaining({
      user: 'root', pass: 'admin', severity: 'critical'
    }));

    expect(finalComplete).toEqual(expect.objectContaining({
      hits: 1
    }));
  });

  it('should ignore transport module errors gracefully and resume gracefully', async () => {
    transports.sprayHttpBasic.mockRejectedValue(new Error('ECONNREFUSED'));

    const onHit = vi.fn();
    const onProgress = vi.fn();
    const onError = vi.fn();

    const opts = { targets: ['192.168.1.1'], protocols: ['http-basic'], ports: { 'http-basic': 80 }, concurrency: 1, credentials: [{user: 'admin', pass: 'admin'}], delayMs: 1, timeoutMs: 1 };

    const finalComplete = await new Promise(resolve => {
      credSpray.startCredSpray(opts, onHit, onProgress, resolve, onError);
    });

    // The error should have been caught via catch (err) block, and hits zeroed
    expect(finalComplete).toEqual(expect.objectContaining({
      hits: 0
    }));
  });

  it('can be manually aborted via the AbortController', async () => {
    // If we mock sprayHttpBasic to just hang via promise, we can stop the engine halfway
    transports.sprayHttpBasic.mockImplementation((ip, port, creds, signal) => new Promise((resolve) => {
        // Sleep until signal aborts // Deliberately omit resolving normally
        signal.addEventListener('abort', () => resolve([]));
    }));

    const onHit = vi.fn();
    const onProgress = vi.fn();
    const onError = vi.fn();

    const opts = { targets: ['192.168.1.1'], protocols: ['http-basic'], ports: { 'http-basic': 80 }, concurrency: 1, credentials: [{user: 'admin', pass: 'admin'}], delayMs: 1, timeoutMs: 1 };

    const sprayPromise = new Promise(resolve => {
      credSpray.startCredSpray(opts, onHit, onProgress, resolve, onError);
    });
    
    // Engine starts... wait 50ms, then abort
    setTimeout(() => {
      credSpray.stopCredSpray();
    }, 50);

    const finalComplete = await sprayPromise;

    // The aborted signal resolves softly
    expect(finalComplete).toEqual(expect.objectContaining({
      aborted: true
    }));
  });
});
