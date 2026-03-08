import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import ping from 'ping';
import { Notification } from 'electron';
import { enrichHost, getArpTable } from '../src/main/scanner.js';
import * as scanner from '../src/main/scanner.js';

// Mock electron
vi.mock('electron', () => ({
  Notification: vi.fn().mockImplementation(() => ({
    show: vi.fn()
  })),
  ipcMain: {
    handle: vi.fn(),
    on: vi.fn()
  }
}));

// Mock dependencies of hardeningMonitor.js
vi.mock('electron-store', () => {
  let storeData = {};
  return {
    default: class MockStore {
      constructor() {
        this.get = vi.fn((key) => storeData[key]);
        this.set = vi.fn((key, val) => { storeData[key] = val; });
        this.clear = vi.fn(() => { storeData = {}; });
      }
    }
  };
});

// Mock ping
vi.mock('ping', () => ({
  default: {
    promise: {
      probe: vi.fn()
    }
  }
}));

vi.mock('#shared/networkConstants.js', () => ({
  expandCIDR: vi.fn().mockImplementation((cidr) => {
    if (cidr === '10.0.0.0/29') return ['10.0.0.0', '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.6', '10.0.0.7'];
    if (cidr === '10.0.0.0/24') return ['10.0.0.1', '10.0.0.2']; // Minimal for cycle test
    return [];
  }),
  COMMON_PORTS: [80, 443]
}));

// Re-add scanner imports to resolve ReferenceError
vi.mock('../src/main/scanner.js', async (importOriginal) => {
  return {
    enrichHost: vi.fn(),
    getArpTable: vi.fn().mockResolvedValue({}),
    SCAN_ERROR_CHANNELS: { SCAN_ERROR: 'scan-error' }
  };
});

// NOW import the module under test
import * as monitor from '../src/main/hardeningMonitor.js';

describe('Hardening Monitor Module', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('validateCidr', () => {
    it('should validate correct CIDR notations', () => {
      expect(monitor.validateCidr('192.168.1.0/24')).toBe('192.168.1.0/24');
      expect(monitor.validateCidr('10.0.0.0/16')).toBe('10.0.0.0/16'); // Safe range is 16-32
    });

    it('should throw on invalid CIDR notations', () => {
      expect(() => monitor.validateCidr('invalid')).toThrow();
      expect(() => monitor.validateCidr('192.168.1.1')).toThrow(); // missing prefix
      expect(() => monitor.validateCidr('192.168.1.0/33')).toThrow(); // invalid prefix
      expect(() => monitor.validateCidr('10.0.0.0/8')).toThrow(); // out of safe range
    });
  });

  describe('pingHost', () => {
    it('should return alive status and time', async () => {
      ping.promise.probe.mockResolvedValue({ alive: true, time: 15 });
      const result = await monitor.pingHost('10.0.0.1');
      expect(result).toEqual({ alive: true, time: 15 });
    });

    it('should handle offline hosts', async () => {
      ping.promise.probe.mockResolvedValue({ alive: false, time: null });
      const result = await monitor.pingHost('10.0.0.2');
      expect(result.alive).toBe(false);
    });
  });

  describe('sweepSubnet', () => {
    it('should return a list of alive IPs', async () => {
      // Mock 10.0.0.1 and 10.0.0.3 as alive
      ping.promise.probe.mockImplementation((ip) => {
        if (ip === '10.0.0.1' || ip === '10.0.0.3') {
          return Promise.resolve({ alive: true, time: 10 });
        }
        return Promise.resolve({ alive: false, time: null });
      });

      const alive = await monitor.sweepSubnet('10.0.0.0/29'); // tiny range
      expect(alive).toContain('10.0.0.1');
      expect(alive).toContain('10.0.0.3');
      expect(alive).not.toContain('10.0.0.2');
    });
  });

  describe('diffSnapshots', () => {
    it('should detect new hosts', () => {
      const baseline = [{ ip: '10.0.0.1', mac: 'AA:BB' }];
      const current = [
        { ip: '10.0.0.1', mac: 'AA:BB' },
        { ip: '10.0.0.2', mac: 'CC:DD' }
      ];
      const delta = monitor.diffSnapshots(baseline, current);
      expect(delta.newHosts).toHaveLength(1);
      expect(delta.newHosts[0].ip).toBe('10.0.0.2');
    });

    it('should detect disappeared hosts', () => {
      const baseline = [{ ip: '10.0.0.1' }, { ip: '10.0.0.2' }];
      const current = [{ ip: '10.0.0.1' }];
      const delta = monitor.diffSnapshots(baseline, current);
      expect(delta.removedHosts).toHaveLength(1);
      expect(delta.removedHosts[0].ip).toBe('10.0.0.2');
    });

    it('should detect port changes', () => {
      const baseline = [{ ip: '10.0.0.1', ports: [{ port: 80 }] }];
      const current = [{ ip: '10.0.0.1', ports: [{ port: 80 }, { port: 443 }] }];
      const delta = monitor.diffSnapshots(baseline, current);
      expect(delta.changedHosts).toHaveLength(1);
      expect(delta.changedHosts[0].newPorts.some(p => p.port === 443)).toBe(true);
      expect(delta.severity).toBe('critical'); // New ports = critical
    });

    it('should detect MAC and hostname changes', () => {
      const baseline = [{ ip: '10.0.0.1', mac: 'OLD-MAC', hostname: 'OLD-HOST' }];
      const current = [{ ip: '10.0.0.1', mac: 'NEW-MAC', hostname: 'NEW-HOST' }];
      const delta = monitor.diffSnapshots(baseline, current);
      expect(delta.changedHosts).toHaveLength(1);
      expect(delta.changedHosts[0].macChanged).toBe(true);
      expect(delta.changedHosts[0].hostnameChanged).toBe(true);
      expect(delta.severity).toBe('warning'); // MAC/Host changes = warning
    });

    it('should return null if no changes', () => {
      const baseline = [{ ip: '10.0.0.1' }];
      const current = [{ ip: '10.0.0.1' }];
      const delta = monitor.diffSnapshots(baseline, current);
      expect(delta).toBeNull();
    });
  });

  describe('Baseline Management', () => {
    it('should set and get baseline', () => {
      monitor.setBaseline('192.168.1.0/24', [{ ip: '1.2.3.4' }]);
      const baseline = monitor.getBaseline('192.168.1.0/24');
      expect(baseline).not.toBeNull();
      expect(baseline.hosts[0].ip).toBe('1.2.3.4');
    });

    it('should return null for non-existent baseline', () => {
      expect(monitor.getBaseline('non-existent')).toBeNull();
    });
  });

  describe('Monitor Lifecycle', () => {
    it('should start and stop a monitor', async () => {
      const mockWindow = { webContents: { send: vi.fn() } };
      
      // Setup mock for scan
      enrichHost.mockResolvedValue({ ip: '10.0.0.1', mac: 'M1', ports: [] });
      ping.promise.probe.mockResolvedValue({ alive: true });

      // startMonitor triggers runMonitorCycle background
      await monitor.startMonitor('10.0.0.0/24', { intervalMs: 60000 }, mockWindow);
      
      const monitors = monitor.getActiveMonitors();
      expect(monitors['10.0.0.0/24']).toBeDefined();
      
      monitor.stopMonitor('10.0.0.0/24');
      expect(monitor.getActiveMonitors()['10.0.0.0/24']).toBeUndefined();
    });

    it('should handle errors during start', async () => {
      const mockWindow = { webContents: { send: vi.fn() } };
      const spy = vi.fn();
      mockWindow.webContents.send = spy;
      
      // Invalid CIDR should call status with error
      await monitor.startMonitor('invalid/cidr', {}, mockWindow);
      expect(spy).toHaveBeenCalledWith('hardening-monitor-status', expect.objectContaining({ state: 'error' }));
    });

    it('should respect minimum interval', async () => {
      const mockWindow = { webContents: { send: vi.fn() } };
      await monitor.startMonitor('10.0.0.0/24', { intervalMs: 1000 }, mockWindow); // too low
      
      const monitors = monitor.getActiveMonitors();
      expect(monitors['10.0.0.0/24'].options.intervalMs).toBe(60000);
      monitor.stopMonitor('10.0.0.0/24');
    });

    it('should run recurring cycles and detect deltas', async () => {
      const { expandCIDR } = await import('#shared/networkConstants.js');
      // Override mock for this test
      expandCIDR.mockReturnValue(['10.0.0.1', '10.0.0.2']);

      const mockWindow = { webContents: { send: vi.fn() } };
      const spy = mockWindow.webContents.send;

      // Set a baseline first: only 10.0.0.1
      monitor.setBaseline('10.0.0.0/24', [{ ip: '10.0.0.1', mac: 'M1', ports: [] }]);

      // Mock ping: both IPs are alive
      ping.promise.probe.mockImplementation((ip) => Promise.resolve({ alive: true }));
      
      // Mock enrichHost
      enrichHost.mockImplementation((ip) => Promise.resolve({ 
        ip, 
        mac: ip === '10.0.0.1' ? 'M1' : 'M2', 
        ports: [] 
      }));

      // Initial run: should detect 10.0.0.2 as new
      monitor.startMonitor('10.0.0.0/24', { intervalMs: 60000 }, mockWindow);
      
      // Poll for the expected call because runMonitorCycle is not awaited in startMonitor
      await vi.waitUntil(() => spy.mock.calls.some(c => c[0] === 'hardening-delta-alert'), {
        timeout: 1000,
        interval: 10
      });

      expect(spy).toHaveBeenCalledWith('hardening-delta-alert', expect.objectContaining({
        newHosts: expect.arrayContaining([expect.objectContaining({ ip: '10.0.0.2' })])
      }));

      monitor.stopAllMonitors();
    });

    it('should handle sweep abort', async () => {
      const { expandCIDR } = await import('../src/shared/networkConstants.js');
      expandCIDR.mockReturnValue(['10.0.0.1', '10.0.0.2']);
      
      const controller = new AbortController();
      controller.abort();
      
      const alive = await monitor.sweepSubnet('10.0.0.0/24', controller.signal);
      expect(alive).toHaveLength(0);
    });

    it('should sweep in multiple batches', async () => {
      const { expandCIDR } = await import('../src/shared/networkConstants.js');
      // Generate 30 IPs to trigger multiple batches (concurrency is 25)
      const ips = Array.from({ length: 30 }, (_, i) => `10.0.0.${i + 1}`);
      expandCIDR.mockReturnValue(ips);
      
      ping.promise.probe.mockResolvedValue({ alive: true });
      
      const alive = await monitor.sweepSubnet('10.0.0.0/24');
      expect(alive).toHaveLength(30);
    });
  });
});
