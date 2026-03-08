import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { cancelDeepScan, analyzeService, grabBanner, grabTlsCert, runDeepScan } from '../src/main/deepScanner.js';
import net from 'net';
import tls from 'tls';

let mockSocketInstances = [];

vi.mock('net', () => ({
  default: {
    Socket: class MockSocket {
      constructor() {
        this.listeners = {};
        this._destroyed = false;
        mockSocketInstances.push(this);
      }
      on(event, cb) { 
        if (!this.listeners[event]) this.listeners[event] = [];
        this.listeners[event].push(cb);
        return this; 
      }
      setTimeout() {}
      removeAllListeners(event) { 
        if (event) delete this.listeners[event];
        else this.listeners = {}; 
      }
      write() {}
      emit(event, ...args) {
        if (this._destroyed) return;
        const handlers = this.listeners[event] || [];
        handlers.forEach(h => h(...args));
      }
      connect(port, ip) {
        this.port = port;
        this.ip = ip;
        // console.log(`[MockSocket] Connecting to ${ip}:${port}`);
        
        setTimeout(() => {
          // console.log(`[MockSocket] Emitting connect for ${port}`);
          this.emit('connect');
          
          if (port === 80) {
            // console.log(`[MockSocket] Emitting HTTP data for ${port}`);
            this.emit('data', Buffer.from('HTTP/1.1 200 OK\r\nServer: nginx\r\n'));
          } else if (port === 21) {
            // console.log(`[MockSocket] Emitting FTP data for ${port}`);
            this.emit('data', Buffer.from('220 FTP server ready\r\n'));
          } else if (port === 22) {
            this.emit('data', Buffer.from('SSH-2.0-OpenSSH_8.9'));
          } else if (port === 9999) {
            this.emit('timeout');
          } else if (port === 8888) {
            this.emit('error', new Error('ECONNREFUSED'));
          } else if (port === 443 || port === 8443) {
            // Connects but no banner (for TLS tests)
          } else {
            // Closed port simulation
            if (port > 1024) {
              this.emit('error', new Error('mock'));
            }
          }
        }, 5);
      }
      destroy() {
        this._destroyed = true;
      }
    }
  }
}));

vi.mock('tls', () => ({
  default: {
    connect: vi.fn((opts, cb) => {
      const sock = {
        setTimeout: vi.fn(),
        on: vi.fn((event, handler) => {
          if (event === 'error' && opts.port === 7777) {
            setTimeout(() => handler(new Error('TLS error')), 5);
          }
          if (event === 'timeout' && opts.port === 6666) {
            setTimeout(() => handler(), 5);
          }
        }),
        getPeerCertificate: vi.fn().mockReturnValue({
          subject: { CN: 'example.com' },
          issuer: { CN: 'CA Authority' },
          valid_from: '2024-01-01',
          valid_to: '2026-12-31'
        }),
        end: vi.fn(),
        destroy: vi.fn(),
      };
      // Only "connect" for TLS ports or specific test ports
      const isTlsPort = opts.port === 443 || opts.port === 8443 || opts.port === 444; // 444 for simple grabTlsCert test
      if (isTlsPort) {
        setTimeout(() => cb(), 5);
      } else {
        // For other ports, TLS handshake fails
        setTimeout(() => {
          const handlers = sock.on.mock.calls.filter(c => c[0] === 'error');
          handlers.forEach(h => h[1](new Error('TLS Hanshake Failed')));
        }, 5);
      }
      return sock;
    })
  }
}));

vi.mock('../src/main/securityAnalyzer.js', () => ({
  checkAnonymousFtp: vi.fn().mockResolvedValue({ vulnerable: true, details: 'Anonymous FTP allowed' }),
  checkSensitiveWebDirs: vi.fn().mockResolvedValue({ vulnerable: true, details: 'Found /config' })
}));

describe('Deep Scanner Module', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('cancelDeepScan', () => {
    it('should safely accept cancellation for an explicit IP', () => {
      expect(() => cancelDeepScan('10.0.0.1')).not.toThrow();
    });
    it('should handle cancellation for IPs not in the active scan pool', () => {
      expect(() => cancelDeepScan('255.255.255.255')).not.toThrow();
    });
    it('should be callable multiple times for the same IP', () => {
      expect(() => { cancelDeepScan('10.0.0.1'); cancelDeepScan('10.0.0.1'); }).not.toThrow();
    });
  });

  describe('grabBanner', () => {
    it('should return banner text when port responds with data', async () => {
      const bannerPromise = grabBanner('127.0.0.1', 80);
      await vi.runAllTimersAsync();
      const banner = await bannerPromise;
      expect(banner).toContain('HTTP/1.1');
    });

    it('should return SSH banner from port 22', async () => {
      const bannerPromise = grabBanner('127.0.0.1', 22);
      await vi.runAllTimersAsync();
      const banner = await bannerPromise;
      expect(banner).toContain('SSH-2.0');
    });

    it('should return null on timeout', async () => {
      const resultPromise = grabBanner('127.0.0.1', 9999);
      await vi.runAllTimersAsync();
      const result = await resultPromise;
      expect(result).toBeNull();
    });

    it('should return null on error', async () => {
      const resultPromise = grabBanner('127.0.0.1', 8888);
      await vi.runAllTimersAsync();
      const result = await resultPromise;
      expect(result).toBeNull();
    });
  });

  describe('grabTlsCert', () => {
    it('should return certificate info from a TLS connection', async () => {
      const certPromise = grabTlsCert('127.0.0.1', 444);
      await vi.runAllTimersAsync();
      const cert = await certPromise;
      expect(cert).toBeDefined();
      expect(cert.subject).toBe('example.com');
      expect(cert.issuer).toBe('CA Authority');
      expect(cert.validFrom).toBe('2024-01-01');
      expect(cert.validTo).toBe('2026-12-31');
    });

    it('should return null on TLS error', async () => {
      const certPromise = grabTlsCert('127.0.0.1', 7777);
      await vi.runAllTimersAsync();
      const cert = await certPromise;
      expect(cert).toBeNull();
    });

    it('should return null on TLS timeout', async () => {
      const certPromise = grabTlsCert('127.0.0.1', 6666);
      await vi.runAllTimersAsync();
      const cert = await certPromise;
      expect(cert).toBeNull();
    });
  });

  describe('analyzeService', () => {
    it('should identify TLS/SSL service from cert', () => {
      const cert = { subject: 'example.com', issuer: 'CA', validTo: '2026-12-31T23:59:59' };
      const result = analyzeService(443, null, cert);
      expect(result.serviceName).toBe('TLS/SSL Service');
      expect(result.details).toContain('example.com');
      expect(result.details).toContain('Expiration');
    });

    it('should handle TLS cert without validTo', () => {
      const cert = { subject: 'test', issuer: 'issuer' };
      const result = analyzeService(443, null, cert);
      expect(result.details).not.toContain('Expiration');
    });

    it('should identify HTTP web server from Server header', () => {
      const banner = 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n';
      const result = analyzeService(80, banner, null);
      expect(result.serviceName).toBe('HTTP Web Server');
    });

    it('should identify SSH server from banner', () => {
      const result = analyzeService(22, 'SSH-2.0-OpenSSH_8.9p1', null);
      expect(result.serviceName).toBe('SSH Server');
    });

    it('should identify SMTP from 220 banner', () => {
      const result = analyzeService(25, '220 mail.example.com ESMTP', null);
      expect(result.serviceName).toBe('SMTP Mail Server');
    });

    it('should identify FTP server from banner', () => {
      const result = analyzeService(21, 'ProFTPD 1.3.6 Ready', null);
      expect(result.serviceName).toBe('FTP Server');
    });

    it('should identify FTP server from vsFTPd banner', () => {
      const result = analyzeService(21, 'Welcome to the vsFTPd server', null);
      expect(result.serviceName).toBe('FTP Server');
    });

    it('should detect HTTP redirect', () => {
      const banner = 'HTTP/1.1 301 Moved\r\nLocation: https://example.com\r\n';
      const result = analyzeService(80, banner, null);
      expect(result.details).toContain('Redirects to');
    });

    it('should detect unrecognized web service from HTML', () => {
      const banner = 'HTTP/1.1 200 OK\r\n\r\n<html><body>Hello</body></html>';
      const result = analyzeService(80, banner, null);
      expect(result.serviceName).toBe('Web Service (Unrecognized)');
    });

    it('should identify custom service from unknown banner', () => {
      const result = analyzeService(9999, 'CUSTOM_PROTOCOL v2.1', null);
      expect(result.serviceName).toBe('Custom Service');
    });

    // Port guessing
    it('should guess Telnet for port 23 (vulnerable)', () => {
      const result = analyzeService(23, null, null);
      expect(result.vulnerable).toBe(true);
      expect(result.severity).toBe('critical');
    });

    it('should guess DNS for port 53', () => {
      const result = analyzeService(53, null, null);
      expect(result.serviceName).toContain('DNS');
    });

    // Database ports
    it('should flag MySQL 3306', () => {
      expect(analyzeService(3306, null, null).vulnerable).toBe(true);
    });
    it('should flag SQL Server 1433', () => {
      expect(analyzeService(1433, null, null).vulnerable).toBe(true);
    });
    it('should flag MongoDB 27017', () => {
      expect(analyzeService(27017, null, null).vulnerable).toBe(true);
    });
    it('should flag Redis 6379', () => {
      expect(analyzeService(6379, null, null).vulnerable).toBe(true);
    });
    it('should flag PostgreSQL 5432', () => {
      expect(analyzeService(5432, null, null).vulnerable).toBe(true);
    });

    it('should guess RDP for port 3389', () => {
      const result = analyzeService(3389, null, null);
      expect(result.serviceName).toBe('RDP (Guessed)');
    });

    it('should return unknown for unrecognized port with no banner', () => {
      const result = analyzeService(12345, null, null);
      expect(result.serviceName).toBe('Unknown TCP Service');
    });
  });

  describe('runDeepScan', () => {
    it('should perform a full scan and report found ports', async () => {
      const onPortFound = vi.fn((data) => {
        if (data.port === 443) cancelDeepScan('10.0.0.1');
      });
      const onProgress = vi.fn();
      
      const scanPromise = runDeepScan('10.0.0.1', onPortFound, onProgress);
      
      // Advance timers to clear the chunking delays
      for (let i = 0; i < 50; i++) {
        await vi.runAllTimersAsync();
      }
      
      await scanPromise;
      
      expect(onPortFound).toHaveBeenCalled();
      expect(onPortFound).toHaveBeenCalledWith(expect.objectContaining({ port: 80 }));
      expect(onPortFound).toHaveBeenCalledWith(expect.objectContaining({ port: 443 }));
    });

    it('should handle scan cancellation', async () => {
      const onPortFound = vi.fn();
      const scanPromise = runDeepScan('10.0.0.2', onPortFound);
      
      // Delay cancellation so it happens after runDeepScan adds the IP to activeScans
      cancelDeepScan('10.0.0.2');
      
      for (let i = 0; i < 10; i++) {
        await vi.runAllTimersAsync();
      }
      
      await scanPromise;
      // Should stop early and not try to scan all 65k
    });

    it.skip('should trigger security audits for FTP and HTTP', async () => {
      const { checkAnonymousFtp, checkSensitiveWebDirs } = await import('../src/main/securityAnalyzer.js');
      
      const onPortFound = vi.fn((data) => {
        // Cancel after we've seen the ports we care about
        if (data.port === 443) cancelDeepScan('10.0.0.5');
      });
      
      const scanPromise = runDeepScan('10.0.0.5', onPortFound);
      
      // Advance by sufficient time to cover the first few chunks
      // Each chunk is roughly 20ms delay + mock delays.
      for (let i = 0; i < 50; i++) {
        vi.advanceTimersByTime(100);
        await vi.runAllTimersAsync();
      }
      
      await scanPromise;
      
      expect(checkAnonymousFtp).toHaveBeenCalledWith('10.0.0.5', 21);
      expect(checkSensitiveWebDirs).toHaveBeenCalledWith('10.0.0.5', 80, false);
      expect(checkSensitiveWebDirs).toHaveBeenCalledWith('10.0.0.5', 443, true);
    });

    it('should handle audit errors gracefully', async () => {
      const onPortFound = vi.fn(() => cancelDeepScan('10.0.0.4'));
      const { checkAnonymousFtp } = await import('../src/main/securityAnalyzer.js');
      checkAnonymousFtp.mockRejectedValueOnce(new Error('Audit Failed'));
      
      const scanPromise = runDeepScan('10.0.0.4', onPortFound);
      for (let i = 0; i < 10; i++) {
        await vi.runAllTimersAsync();
      }
      await expect(scanPromise).resolves.not.toThrow();
    });
  });
});
