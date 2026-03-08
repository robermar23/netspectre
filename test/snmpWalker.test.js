import { describe, it, expect, vi, beforeEach } from 'vitest';
import { snmpWalk, snmpGet, cancelSnmpWalk, parseSysDescr, extractIntelligence } from '../src/main/snmpWalker.js';
import snmp from 'net-snmp';

// Mock net-snmp
vi.mock('net-snmp', () => {
  return {
    default: {
      Version1: 0,
      Version2c: 1,
      Version3: 3,
      SecurityLevel: { noAuthNoPriv: 1, authNoPriv: 2, authPriv: 3 },
      AuthProtocols: { md5: 1, sha: 2 },
      PrivProtocols: { des: 1, aes: 2 },
      createSession: vi.fn(),
      createV3Session: vi.fn(),
      isVarbindError: vi.fn((vb) => vb.type === 128), // 128 is an error type in SNMP
      varbindError: vi.fn(() => 'MockError')
    }
  };
});

describe('SNMP Walker', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('snmpWalk (v1/v2c)', () => {
    it('creates session and walks given OID', () => {
      const mockSession = {
        walk: vi.fn((oid, max, cb, done) => {
          // Simulate some results
          cb([{ oid: [1,3,6,1,2,1,1,1], type: 4, value: Buffer.from('Test Router') }]);
          done();
        }),
        close: vi.fn()
      };
      
      snmp.createSession.mockReturnValue(mockSession);

      const onResult = vi.fn();
      const onProgress = vi.fn();
      const onComplete = vi.fn();
      const onError = vi.fn();

      snmpWalk('10.0.0.1', { version: 'v2c', community: 'public' }, onResult, onProgress, onComplete, onError);

      expect(snmp.createSession).toHaveBeenCalledWith('10.0.0.1', 'public', expect.any(Object));
      expect(mockSession.walk).toHaveBeenCalledWith('1.3.6.1.2.1', 20, expect.any(Function), expect.any(Function));
      
      expect(onResult).toHaveBeenCalledTimes(1);
      expect(onResult).toHaveBeenCalledWith(expect.objectContaining({ 
        targetIp: '10.0.0.1',
        oid: '1.3.6.1.2.1.1.1',
        value: 'Test Router'
      }));
      expect(onComplete).toHaveBeenCalledWith({ targetIp: '10.0.0.1', totalOids: 1 });
      expect(onError).not.toHaveBeenCalled();
    });

    it('uses custom retries and timeout options', () => {
      const mockSession = { walk: vi.fn(), close: vi.fn() };
      snmp.createSession.mockReturnValue(mockSession);

      snmpWalk('10.0.0.10', { retries: 3, timeout: 10000 }, vi.fn(), vi.fn(), vi.fn(), vi.fn());

      expect(snmp.createSession).toHaveBeenCalledWith(
        '10.0.0.10', 
        'public', 
        expect.objectContaining({ retries: 3, timeout: 10000 })
      );
    });

    it('prevents concurrent walks on the same IP', () => {
      const mockSession = { walk: vi.fn(), close: vi.fn() };
      snmp.createSession.mockReturnValue(mockSession);

      const onError1 = vi.fn();
      const onError2 = vi.fn();

      snmpWalk('10.0.0.2', { version: 'v2c' }, vi.fn(), vi.fn(), vi.fn(), onError1);
      snmpWalk('10.0.0.2', { version: 'v2c' }, vi.fn(), vi.fn(), vi.fn(), onError2);

      expect(onError1).not.toHaveBeenCalled();
      expect(onError2).toHaveBeenCalledWith(expect.objectContaining({ error: expect.stringContaining('already in progress') }));
    });

    it('handles snmp.isVarbindError during walk', () => {
      const mockSession = {
        walk: vi.fn((oid, max, cb, done) => {
          cb([{ oid: [1,3,6,1,2,1], type: 128, value: null }]); // 128 = error
          done();
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);
      const onResult = vi.fn();

      snmpWalk('10.0.0.11', {}, onResult, vi.fn(), vi.fn(), vi.fn());
      expect(onResult).not.toHaveBeenCalled();
    });

    it('reports timeout specifically', () => {
      const mockSession = {
        walk: vi.fn((oid, max, cb, done) => {
          done(new Error('Request timed out'));
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);
      const onError = vi.fn();

      snmpWalk('10.0.0.12', {}, vi.fn(), vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalledWith(expect.objectContaining({ 
        error: expect.stringContaining('Timeout: Host did not respond') 
      }));
    });

    it('triggers onProgress every 50 OIDs', () => {
      const mockSession = {
        walk: vi.fn((oid, max, cb, done) => {
          // Send 50 varbinds one by one or in small chunks
          for(let i=1; i<=50; i++) {
            cb([{ oid: [1,3,6,1,2,1,1,i], value: 'val' }]);
          }
          done();
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);
      const onProgress = vi.fn();

      snmpWalk('10.0.0.13', {}, vi.fn(), onProgress, vi.fn(), vi.fn());
      expect(onProgress).toHaveBeenCalledWith(expect.objectContaining({ count: 50 }));
    });
  });

  describe('snmpWalk (v3)', () => {
    it('creates v3 session with noAuthNoPriv', () => {
      const mockSession = { walk: vi.fn(), close: vi.fn() };
      snmp.createV3Session.mockReturnValue(mockSession);

      snmpWalk('10.0.0.21', { version: 'v3', user: 'admin' }, vi.fn(), vi.fn(), vi.fn(), vi.fn());

      expect(snmp.createV3Session).toHaveBeenCalledWith(
        '10.0.0.21',
        expect.objectContaining({ name: 'admin', level: 1 }),
        expect.any(Object)
      );
    });

    it('creates v3 session with authNoPriv', () => {
      const mockSession = { walk: vi.fn(), close: vi.fn() };
      snmp.createV3Session.mockReturnValue(mockSession);

      snmpWalk('10.0.0.22', { 
        version: 'v3', 
        user: 'admin', 
        authKey: 'pass', 
        authProtocol: 'sha' 
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn());

      expect(snmp.createV3Session).toHaveBeenCalledWith(
        '10.0.0.22',
        expect.objectContaining({ 
          level: 2, 
          authProtocol: 2, 
          authKey: 'pass' 
        }),
        expect.any(Object)
      );
    });

    it('creates v3 session with authPriv (AES)', () => {
      const mockSession = { walk: vi.fn(), close: vi.fn() };
      snmp.createV3Session.mockReturnValue(mockSession);

      snmpWalk('10.0.0.23', { 
        version: 'v3', 
        user: 'admin', 
        authKey: 'auth', 
        privKey: 'priv',
        privProtocol: 'aes'
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn());

      expect(snmp.createV3Session).toHaveBeenCalledWith(
        '10.0.0.23',
        expect.objectContaining({ 
          level: 3, 
          privProtocol: 2, 
          privKey: 'priv' 
        }),
        expect.any(Object)
      );
    });
  });

  describe('Intelligence Helpers', () => {
    it('parseSysDescr should handle hardware/software strings', () => {
      const result = parseSysDescr('Hardware: Cisco - Software: IOS 12.4');
      expect(result.vendor).toBe('Cisco');
      expect(result.os).toBe('IOS 12.4');
    });

    it('extractIntelligence should detect ARP data', () => {
      const onIntelligence = vi.fn();
      extractIntelligence({ 
        oid: '1.3.6.1.2.1.3.1.1.2.1.1.10.0.0.1', 
        val: '00:11:22:33:44:55', 
        targetIp: '10.0.0.100', 
        onIntelligence 
      });
      expect(onIntelligence).toHaveBeenCalledWith(expect.objectContaining({ type: 'arp-discovery' }));
    });

    it('extractIntelligence should detect process names', () => {
      const onIntelligence = vi.fn();
      extractIntelligence({ 
        oid: '1.3.6.1.2.1.25.4.2.1.2.100', 
        val: 'nginx', 
        targetIp: '10.0.0.100', 
        onIntelligence 
      });
      expect(onIntelligence).toHaveBeenCalledWith(expect.objectContaining({ type: 'process-discovery', processName: 'nginx' }));
    });
  });

  describe('snmpGet', () => {
    it('resolves with multiple OID results', async () => {
      const { snmpGet } = await import('../src/main/snmpWalker.js');
      const mockSession = {
        get: vi.fn((oids, cb) => {
          cb(null, [
            { oid: [1,3,6,1,2,1,1,5,0], value: Buffer.from('HostA'), type: 4 }
          ]);
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);

      const results = await snmpGet('10.0.0.1', ['1.3.6.1.2.1.1.5.0'], {});
      expect(results[0].value).toBe('HostA');
      expect(mockSession.close).toHaveBeenCalled();
    });

    it('rejects on session error', async () => {
      const { snmpGet } = await import('../src/main/snmpWalker.js');
      const mockSession = {
        get: vi.fn((oids, cb) => cb(new Error('SNMP Error'))),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);

      await expect(snmpGet('10.0.0.1', ['1.3.6.1.2.1'], {})).rejects.toThrow('SNMP Error');
    });

    it('handles varbind error in snmpGet', async () => {
      const { snmpGet } = await import('../src/main/snmpWalker.js');
      const mockSession = {
        get: vi.fn((oids, cb) => {
          cb(null, [{ oid: [1,2,3], type: 128 }]); // 128 = error
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);

      const results = await snmpGet('10.0.0.1', ['1.2.3'], {});
      expect(results[0].error).toBe('MockError');
    });

    it('rejects if createSession throws in snmpGet', async () => {
      const { snmpGet } = await import('../src/main/snmpWalker.js');
      snmp.createSession.mockImplementation(() => { throw new Error('Session creation failed'); });

      await expect(snmpGet('10.0.0.1', ['1.2.3'], {})).rejects.toThrow('Session creation failed');
    });
  });

  describe('cancelSnmpWalk', () => {
    it('closes the session and removes from active walks', () => {
      const mockSession = { walk: vi.fn(), close: vi.fn() };
      snmp.createSession.mockReturnValue(mockSession);

      snmpWalk('10.0.0.3', { version: 'v2c' }, vi.fn(), vi.fn(), vi.fn(), vi.fn());
      
      const res = cancelSnmpWalk('10.0.0.3');
      expect(res).toBe(true);
      expect(mockSession.close).toHaveBeenCalled();
    });
  });
});
