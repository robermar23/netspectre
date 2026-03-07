import { describe, it, expect, vi, beforeEach } from 'vitest';
import { startBruteForce, stopBruteForce, isBruteForceRunning, cleanupBruteForce } from '../src/main/bruteForce.js';
import { spawn } from 'child_process';
import fs from 'fs';

vi.mock('child_process', () => ({
  spawn: vi.fn(),
  exec: vi.fn(),
  execSync: vi.fn()
}));

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(true),
    readFileSync: vi.fn()
  },
  existsSync: vi.fn().mockReturnValue(true),
  readFileSync: vi.fn()
}));

vi.mock('../src/main/store.js', () => ({
  getSetting: vi.fn().mockImplementation((key) => {
    if (key === 'hydra.path') return 'hydra';
    return null;
  }),
  setSetting: vi.fn(),
  checkDependency: vi.fn().mockResolvedValue({ installed: true, output: 'Hydra v9.5' })
}));

function createMockProcess() {
  const proc = {
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
    on: vi.fn(),
    kill: vi.fn(),
    pid: 12345,
  };
  return proc;
}

describe('Brute-Force Module', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clean up any active processes from previous tests
    cleanupBruteForce();
  });

  describe('Input Validation', () => {
    it('should reject invalid IP address', () => {
      const onError = vi.fn();

      startBruteForce({
        targetIp: 'not-an-ip',
        port: 22,
        protocol: 'ssh',
        username: 'root',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('Invalid IP') })
      );
      expect(spawn).not.toHaveBeenCalled();
    });

    it('should reject empty IP address', () => {
      const onError = vi.fn();

      startBruteForce({
        targetIp: '',
        port: 22,
        protocol: 'ssh',
        username: 'root',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalled();
      expect(spawn).not.toHaveBeenCalled();
    });

    it('should reject invalid protocol', () => {
      const onError = vi.fn();

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'invalid-proto',
        username: 'root',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('Unsupported protocol') })
      );
    });

    it('should reject port out of bounds (0)', () => {
      const onError = vi.fn();

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 0,
        protocol: 'ssh',
        username: 'root',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('Port must be') })
      );
    });

    it('should reject port out of bounds (70000)', () => {
      const onError = vi.fn();

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 70000,
        protocol: 'ssh',
        username: 'root',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('Port must be') })
      );
    });

    it('should reject missing username and user list', () => {
      const onError = vi.fn();

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: '',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('Username') })
      );
    });

    it('should reject missing wordlist path', () => {
      const onError = vi.fn();

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'root',
        wordlistPath: '',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('Wordlist path') })
      );
    });

    it('should reject non-existent wordlist file', () => {
      fs.existsSync.mockReturnValueOnce(false);
      const onError = vi.fn();

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'root',
        wordlistPath: '/nonexistent/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('not found') })
      );
    });

    it('should reject thread count > 16', () => {
      const onError = vi.fn();

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'root',
        wordlistPath: '/tmp/wordlist.txt',
        threads: 32,
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('Thread count must be') })
      );
    });
  });

  describe('Spawn & Command Construction', () => {
    it('should spawn hydra with correct arguments for valid input', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
        threads: 4,
        delay: 0,
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn());

      expect(spawn).toHaveBeenCalledTimes(1);
      const [cmd, args] = spawn.mock.calls[0];
      expect(cmd).toBe('hydra');
      expect(args).toContain('-l');
      expect(args).toContain('admin');
      expect(args).toContain('-P');
      expect(args).toContain('/tmp/wordlist.txt');
      expect(args).toContain('-s');
      expect(args).toContain('22');
      expect(args).toContain('-t');
      expect(args).toContain('4');
      expect(args).toContain('-f');
      expect(args).toContain('-V');
      expect(args).toContain('10.0.0.1');
      expect(args).toContain('ssh');
    });

    it('should include delay flag when delay > 0', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
        threads: 4,
        delay: 500,
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn());

      const args = spawn.mock.calls[0][1];
      expect(args).toContain('-W');
      expect(args).toContain('500');
    });

    it('should cap thread count at 16', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      // Set threads to 15 (valid) and verify it passes through
      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
        threads: 15,
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn());

      const args = spawn.mock.calls[0][1];
      const threadIdx = args.indexOf('-t') + 1;
      expect(parseInt(args[threadIdx])).toBeLessThanOrEqual(16);
    });
  });

  describe('Output Parsing', () => {
    it('should parse credential hit from Hydra stdout', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onResult = vi.fn();
      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), onResult, vi.fn(), vi.fn(), vi.fn());

      // Simulate stdout data event with credential hit
      const stdoutHandler = mockProc.stdout.on.mock.calls.find(c => c[0] === 'data')[1];
      stdoutHandler(Buffer.from('[22][ssh] host: 10.0.0.1   login: admin   password: secret123\n'));

      expect(onResult).toHaveBeenCalledWith(
        expect.objectContaining({
          port: 22,
          protocol: 'ssh',
          host: '10.0.0.1',
          user: 'admin',
          password: 'secret123',
        })
      );
    });

    it('should not trigger onResult for non-hit lines', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onResult = vi.fn();
      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), onResult, vi.fn(), vi.fn(), vi.fn());

      const stdoutHandler = mockProc.stdout.on.mock.calls.find(c => c[0] === 'data')[1];
      stdoutHandler(Buffer.from('Hydra v9.5 starting...\n'));

      expect(onResult).not.toHaveBeenCalled();
    });

    it('should parse STATUS progress lines', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onProgress = vi.fn();
      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), onProgress, vi.fn(), vi.fn());

      const stdoutHandler = mockProc.stdout.on.mock.calls.find(c => c[0] === 'data')[1];
      stdoutHandler(Buffer.from('[STATUS] 64.00 tries/min, 128 tries in 00:02h\n'));

      expect(onProgress).toHaveBeenCalledWith(
        expect.objectContaining({
          statusText: expect.stringContaining('64.00 tries/min'),
        })
      );
    });
  });

  describe('Process Lifecycle', () => {
    it('should track running state', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      expect(isBruteForceRunning()).toBe(false);

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn());

      expect(isBruteForceRunning()).toBe(true);
    });

    it('should call onComplete on process close', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onComplete = vi.fn();
      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn(), onComplete);

      // Simulate process close
      const closeHandler = mockProc.on.mock.calls.find(c => c[0] === 'close')[1];
      closeHandler(0);

      expect(onComplete).toHaveBeenCalledWith(
        expect.objectContaining({
          exitCode: 0,
          totalAttempts: expect.any(Number),
          credentialsFound: expect.any(Array),
        })
      );
    });

    it('should stop and kill the process', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn());

      const result = stopBruteForce('10.0.0.1:ssh');
      expect(result).toBe(true);
      expect(mockProc.kill).toHaveBeenCalledWith('SIGTERM');
      expect(isBruteForceRunning()).toBe(false);
    });

    it('should prevent duplicate attacks on same target:protocol', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);
      const onError = vi.fn();

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn());

      // Second call on same target
      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), onError, vi.fn());

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringContaining('already running') })
      );
    });

    it('should cleanup all processes', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      startBruteForce({
        targetIp: '10.0.0.1',
        port: 22,
        protocol: 'ssh',
        username: 'admin',
        wordlistPath: '/tmp/wordlist.txt',
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn());

      expect(isBruteForceRunning()).toBe(true);
      cleanupBruteForce();
      expect(isBruteForceRunning()).toBe(false);
      expect(mockProc.kill).toHaveBeenCalledWith('SIGKILL');
    });
  });
});
