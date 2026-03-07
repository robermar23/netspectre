import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import net from 'net';
import { spawn } from 'child_process';
import { startListener, stopListener, sendToShell, isListenerActive } from '../src/main/revShellListener.js';

vi.mock('child_process');
vi.mock('net');

describe('revShellListener', () => {
  let mockSocket;
  let mockServer;
  let mockProcess;

  beforeEach(() => {
    mockSocket = {
      remoteAddress: '10.0.0.5',
      remotePort: 54321,
      remoteFamily: 'IPv4',
      write: vi.fn(),
      end: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event, cb) => {
        if (event === 'data') mockSocket.triggerData = cb;
        if (event === 'error') mockSocket.triggerError = cb;
        if (event === 'close') mockSocket.triggerClose = cb;
      }),
    };

    mockServer = {
      close: vi.fn(),
      listen: vi.fn((port, host, cb) => {
        if (typeof host === 'function') {
          host();
        } else if (typeof cb === 'function') {
          cb();
        }
      }),
      on: vi.fn((event, cb) => {
        if (event === 'error') mockServer.triggerError = cb;
      }),
    };

    net.createServer.mockImplementation((cb) => {
      mockServer.triggerConnection = cb;
      return mockServer;
    });

    mockProcess = {
      kill: vi.fn(),
      stdin: { write: vi.fn() },
      stdout: {
        on: vi.fn((event, cb) => {
          if (event === 'data') mockProcess.triggerStdout = cb;
        })
      },
      stderr: {
        on: vi.fn((event, cb) => {
          if (event === 'data') mockProcess.triggerStderr = cb;
        })
      },
      on: vi.fn((event, cb) => {
        if (event === 'error') mockProcess.triggerError = cb;
        if (event === 'close') mockProcess.triggerClose = cb;
      })
    };

    spawn.mockReturnValue(mockProcess);
  });

  afterEach(() => {
    stopListener();
    vi.clearAllMocks();
  });

  it('should start native listener and handle connection', () => {
    const onConnection = vi.fn();
    const onData = vi.fn();
    const onError = vi.fn();

    startListener({ port: 4444, mode: 'native' }, onConnection, onData, onError);

    expect(net.createServer).toHaveBeenCalled();
    expect(mockServer.listen).toHaveBeenCalledWith(4444, '0.0.0.0', expect.any(Function));
    expect(isListenerActive()).toBe(true);
    expect(onData).toHaveBeenCalledWith('[Native] Listening on 0.0.0.0:4444...\n');

    // Trigger connection
    mockServer.triggerConnection(mockSocket);
    expect(onConnection).toHaveBeenCalledWith({ address: '10.0.0.5', port: 54321, family: 'IPv4' });

    // Send data
    mockSocket.triggerData(Buffer.from('hello from shell'));
    expect(onData).toHaveBeenCalledWith('hello from shell');

    // Send response
    sendToShell('whoami');
    expect(mockSocket.write).toHaveBeenCalledWith('whoami\n');
  });

  it('should start ncat listener and parse stderr connection', () => {
    const onConnection = vi.fn();
    const onData = vi.fn();
    const onError = vi.fn();

    startListener({ port: 4444, mode: 'ncat' }, onConnection, onData, onError);

    expect(spawn).toHaveBeenCalledWith('ncat', ['-lvnp', '4444']);
    expect(isListenerActive()).toBe(true);

    mockProcess.triggerStderr(Buffer.from('Ncat: Connection from 10.0.0.5.'));
    expect(onConnection).toHaveBeenCalledWith({ address: '10.0.0.5', port: 0 });

    mockProcess.triggerStdout(Buffer.from('root@kali:~# '));
    expect(onData).toHaveBeenCalledWith('root@kali:~# ');

    sendToShell('ls -la');
    expect(mockProcess.stdin.write).toHaveBeenCalledWith('ls -la\n');
  });

  it('should reject invalid ports', () => {
    const onError = vi.fn();
    startListener({ port: 80, mode: 'native' }, null, null, onError);
    expect(onError).toHaveBeenCalledWith(expect.stringContaining('Invalid port'));
    expect(isListenerActive()).toBe(false);
  });

  it('should reject starting if already active', () => {
    const onError = vi.fn();
    startListener({ port: 4444, mode: 'native' }, null, null, null);
    startListener({ port: 4445, mode: 'ncat' }, null, null, onError);
    expect(onError).toHaveBeenCalledWith(expect.stringContaining('already active'));
  });

  it('should stop listener successfully', () => {
    startListener({ port: 4444, mode: 'native' }, null, null, null);
    mockServer.triggerConnection(mockSocket);
    
    stopListener();
    expect(mockSocket.destroy).toHaveBeenCalled();
    expect(mockServer.close).toHaveBeenCalled();
    expect(isListenerActive()).toBe(false);
  });
});
