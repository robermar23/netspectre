import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import net from 'net';
import { EventEmitter } from 'events';

// Create the module mock before importing it
vi.mock('../src/main/credSprayTransports.js', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    sleep: () => Promise.resolve() // Overwrite sleep cleanly for tests
  };
});

describe('Credential Spray Transports Layer', () => {
  let transports;
  let originalFetch;
  
  beforeEach(async () => {
    vi.resetModules();
    vi.clearAllMocks();
    transports = await import('../src/main/credSprayTransports.js');
    originalFetch = global.fetch;
    global.fetch = vi.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  const abortSignalBase = new AbortController().signal;

  it('HTTP Basic - should detect valid 200 OK responses', async () => {
    global.fetch.mockResolvedValue({
      status: 200,
      text: () => Promise.resolve('Success')
    });

    const creds = [{user: 'admin', pass: 'password'}];
    const hits = await transports.sprayHttpBasic('127.0.0.1', 80, creds, abortSignalBase, 1, 100);

    expect(hits.length).toBe(1);
    expect(hits[0].user).toBe('admin');
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledWith('http://127.0.0.1:80/', expect.objectContaining({
      headers: { 'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ=' }
    }));
  });

  it('HTTP Basic - should skip missing credentials', async () => {
    global.fetch.mockResolvedValue({
      status: 401,
      text: () => Promise.resolve('Unauthorized')
    });

    const creds = [{user: 'admin', pass: 'incorrect'}, {user: 'admin', pass: 'wrong'}];
    const hits = await transports.sprayHttpBasic('127.0.0.1', 80, creds, abortSignalBase, 1, 100);

    expect(hits.length).toBe(0);
    expect(global.fetch).toHaveBeenCalledTimes(2); // Retries next attempts flawlessly
  });

  it('HTTP Basic - should break loop on fatal target timeouts', async () => {
    const timeoutErr = new Error('Fetch Error');
    timeoutErr.code = 'ECONNREFUSED';
    global.fetch.mockRejectedValue(timeoutErr);

    const creds = [{user: 'admin', pass: 'incorrect'}, {user: 'admin', pass: 'wrong'}];
    const hits = await transports.sprayHttpBasic('127.0.0.1', 80, creds, abortSignalBase, 1, 100);

    // If connection is refused, it skips the remainder of the array
    expect(hits.length).toBe(0);
    expect(global.fetch).toHaveBeenCalledTimes(1); 
  });

  it('HTTP Form - should detect successful logins or HTTP redirects', async () => {
    // Attempt 1: 200 OK with 'incorrect' string in body = Fail
    global.fetch.mockResolvedValueOnce({
      status: 200,
      text: () => Promise.resolve('<html>incorrect login details</html>')
    });
    // Attempt 2: 302 Redirect = Success!
    global.fetch.mockResolvedValueOnce({
      status: 302,
      text: () => Promise.resolve('')
    });

    const creds = [{user: 'admin', pass: 'incorrect'}, {user: 'root', pass: 'admin'}];
    const hits = await transports.sprayHttpForm('192.168.1.1', 8080, {}, creds, abortSignalBase, 1, 100);

    expect(hits.length).toBe(1);
    expect(hits[0].user).toBe('root');
    expect(global.fetch).toHaveBeenCalledTimes(2);
    expect(global.fetch).toHaveBeenLastCalledWith('http://192.168.1.1:8080/login.cgi', expect.objectContaining({
       method: 'POST',
       body: 'username=root&password=admin'
    }));
  });

  it('HTTP Form - should detect Dashboard indicators on 200 OK', async () => {
    // Attempt 1: 200 OK with NO 'incorrect' string = Success!
    global.fetch.mockResolvedValueOnce({
      status: 200,
      text: () => Promise.resolve('<html>Welcome to the Admin Dashboard</html>') // No "incorrect" wording
    });
    // Attempt 2: 404 (would never be reached if stopOnFirstHit) - but we aren't enforcing orchestrator logic here
    global.fetch.mockResolvedValueOnce({
      status: 404,
      text: () => Promise.resolve('')
    });

    const creds = [{user: 'root', pass: 'admin'}, {user: 'admin', pass: 'incorrect'}];
    const hits = await transports.sprayHttpForm('192.168.1.1', 80, {}, creds, abortSignalBase, 1, 100);

    expect(hits.length).toBe(1);
    expect(hits[0].user).toBe('root');
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  it('Telnet - should establish socket correctly and return true', async () => {
    // We mock net.Socket entirely to simulate the prompt/response handshake
    const mockSocket = new EventEmitter();
    mockSocket.connect = vi.fn();
    mockSocket.write = vi.fn((cmd) => {
      // Respond to user prompt:
      if (cmd.includes('admin')) {
         setImmediate(() => mockSocket.emit('data', 'Password:'));
      }
      // Respond to pass prompt:
      if (cmd.includes('password')) {
         setImmediate(() => mockSocket.emit('data', 'root@router~# ')); // Shell prompt
      }
    });
    mockSocket.setTimeout = vi.fn();
    mockSocket.destroy = vi.fn();

    vi.spyOn(net, 'Socket').mockImplementation(function() { 
      setTimeout(() => mockSocket.emit('timeout'), 50);
      return mockSocket; 
    });

    const creds = [{user: 'admin', pass: 'password'}];

    // Fire test async
    const sprayPromise = transports.sprayTelnet('10.0.0.1', 23, creds, abortSignalBase, 1, 100);
    
    // Simulate connection resolving and firing the initial login banner!
    setTimeout(() => {
      mockSocket.emit('data', 'Welcome to BusyBox\nLogin:');
    }, 1);

    const hits = await sprayPromise;

    expect(hits.length).toBe(1);
    expect(hits[0].user).toBe('admin');
    expect(mockSocket.connect).toHaveBeenCalledWith(23, '10.0.0.1');
    expect(mockSocket.write).toHaveBeenCalledTimes(2);
  });

  it('Telnet - should fail gracefully on incorrect logins', async () => {
    const mockSocket = new EventEmitter();
    mockSocket.connect = vi.fn();
    mockSocket.write = vi.fn((cmd) => {
      if (cmd.includes('admin')) setImmediate(() => mockSocket.emit('data', 'Password:'));
      if (cmd.includes('incorrect')) setImmediate(() => mockSocket.emit('data', 'Login incorrect\nLogin:'));
    });
    mockSocket.setTimeout = vi.fn();
    mockSocket.destroy = vi.fn();

    vi.spyOn(net, 'Socket').mockImplementation(function() { 
      setTimeout(() => mockSocket.emit('timeout'), 50);
      return mockSocket; 
    });

    const creds = [{user: 'admin', pass: 'incorrect'}];

    const sprayPromise = transports.sprayTelnet('10.0.0.1', 23, creds, abortSignalBase, 1, 100);
    
    setTimeout(() => mockSocket.emit('data', 'Welcome to BusyBox\nLogin:'), 1);

    const hits = await sprayPromise;
    expect(hits.length).toBe(0);
    expect(mockSocket.destroy).toHaveBeenCalled();
  });
});
