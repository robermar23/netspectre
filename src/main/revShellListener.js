import net from 'net';
import { spawn } from 'child_process';
import os from 'os';

let activeListener = null;
let activeSocket = null;
let ncatProcess = null;

/**
 * Starts a reverse shell listener natively or via ncat.
 * @param {Object} options Options containing port and mode ('native'|'ncat')
 * @param {Function} onConnection Callback when a reverse shell connects
 * @param {Function} onData Callback when reverse shell receives data
 * @param {Function} onError Callback on error
 */
export async function startListener(options, onConnection, onData, onError) {
  if (activeListener || ncatProcess) {
    if (onError) onError({ message: 'A listener is already active. Please stop it first.' });
    return;
  }

  const { port = 4444, mode = 'native' } = options;

  if (port < 1024 || port > 65535) {
    if (onError) onError({ message: `Invalid port ${port}. Must be between 1024 and 65535.` });
    return;
  }

  if (mode === 'native') {
    startNativeServer(port, onConnection, onData, onError);
  } else if (mode === 'ncat') {
    startNcatListener(port, onConnection, onData, onError);
  } else {
    if (onError) onError({ message: 'Invalid listener mode.' });
  }
}

function startNativeServer(port, onConnection, onData, onError) {
  activeListener = net.createServer((socket) => {
    // Only accept one connection at a time
    if (activeSocket) {
      socket.write('A reverse shell is already connected.\n');
      socket.end();
      return;
    }

    activeSocket = socket;
    
    if (onConnection) {
      onConnection({
        address: socket.remoteAddress,
        port: socket.remotePort,
        family: socket.remoteFamily
      });
    }

    socket.on('data', (data) => {
      if (onData) onData(data.toString());
    });

    socket.on('error', (err) => {
      // Disconnected or connection closed
      activeSocket = null;
      if (onError && err.code !== 'ECONNRESET') {
        const msg = err.code === 'EADDRINUSE' ? `Port ${port} is already in use by another application.` : `Socket Error: ${err.message}`;
        onError({ message: msg, code: err.code });
      }
    });

    socket.on('close', () => {
      activeSocket = null;
      if (onData) onData('\n[Connection Closed]\n');
    });
  });

  activeListener.on('error', (err) => {
    let msg = `Listener Error: ${err.message}`;
    if (err.code === 'EACCES') msg = `Permission denied: Port ${port} is privileged or restricted.`;
    if (err.code === 'EADDRINUSE') msg = `Port ${port} is already in use. Close other apps or pick a new port.`;
    
    if (onError) onError({ message: msg, code: err.code, type: 'listener_error' });
    stopListener();
  });

  // Explicitly bind to '0.0.0.0' to accept connections from external hosts
  activeListener.listen(port, '0.0.0.0', () => {
    if (onData) onData(`[Native] Listening on 0.0.0.0:${port}...\n`);
  });
}

function startNcatListener(port, onConnection, onData, onError) {
  // Using ncat bundled or system ncat. For now, assuming ncat is in PATH or bundled as `ncat`
  try {
    ncatProcess = spawn('ncat', ['-lvnp', port.toString()]);
    
    if (onData) onData(`[Ncat] Listening on 0.0.0.0:${port}...\n`);

    ncatProcess.stdout.on('data', (data) => {
      if (onData) onData(data.toString());
    });

    ncatProcess.stderr.on('data', (data) => {
      const dataStr = data.toString();
      // Ncat outputs connection info to stderr (e.g., "Ncat: Connection from 10.0.0.5.")
      if (dataStr.includes('Connection from')) {
        const ipMatch = dataStr.match(/from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})/);
        const ipv6Match = dataStr.match(/from\s+([0-9a-fA-F:]+)/);
        const match = ipMatch || ipv6Match;
        if (onConnection && match) {
          onConnection({ address: match[1], port: 0 }); // Ncat stderr might not print port immediately
        }
      }
      if (onData) onData(dataStr);
    });

    ncatProcess.on('error', (err) => {
      const msg = `Ncat spawn error: ${err.message}. Ensure Nmap/Ncat is installed.`;
      if (onError) onError({ message: msg, type: 'spawn_error', code: err.code });
      stopListener();
    });

    ncatProcess.on('close', (code) => {
      ncatProcess = null;
      if (onData && code !== 0 && code !== null) onData(`\n[Ncat Closed with code ${code}]\n`);
    });
  } catch (err) {
    if (onError) onError(`Failed to spawn Ncat: ${err.message}`);
    stopListener();
  }
}

/**
 * Stops the active reverse shell listener.
 */
export function stopListener() {
  if (activeSocket) {
    activeSocket.destroy();
    activeSocket = null;
  }
  
  if (activeListener) {
    activeListener.close();
    activeListener = null;
  }

  if (ncatProcess) {
    ncatProcess.kill('SIGINT');
    ncatProcess = null;
  }
}

/**
 * Sends a command/data string back to the connected shell.
 * @param {string} data The command to send
 */
export function sendToShell(data) {
  const payload = data.endsWith('\n') ? data : `${data}\n`;
  if (activeSocket) {
    activeSocket.write(payload);
    return true;
  } else if (ncatProcess && ncatProcess.stdin) {
    ncatProcess.stdin.write(payload);
    return true;
  }
  return false;
}

/**
 * Checks if the listener is active.
 * @returns {boolean} true if listening
 */
export function isListenerActive() {
  return activeListener !== null || ncatProcess !== null;
}
