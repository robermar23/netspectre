import { spawn, exec, execSync } from 'child_process';
import os from 'os';
import { getSetting, checkDependency } from './store.js';

const activeScans = new Map(); // Store child processes by ID (ip or subnet)

export async function checkNmapInstalled() {
  const result = await checkDependency('nmap');
  return result.installed;
}

export function cancelNmapScan(id) {
  const scanProcess = activeScans.get(id);
  if (scanProcess) {
    console.log(`Killing Nmap scan: ${id}`);
    scanProcess.kill('SIGKILL');
    activeScans.delete(id);
    return true;
  }
  return false;
}

export async function runNmapScan(type, targetObj, onResultCallback, onCompleteCallback, onErrorCallback) {
  const isInstalled = await checkNmapInstalled();
  if (!isInstalled) {
    onErrorCallback({ error: 'Nmap is not installed or not in PATH.' });
    return;
  }

  // Support both old string format and new object format
  const target = typeof targetObj === 'string' ? targetObj : targetObj.ip;
  const scriptName = targetObj.scriptName;
  const scriptArgs = targetObj.args;

  // Define arguments based on scan type
  let args = [];
  if (type === 'deep') {
    // Basic comprehensive scan (skip ping, version detection, all ports, aggressive)
    args = ['-Pn', '-sV', '-p', '1-65535', '-A', '-T4', '--stats-every', '3s', target];
  } else if (type === 'vuln') {
    // Vulnerability script scan
    args = ['-Pn', '-sV', '--script', 'vuln', '--stats-every', '3s', target];
  } else if (type === 'custom') {
    // Custom script execution from the NSE Explorer
    args = ['-Pn', '-sV', '--script', scriptName];
    if (scriptArgs && scriptArgs.trim() !== '') {
       args.push('--script-args', scriptArgs.trim());
    }
    args.push('--stats-every', '3s', target);
  } else if (type === 'host') {
    // Standard aggressive scan for a single host
    args = ['-Pn', '-A', '-T4', '--stats-every', '3s', target];
  } else if (type === 'port') {
    // Specific port scan. Target is expected to be IP:PORT
    const [ip, port] = target.split(':');
    args = ['-Pn', '-p', port, '-sV', '-sC', '--stats-every', '3s', ip];
  } else {
    onErrorCallback({ error: 'Unknown Nmap scan type' });
    return;
  }

  const nmapExecutable = getSetting('nmap.path') || 'nmap';
  console.log(`Starting Nmap ${type} scan on ${target} at ${nmapExecutable} with args:`, args.join(' '));

  const nmapProcess = spawn(nmapExecutable, args);
  activeScans.set(target, nmapProcess);

  let outputBuffer = '';

  nmapProcess.stdout.on('data', (data) => {
    const chunk = data.toString();
    outputBuffer += chunk;
    onResultCallback({ chunk });
  });

  nmapProcess.stderr.on('data', (data) => {
    console.error(`Nmap Stderr (${target}):`, data.toString());
  });

  nmapProcess.on('close', (code) => {
    activeScans.delete(target);
    if (code !== 0 && code !== null) { // null if killed
      onErrorCallback({ error: `Nmap process exited with code ${code}` });
    } else {
      onCompleteCallback({ target, fullOutput: outputBuffer });
    }
  });

  nmapProcess.on('error', (err) => {
    activeScans.delete(target);
    onErrorCallback({ error: err.message });
  });
}

// ==========================================
// NCAT Execution
// ==========================================

export async function runNcat({ target, port, payload }, onResultCallback, onCompleteCallback, onErrorCallback) {
  const isInstalled = await checkNmapInstalled();
  if (!isInstalled) {
    onErrorCallback({ error: 'Nmap (and Ncat) is not installed or not in PATH.' });
    return;
  }

  // Ncat arguments: ncat [options] <host> <port>
  // We use -w 5 for a 5 second timeout so it doesn't hang forever if unresponsive.
  let args = ['-v', '-w', '10', target, port];
  
  // Ncat path logic assumes Ncat lives in the same directory as Nmap
  let ncatExecutable = 'ncat';
  const nmapStoredPath = getSetting('nmap.path');
  if (nmapStoredPath) {
    const dir = path.dirname(nmapStoredPath);
    const nmapName = path.basename(nmapStoredPath);
    // On Windows, nmap.exe -> ncat.exe. On Unix, nmap -> ncat.
    const ncatName = nmapName.replace(/^nmap/i, 'ncat');
    const potentialNcatPath = path.join(dir, ncatName);
    if (fs.existsSync(potentialNcatPath)) {
      ncatExecutable = potentialNcatPath;
    }
  }

  console.log(`Starting Ncat on ${target}:${port} at ${ncatExecutable} with args:`, args.join(' '));

  const ncatProcess = spawn(ncatExecutable, args);
  // Share the same activeScans registry so cancellation works seamlessly
  activeScans.set(target, ncatProcess);

  const fullOutput = [];

  ncatProcess.stdout.on('data', (data) => {
    const str = data.toString();
    fullOutput.push(str);
    onResultCallback({ chunk: str });
  });

  ncatProcess.stderr.on('data', (data) => {
    const str = data.toString();
    fullOutput.push(str);
    onResultCallback({ chunk: str });
  });

  // If the user provided a payload, write it to stdin and send EOF
  if (payload && payload.trim() !== '') {
     try {
       // Replace literal \n and \r tags the user might type inside the UI box with actual breaks
       let formattedPayload = payload.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
       if (!formattedPayload.endsWith('\n')) {
         formattedPayload += '\n';
       }
       ncatProcess.stdin.write(formattedPayload);
       // We DO NOT end stdin here anymore so the server stream stays alive continuously.
       // User can click "Stop" in UI to kill the ncat process.
     } catch (e) {
       console.error("Failed to write Ncat payload:", e);
     }
  }

  ncatProcess.on('close', (code) => {
    activeScans.delete(target);
    console.log(`Ncat completed with code ${code}`);
    onCompleteCallback({ success: code === 0, fullOutput: fullOutput.join('') });
  });

  ncatProcess.on('error', (err) => {
    activeScans.delete(target);
    console.error('Ncat spawn error:', err);
    onErrorCallback({ error: err.message });
  });
}

// ==========================================
// Nmap Scripting Engine (NSE) Discovery
// ==========================================

import fs from 'fs';
import path from 'path';

export async function getNmapScripts() {
  const isInstalled = await checkNmapInstalled();
  if (!isInstalled) return [];

  let scriptsDirs = [];

  // 1. Try to dynamically resolve from system PATH
  try {
    const cmd = process.platform === 'win32' ? 'where nmap' : 'which nmap';
    const out = execSync(cmd, { encoding: 'utf8' }).trim();
    const nmapExePath = out.split('\n')[0].trim(); // `where` can return multiple lines
    
    if (nmapExePath && fs.existsSync(nmapExePath)) {
      const binDir = path.dirname(nmapExePath);
      if (process.platform === 'win32') {
        // Windows: scripts/ is adjacent to nmap.exe
        scriptsDirs.push(path.join(binDir, 'scripts'));
      } else {
        // Unix: usually ../share/nmap/scripts relative to bin/
        scriptsDirs.push(path.join(path.dirname(binDir), 'share', 'nmap', 'scripts'));
        // Fallback if portable: adjacent to binary
        scriptsDirs.push(path.join(binDir, 'scripts'));
      }
    }
  } catch (e) {
    console.log('Dynamic nmap path resolution failed:', e.message);
  }

  // 2. Add standard OS default fallbacks
  if (process.platform === 'win32') {
    scriptsDirs.push(
      path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Nmap', 'scripts'),
      path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Nmap', 'scripts')
    );
  } else if (process.platform === 'darwin') {
    scriptsDirs.push(
      '/usr/local/share/nmap/scripts',
      '/opt/homebrew/share/nmap/scripts'
    );
  } else {
    scriptsDirs.push(
      '/usr/share/nmap/scripts',
      '/usr/local/share/nmap/scripts'
    );
  }

  // De-duplicate array
  scriptsDirs = [...new Set(scriptsDirs)];

  let activeDir = null;
  for (const dir of scriptsDirs) {
    if (fs.existsSync(dir)) {
      activeDir = dir;
      break;
    }
  }

  if (!activeDir) {
    console.warn('Could not locate Nmap scripts directory natively.');
    return [];
  }

  console.log(`Discovered Nmap scripts directory at: ${activeDir}`);
  const scripts = [];

  try {
    const files = fs.readdirSync(activeDir);
    for (const file of files) {
      if (file.endsWith('.nse')) {
        const fullPath = path.join(activeDir, file);
        const id = file.replace('.nse', '');
        
        // Read the first 2KB of the script to find the categories string
        // We do this synchronously but with a small buffer for speed.
        const fd = fs.openSync(fullPath, 'r');
        const buffer = Buffer.alloc(2048);
        const bytesRead = fs.readSync(fd, buffer, 0, 2048, 0);
        fs.closeSync(fd);
        
        const content = buffer.toString('utf8', 0, bytesRead);
        
        // Match `categories = {"safe", "discovery"}`
        let categories = ['uncategorized'];
        const catMatch = content.match(/categories\s*=\s*\{([^}]+)\}/);
        if (catMatch && catMatch[1]) {
           // Parse `"safe", "discovery"` into actual array ['safe', 'discovery']
           categories = catMatch[1]
             .split(',')
             .map(c => c.replace(/['"\s]/g, ''))
             .filter(c => c.length > 0);
        }

        // Parse description = [[ ... ]] (Lua long string, dotAll for multi-line)
        let description = '';
        const descMatch = content.match(/description\s*=\s*\[\[([^\]]*(?:\][^\]]+)*)\]\]/s);
        if (descMatch && descMatch[1]) {
          description = descMatch[1].trim().replace(/\s+/g, ' ').slice(0, 200);
        }

        scripts.push({
          id,
          categories,
          description
        });
      }
    }
    
    // Sort alphabetically by script id
    scripts.sort((a,b) => a.id.localeCompare(b.id));

    console.log(`Successfully parsed ${scripts.length} Nmap scripts.`);
    return scripts;
    
  } catch (e) {
    console.error('Error reading Nmap scripts directory:', e);
    return [];
  }
}
