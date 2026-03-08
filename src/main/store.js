import Store from 'electron-store';
import { exec } from 'child_process';
import util from 'util';

const execPromise = util.promisify(exec);

const schema = {
  nmap: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: true },
      path: { type: 'string', default: '' }
    },
    default: { enabled: true, path: '' }
  },
  tshark: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: false },
      path: { type: 'string', default: '' }
    },
    default: { enabled: false, path: '' }
  },
  hydra: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: false },
      path: { type: 'string', default: '' }
    },
    default: { enabled: false, path: '' }
  },
  msfrpcd: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: false },
      path: { type: 'string', default: '' }
    },
    default: { enabled: false, path: '' }
  },
  smbclient: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: false },
      path: { type: 'string', default: '' }
    },
    default: { enabled: false, path: '' }
  },
  showmount: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: false },
      path: { type: 'string', default: '' }
    },
    default: { enabled: false, path: '' }
  },
  credSpray: {
    type: 'object',
    properties: {
      consentGiven: { type: 'boolean', default: false }
    },
    default: { consentGiven: false }
  }
};

const DEPENDENCY_PATHS = {
  nmap: {
    win32: [
      'nmap',
      'C:\\Program Files (x86)\\Nmap\\nmap.exe',
      'C:\\Program Files\\Nmap\\nmap.exe'
    ],
    darwin: [
      'nmap',
      '/opt/homebrew/bin/nmap',
      '/usr/local/bin/nmap',
      '/usr/bin/nmap',
      '/opt/local/bin/nmap',
      '/sw/bin/nmap'
    ],
    linux: [
      'nmap',
      '/usr/bin/nmap',
      '/usr/local/bin/nmap'
    ],
    versionArg: '-V'
  },
  tshark: {
    win32: [
      'tshark',
      'C:\\Program Files\\Wireshark\\tshark.exe',
      'C:\\Program Files (x86)\\Wireshark\\tshark.exe'
    ],
    darwin: [
      'tshark',
      '/opt/homebrew/bin/tshark',
      '/usr/local/bin/tshark',
      '/usr/bin/tshark',
      '/opt/local/bin/tshark',
      '/Applications/Wireshark.app/Contents/MacOS/tshark'
    ],
    linux: [
      'tshark',
      '/usr/bin/tshark',
      '/usr/local/bin/tshark'
    ],
    versionArg: '-v'
  },
  hydra: {
    win32: [
      'hydra',
      'C:\\Program Files\\THC-Hydra\\hydra.exe'
    ],
    darwin: [
      'hydra',
      '/opt/homebrew/bin/hydra',
      '/usr/local/bin/hydra'
    ],
    linux: [
      'hydra',
      '/usr/bin/hydra',
      '/usr/local/bin/hydra'
    ],
    versionArg: '-h'
  },
  msfrpcd: {
    win32: [
      'msfrpcd',
      'C:\\metasploit-framework\\bin\\msfrpcd.bat',
      'C:\\Program Files\\Metasploit\\bin\\msfrpcd.bat'
    ],
    darwin: [
      'msfrpcd',
      '/opt/metasploit-framework/bin/msfrpcd',
      '/usr/local/bin/msfrpcd',
      '/opt/homebrew/bin/msfrpcd'
    ],
    linux: [
      'msfrpcd',
      '/usr/bin/msfrpcd',
      '/opt/metasploit-framework/bin/msfrpcd',
      '/usr/local/bin/msfrpcd'
    ],
    versionArg: '-h'
  },
  smbclient: {
    win32: [
      'smbclient'
    ],
    darwin: [
      'smbclient',
      '/opt/homebrew/bin/smbclient',
      '/usr/local/bin/smbclient',
      '/usr/bin/smbclient'
    ],
    linux: [
      'smbclient',
      '/usr/bin/smbclient',
      '/usr/local/bin/smbclient'
    ],
    versionArg: '--version'
  },
  showmount: {
    win32: [
      'showmount'
    ],
    darwin: [
      'showmount',
      '/usr/sbin/showmount',
      '/opt/homebrew/bin/showmount'
    ],
    linux: [
      'showmount',
      '/usr/sbin/showmount',
      '/usr/bin/showmount'
    ],
    versionArg: '--version'
  }
};

const store = new Store({ schema });

export function getSetting(key) {
  return store.get(key);
}

export function setSetting(key, value) {
  store.set(key, value);
}

export function getAllSettings() {
  return store.store;
}

export async function checkDependency(toolName) {
  const config = DEPENDENCY_PATHS[toolName];
  if (!config) {
    throw new Error(`Unknown tool: ${toolName}`);
  }

  const platform = process.platform;
  // Fallback to linux paths if platform not specifically defined
  const paths = config[platform] || config.linux || [];
  const versionArg = config.versionArg;

  const commandsToCheck = paths.map(p => ({
    cmd: p.includes(' ') || p.includes('\\') ? `"${p}" ${versionArg}` : `${p} ${versionArg}`,
    path: p
  }));

  let lastError;
  for (const { cmd, path } of commandsToCheck) {
     try {
       const { stdout } = await execPromise(cmd);
       // Save discovered path automatically to the DB so scanners can use it
       setSetting(`${toolName}.path`, path);
       return { installed: true, output: stdout.split('\n')[0].trim() };
     } catch (error) {
       // Some tools (e.g. hydra -h) exit with non-zero but still produce output.
       // If we got stdout/stderr output, the binary exists — treat as installed.
       // But filter out shell-level "command not found" messages.
       const output = error.stdout || error.stderr || '';
       const isShellNotFound = /is not recognized|not found|no such file|cannot find/i.test(output);
       if (output.trim().length > 0 && !isShellNotFound) {
         setSetting(`${toolName}.path`, path);
         return { installed: true, output: output.split('\n')[0].trim() };
       }
       lastError = error;
     }
  }

  // If all failed
  setSetting(`${toolName}.path`, '');
  return { installed: false, error: lastError?.message || 'Unknown execution error' };
}
