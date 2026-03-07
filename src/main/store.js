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
       lastError = error;
     }
  }

  // If all failed
  setSetting(`${toolName}.path`, '');
  return { installed: false, error: lastError?.message || 'Unknown execution error' };
}
