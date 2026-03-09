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
      'impacket-smbclient',
      'impacket-smbclient.exe',
      'smbclient.exe',
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
  const versionArg = config.versionArg;
  const commandsToCheck = [];

  // Check for a saved custom manual path override
  const savedPath = getSetting(`${toolName}.path`);
  const isCustomPath = savedPath && savedPath.trim().length > 0;

  if (isCustomPath) {
    const isPython = savedPath.toLowerCase().endsWith('.py');
    const baseCmd = savedPath.includes(' ') || savedPath.includes('\\') ? `"${savedPath}"` : savedPath;
    commandsToCheck.push({
      cmd: isPython ? `python ${baseCmd} ${versionArg}` : `${baseCmd} ${versionArg}`,
      path: savedPath
    });
  } else {
    // Fallback to default auto-detection list if no custom path exists
    const paths = config[platform] || config.linux || [];
    paths.forEach(p => {
      const isPython = p.toLowerCase().endsWith('.py');
      const baseCmd = p.includes(' ') || p.includes('\\') ? `"${p}"` : p;
      commandsToCheck.push({
        cmd: isPython ? `python ${baseCmd} ${versionArg}` : `${baseCmd} ${versionArg}`,
        path: p
      });
    });
  }

  let lastError;
  for (const { cmd, path } of commandsToCheck) {
     try {
       const { stdout } = await execPromise(cmd);
       // only map auto-discovered path if we were relying on defaults
       if (!isCustomPath) setSetting(`${toolName}.path`, path);
       return { installed: true, output: stdout.split('\n')[0].trim() };
     } catch (error) {
       const output = error.stdout || error.stderr || '';
       const isShellNotFound = /is not recognized|not found|no such file|cannot find/i.test(output);
       // Impacket crashes with exit code 1 when passed -V, but we can still parse the version string
       const isImpacketVersion = output.toLowerCase().includes('impacket');
       
       if ((output.trim().length > 0 && !isShellNotFound) || isImpacketVersion) {
         if (!isCustomPath) setSetting(`${toolName}.path`, path);
         return { installed: true, output: output.split('\n')[0].trim() };
       }
       lastError = error;
     }
  }

  // If all failed, DO NOT wipe custom path so the user can fix it
  if (!isCustomPath) {
    setSetting(`${toolName}.path`, '');
  }
  return { installed: false, error: lastError?.message || 'Unknown execution error' };
}
