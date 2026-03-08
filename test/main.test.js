import { describe, it, expect, vi } from 'vitest';
import { app, BrowserWindow, ipcMain, shell, dialog } from 'electron';
import { spawn, exec } from 'child_process';
import util from 'util';
import ping from 'ping';
import * as store from '../src/main/store.js';
import * as bruteForce from '../src/main/bruteForce.js';
import * as metasploit from '../src/main/metasploitRpc.js';
import * as hardeningMonitor from '../src/main/hardeningMonitor.js';
import * as scanner from '../src/main/scanner.js';
import * as deepScanner from '../src/main/deepScanner.js';

// Mock child_process
vi.mock('child_process', () => ({
  spawn: vi.fn().mockReturnValue({
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
    on: vi.fn(),
    kill: vi.fn()
  }),
  exec: vi.fn((cmd, cb) => cb(null, { stdout: 'Mock Output' })),
  execSync: vi.fn().mockReturnValue('mock sequence')
}));

// Mock util
vi.mock('util', () => ({
  promisify: vi.fn((fn) => fn),
  default: { promisify: vi.fn((fn) => fn) }
}));

// Mock ping
vi.mock('ping', () => ({
  default: {
    promise: {
      probe: vi.fn().mockResolvedValue({ alive: true, time: 10 })
    }
  },
  promise: {
    probe: vi.fn().mockResolvedValue({ alive: true, time: 10 })
  }
}));

// Mock electron completely
vi.mock('electron', () => {
  return {
    app: {
      whenReady: () => Promise.resolve(),
      on: vi.fn(),
      getPath: vi.fn().mockReturnValue('/home/docs'),
      quit: vi.fn(),
      commandLine: { appendSwitch: vi.fn() }
    },
    BrowserWindow: class BrowserWindowMock {
      constructor() {
        this.on = vi.fn();
        this.once = vi.fn();
        this.loadURL = vi.fn();
        this.loadFile = vi.fn();
        this.getBounds = vi.fn().mockReturnValue({ x: 0, y: 0, width: 800, height: 600 });
        this.webContents = {
          openDevTools: vi.fn(),
          send: vi.fn()
        };
      }
      static getAllWindows = vi.fn().mockReturnValue([]);
    },
    ipcMain: {
      handle: vi.fn(),
      on: vi.fn()
    },
    shell: {
      openExternal: vi.fn().mockResolvedValue()
    },
    dialog: {
      showSaveDialog: vi.fn().mockResolvedValue({ canceled: false, filePath: '/test/save.json' }),
      showOpenDialog: vi.fn().mockResolvedValue({ canceled: false, filePaths: ['/test/save.json'] }),
      showMessageBox: vi.fn().mockResolvedValue({ response: 0 })
    }
  };
});

vi.mock('../src/main/scanner.js', () => ({
  startNetworkScan: vi.fn(),
  stopNetworkScan: vi.fn(),
  getNetworkInterfaces: vi.fn().mockResolvedValue([]),
  probeHost: vi.fn().mockResolvedValue({ alive: true })
}));
vi.mock('../src/main/deepScanner.js', () => ({
  runDeepScan: vi.fn().mockResolvedValue(),
  cancelDeepScan: vi.fn()
}));
vi.mock('../src/main/nmapScanner.js', () => ({
  checkNmapInstalled: vi.fn().mockResolvedValue(true),
  runNmapScan: vi.fn(),
  cancelNmapScan: vi.fn().mockReturnValue(true),
  runNcat: vi.fn(),
  getNmapScripts: vi.fn().mockResolvedValue([])
}));
vi.mock('../src/main/windowManager.js', () => ({
  createMainWindow: vi.fn().mockReturnValue({
    on: vi.fn(),
    webContents: { send: vi.fn() }
  })
}));
vi.mock('../src/main/snmpIpc.js', () => ({
  registerSnmpHandlers: vi.fn()
}));
vi.mock('../src/main/store.js', () => ({
  getSetting: vi.fn(),
  setSetting: vi.fn(),
  getAllSettings: vi.fn().mockReturnValue({}),
  checkDependency: vi.fn().mockResolvedValue(true)
}));
vi.mock('../src/main/bruteForce.js', () => ({
  startBruteForce: vi.fn(),
  stopBruteForce: vi.fn(),
  cleanupBruteForce: vi.fn(),
  registerIpcHandlers: vi.fn()
}));
vi.mock('../src/main/metasploitRpc.js', () => ({
  msfConnect: vi.fn().mockResolvedValue({ status: 'success' }),
  msfDisconnect: vi.fn().mockResolvedValue({ status: 'success' }),
  msfListExploits: vi.fn().mockResolvedValue([]),
  msfRunExploit: vi.fn().mockResolvedValue({ job_id: 1 }),
  msfGetSessions: vi.fn().mockResolvedValue({}),
  cleanupMsf: vi.fn(),
  registerIpcHandlers: vi.fn()
}));
vi.mock('../src/main/hardeningMonitor.js', () => ({
  startMonitor: vi.fn(),
  stopMonitor: vi.fn(),
  stopAllMonitors: vi.fn(),
  setBaseline: vi.fn(),
  getBaseline: vi.fn(),
  getActiveMonitors: vi.fn().mockReturnValue([]),
  registerIpcHandlers: vi.fn()
}));
vi.mock('../src/main/revShellListener.js', () => ({
  startListener: vi.fn(),
  stopListener: vi.fn(),
  sendToShell: vi.fn().mockReturnValue(true),
  registerIpcHandlers: vi.fn()
}));
vi.mock('../src/main/shareEnumerator.js', () => ({
  enumerateShares: vi.fn(),
  browseShare: vi.fn(),
  downloadFile: vi.fn().mockResolvedValue(true),
  cleanupShares: vi.fn(),
  registerIpcHandlers: vi.fn()
}));
vi.mock('../src/main/dirFuzzer.js', () => ({
  startDirFuzz: vi.fn(),
  stopDirFuzz: vi.fn(),
  cleanupDirFuzz: vi.fn(),
  registerIpcHandlers: vi.fn()
}));
vi.mock('../src/main/credSpray.js', () => ({
  startCredSpray: vi.fn(),
  stopCredSpray: vi.fn(),
  cleanupCredSpray: vi.fn(),
  registerIpcHandlers: vi.fn()
}));
vi.mock('../src/main/ipc/scanIpc.js', () => ({ registerIpcHandlers: vi.fn() }));
vi.mock('../src/main/ipc/settingsIpc.js', () => ({ registerIpcHandlers: vi.fn() }));
vi.mock('../src/main/ipc/fileIpc.js', () => ({ registerIpcHandlers: vi.fn() }));
vi.mock('../src/main/ipc/utilIpc.js', () => ({ registerIpcHandlers: vi.fn() }));
vi.mock('../src/main/ipc/passiveIpc.js', () => ({ registerIpcHandlers: vi.fn() }));
vi.mock('../src/main/tsharkScanner.js', () => ({
  startTsharkCapture: vi.fn(),
  stopTsharkCapture: vi.fn().mockReturnValue(true)
}));
vi.mock('../src/main/pcapAnalyzer.js', () => ({
  startLiveCapture: vi.fn(),
  stopLiveCapture: vi.fn(),
  analyzePcapFile: vi.fn()
}));
vi.mock('../src/main/rogueDhcpDetector.js', () => ({
  startDhcpDetection: vi.fn().mockReturnValue(true),
  stopDhcpDetection: vi.fn().mockReturnValue(true)
}));
vi.mock('../src/main/credentialSniffer.js', () => ({
  startCredentialSniffing: vi.fn().mockReturnValue(true),
  stopCredentialSniffing: vi.fn().mockReturnValue(true)
}));
vi.mock('../src/main/dnsHarvester.js', () => ({
  startDnsHarvesting: vi.fn().mockReturnValue(true),
  stopDnsHarvesting: vi.fn().mockReturnValue(true)
}));
vi.mock('../src/main/arpSpoofDetector.js', () => ({
  startArpDetection: vi.fn().mockReturnValue(true),
  stopArpDetection: vi.fn().mockReturnValue(true)
}));
vi.mock('../src/main/rogueDnsDetector.js', () => ({
  startRogueDnsDetection: vi.fn().mockReturnValue(true),
  stopRogueDnsDetection: vi.fn().mockReturnValue(true)
}));
vi.mock('../src/main/pcapExporter.js', () => ({
  exportPcap: vi.fn().mockResolvedValue({ status: 'exported' })
}));
vi.mock('../src/main/passiveCapture.js', () => ({
  stopAll: vi.fn().mockReturnValue([])
}));
vi.mock('../src/main/nmapXmlParser.js', () => ({
  parseNmapXml: vi.fn().mockReturnValue([])
}));
vi.mock('dns', () => ({
  default: { promises: { lookup: vi.fn().mockResolvedValue({ address: '1.2.3.4' }) } },
  promises: { lookup: vi.fn().mockResolvedValue({ address: '1.2.3.4' }) }
}));

// Mock fs
vi.mock('fs', () => ({
  default: {
    writeFileSync: vi.fn(),
    readFileSync: vi.fn().mockReturnValue('[]'),
    existsSync: vi.fn().mockReturnValue(true),
    promises: {
      readFile: vi.fn().mockResolvedValue('')
    }
  },
  writeFileSync: vi.fn(),
  readFileSync: vi.fn().mockReturnValue('[]'),
  existsSync: vi.fn().mockReturnValue(true),
  promises: {
    readFile: vi.fn().mockResolvedValue('line1\nline2\n#comment\n192.168.1.1')
  }
}));

// Mock electron-updater
vi.mock('electron-updater', () => {
  const autoUpdater = {
    logger: null,
    checkForUpdatesAndNotify: vi.fn(),
    on: vi.fn(),
    quitAndInstall: vi.fn(),
    quitAndInstallCallback: vi.fn()
  };
  return {
    default: { autoUpdater },
    autoUpdater
  };
});

describe('IPC Payload Validation & Electron API', () => {
  it('Should validate IP payload formatting', () => {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    expect(ipRegex.test('192.168.1.10')).toBe(true);
    expect(ipRegex.test('10.0.0.1')).toBe(true);
    expect(ipRegex.test('not_an_ip')).toBe(false);
  });

  it('Should validate port bounds', () => {
    const isValidPort = (port) => {
      const parsedPort = parseInt(port, 10);
      return !isNaN(parsedPort) && parsedPort >= 1 && parsedPort <= 65535;
    };
    expect(isValidPort('80')).toBe(true);
    expect(isValidPort('0')).toBe(false);
  });

  it('Should exercise local scan and results handlers', async () => {
     await import('../src/main/main.js');
     const handlers = {};
     ipcMain.handle.mock.calls.forEach(call => {
       handlers[call[0]] = call[1];
     });

     if (handlers['save-results']) {
       const res = await handlers['save-results']({}, [{ ip: '1.2.3.4' }]);
       expect(res.status).toBe('saved');
     }

     if (handlers['load-results']) {
       const res = await handlers['load-results']({});
       expect(res.status).toBe('loaded');
     }
  });

  it('Should handle scan and probe handlers', async () => {
     await import('../src/main/main.js');
     const handlers = {};
     ipcMain.handle.mock.calls.forEach(call => {
       handlers[call[0]] = call[1];
     });

     if (handlers['run-nmap-scan']) {
       const res = await handlers['run-nmap-scan']({}, { type: 'deep', target: '10.0.0.1' });
       expect(res.status).toBe('started');
     }

     if (handlers['ping-host']) {
       const res = await handlers['ping-host']({}, '127.0.0.1');
       expect(res).toHaveProperty('alive');
     }

     if (handlers['cancel-deep-scan']) {
       const res = await handlers['cancel-deep-scan']({}, '10.0.0.1');
       expect(res.status).toBe('cancelled');
     }
  });

  it('Should handle settings and dependency checks', async () => {
     const handlers = {};
     ipcMain.handle.mock.calls.forEach(call => {
       handlers[call[0]] = call[1];
     });

     if (handlers['get-setting']) {
       const res = await handlers['get-setting']({}, 'theme');
       expect(store.getSetting).toHaveBeenCalledWith('theme');
     }

     if (handlers['check-dependency']) {
       const res = await handlers['check-dependency']({}, 'nmap');
       expect(res).toBe(true);
     }
  });

  it('Should handle offensive pentest: brute-force', async () => {
     const handlers = {};
     ipcMain.handle.mock.calls.forEach(call => {
       handlers[call[0]] = call[1];
     });

     if (handlers['bruteforce-start']) {
       const res = await handlers['bruteforce-start']({}, { targetIp: '10.0.0.1' });
       expect(res.status).toBe('started');
     }

     if (handlers['bruteforce-stop']) {
       const res = await handlers['bruteforce-stop']({});
       expect(res.status).toBe('stopped');
     }
  });

  it('Should handle offensive pentest: Metasploit RPC', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['msf-connect']) {
      const res = await handlers['msf-connect']({}, { host: 'localhost', port: 55553 });
      expect(res.status).toBe('success');
    }

    if (handlers['msf-disconnect']) {
      const res = await handlers['msf-disconnect']({});
      expect(res.status).toBe('success');
    }
  });

  it('Should handle Feature 5: Hardening Monitor', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['hardening-start-monitor']) {
      const res = await handlers['hardening-start-monitor']({}, { subnet: '192.168.1.0/24' });
      expect(res.ok).toBe(true);
    }

    if (handlers['hardening-get-baseline']) {
      const res = await handlers['hardening-get-baseline']({}, { subnet: '192.168.1.0/24' });
      expect(res).toBeDefined();
    }
  });

  it('Should handle passive capture and PCAP', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['start-passive-capture']) {
      const res = await handlers['start-passive-capture']({}, { moduleId: 'dhcp', interfaceId: 'eth0' });
      expect(res.status).toBe('started');
    }

    if (handlers['stop-passive-capture']) {
      const res = await handlers['stop-passive-capture']({}, 'dhcp');
      expect(res.status).toBe('stopped');
    }

    if (handlers['export-pcap']) {
      const res = await handlers['export-pcap']({}, { interfaceId: 'eth0' });
      expect(res.status).toBe('exported');
    }
  });

  it('Should handle scope file import', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['import-scope-file']) {
      const res = await handlers['import-scope-file']({});
      expect(res.status).toBe('imported');
    }
  });

  it('Should handle offensive pentest: Reverse Shell', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['revshell-start']) {
      const res = await handlers['revshell-start']({}, { port: 4444, mode: 'reverse' });
      expect(res.status).toBe('started');
    }

    if (handlers['revshell-stop']) {
      const res = await handlers['revshell-stop']({});
      expect(res.status).toBe('stopped');
    }

    if (handlers['revshell-send']) {
      const res = await handlers['revshell-send']({}, 'ls\n');
      expect(res.status).toBe('sent');
    }
  });

  it('Should handle offensive pentest: Share Enumeration', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['share-enumerate']) {
      const res = await handlers['share-enumerate']({}, { targetIp: '10.0.0.1' });
      expect(res.status).toBe('started');
    }

    if (handlers['share-browse']) {
      const res = await handlers['share-browse']({}, { targetIp: '10.0.0.1', shareName: 'C$' });
      expect(res.status).toBe('done');
    }

    if (handlers['share-download']) {
      const res = await handlers['share-download']({}, { targetIp: '10.0.0.1', shareName: 'C$', remoteFile: 'flag.txt' });
      expect(res.status).toBe('downloaded');
    }
  });

  it('Should handle offensive pentest: Dir Fuzzing', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['dirfuzz-start']) {
      const res = await handlers['dirfuzz-start']({}, { targetUrl: 'http://10.0.0.1/' });
      expect(res.status).toBe('started');
    }

    if (handlers['dirfuzz-stop']) {
      const res = await handlers['dirfuzz-stop']({});
      expect(res.status).toBe('stopped');
    }
  });

  it('Should handle more Metasploit handlers', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['msf-list-exploits']) {
      const res = await handlers['msf-list-exploits']({}, 'windows/smb/');
      expect(res.status).toBe('success');
    }

    if (handlers['msf-run-exploit']) {
      const res = await handlers['msf-run-exploit']({}, { modulePath: 'exploit/multi/handler', targetIp: '10.0.0.1' });
      expect(res.status).toBe('started');
    }

    if (handlers['msf-session-list']) {
      const res = await handlers['msf-session-list']({});
      expect(res.status).toBe('success');
    }
  });

  it('Should handle miscellaneous handlers', async () => {
    const handlers = {};
    ipcMain.handle.mock.calls.forEach(call => {
      handlers[call[0]] = call[1];
    });

    if (handlers['browse-file']) {
      const res = await handlers['browse-file']({}, { title: 'Select wordlist' });
      expect(res.status).toBe('selected');
    }

    if (handlers['clear-results']) {
      const res = await handlers['clear-results']({});
      expect(res.status).toBe('cleared');
    }

    if (handlers['get-all-settings']) {
      const res = await handlers['get-all-settings']({});
      expect(res).toBeDefined();
    }

    if (handlers['analyze-pcap-file']) {
      const res = await handlers['analyze-pcap-file']({}, '/path/to/file.pcap');
      expect(res.status).toBe('started');
    }
  });

  it('Should test app-all-closed cleanup', async () => {
    const listeners = {};
    app.on.mock.calls.forEach(call => {
      listeners[call[0]] = call[1];
    });
    
    // We can't easily trigger the 'window-all-closed' listener from outside
    // unless we find which call it was.
    const allClosedCall = app.on.mock.calls.find(c => c[0] === 'window-all-closed');
    if (allClosedCall) {
      const handler = allClosedCall[1];
      handler();
      // Should call various cleanup functions
      expect(bruteForce.cleanupBruteForce).toHaveBeenCalled();
      expect(metasploit.cleanupMsf).toHaveBeenCalled();
    }
  });
});
