import { app, BrowserWindow, ipcMain, shell, dialog } from 'electron';
import net from 'net';
import pkg from 'electron-updater';
const { autoUpdater } = pkg;
import { IPC_CHANNELS } from '#shared/ipc.js';
import { expandCIDR } from '#shared/networkConstants.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import dns from 'dns';
const dnsPromises = dns.promises;
import { spawn, exec } from 'child_process';

// --- Linux Root/Sandbox Detection ---
// Chromium refuses to start with sandboxing when running as root (UID 0).
// Network scanning tools are often launched with sudo on Linux,
// so we defensively disable the sandbox in that case.
if (process.platform === 'linux' && process.getuid && process.getuid() === 0) {
  app.commandLine.appendSwitch('no-sandbox');
  console.warn('[NetSpecter] Running as root — Chromium sandbox disabled via --no-sandbox.');
}

import { startNetworkScan, stopNetworkScan, getNetworkInterfaces, probeHost } from './scanner.js';
import { runDeepScan, cancelDeepScan } from './deepScanner.js';
import { checkNmapInstalled, runNmapScan, cancelNmapScan, runNcat, getNmapScripts } from './nmapScanner.js';
import { createMainWindow } from './windowManager.js';
import { parseNmapXml } from './nmapXmlParser.js';
import { registerSnmpHandlers } from './snmpIpc.js';
import ping from 'ping';
import { getSetting, setSetting, getAllSettings, checkDependency } from './store.js';
import { startTsharkCapture, stopTsharkCapture } from './tsharkScanner.js';
import { startDhcpDetection, stopDhcpDetection } from './rogueDhcpDetector.js';
import { startCredentialSniffing, stopCredentialSniffing } from './credentialSniffer.js';
import { startDnsHarvesting, stopDnsHarvesting } from './dnsHarvester.js';
import { startArpDetection, stopArpDetection } from './arpSpoofDetector.js';
import { exportPcap } from './pcapExporter.js';
import { stopAll as stopAllPassive } from './passiveCapture.js';
import { startLiveCapture, stopLiveCapture, analyzePcapFile } from './pcapAnalyzer.js';
import { startRogueDnsDetection, stopRogueDnsDetection } from './rogueDnsDetector.js';
import { startBruteForce, stopBruteForce, cleanupBruteForce } from './bruteForce.js';
import { msfConnect, msfDisconnect, msfListExploits, msfRunExploit, msfGetSessions, cleanupMsf } from './metasploitRpc.js';
import { startListener as startRevShell, stopListener as stopRevShell, sendToShell as sendRevShell } from './revShellListener.js';
import { enumerateShares, browseShare, downloadFile as downloadShareFile, cleanupShares } from './shareEnumerator.js';
import { startDirFuzz, stopDirFuzz, cleanupDirFuzz } from './dirFuzzer.js';
import {
  startMonitor as startHardeningMonitor,
  stopMonitor  as stopHardeningMonitor,
  stopAllMonitors,
  setBaseline  as setHardeningBaseline,
  getBaseline  as getHardeningBaseline,
  getActiveMonitors,
} from './hardeningMonitor.js';
import { startCredSpray, stopCredSpray, cleanupCredSpray } from './credSpray.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isDev = process.env.NODE_ENV === 'development';

let mainWindow;

function checkPort(port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(200);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, '127.0.0.1');
  });
}

async function createWindow() {
  let devPort = process.env.VITE_PORT || '5173';
  
  if (isDev) {
    // Check if 5173 is actually open, if not try 5174
    const is5173Open = await checkPort(5173);
    if (!is5173Open) {
      const is5174Open = await checkPort(5174);
      if (is5174Open) devPort = '5174';
    }
  }

  const devUrl = `http://localhost:${devPort}`;
  console.log(`[NetSpecter] Dev Mode: Loading ${devUrl}`);
  
  mainWindow = createMainWindow(
    isDev, 
    (p) => path.join(__dirname, p), 
    devUrl
  );
  registerSnmpHandlers(ipcMain, mainWindow);
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  // Init Auto-Updater
  autoUpdater.logger = console;
  autoUpdater.checkForUpdatesAndNotify();

  autoUpdater.on('update-available', () => {
    console.log('Update available.');
  });

  autoUpdater.on('download-progress', (progressObj) => {
    console.log(`Download speed: ${progressObj.bytesPerSecond} - Downloaded ${progressObj.percent}% (${progressObj.transferred}/${progressObj.total})`);
  });

  autoUpdater.on('update-downloaded', () => {
    console.log('Update downloaded. Prompting user to install.');
    dialog.showMessageBox({
      type: 'info',
      title: 'Update Ready',
      message: 'A new version of NetSpecter is ready. Quit and Install now?',
      buttons: ['Yes', 'Later']
    }).then((result) => {
      if (result.response === 0) {
        autoUpdater.quitAndInstall();
      }
    });
  });
});

app.on('window-all-closed', function () {
  cleanupBruteForce();
  cleanupMsf();
  stopRevShell();
  cleanupShares();
  cleanupDirFuzz();
  stopAllMonitors();
  cleanupCredSpray();
  if (process.platform !== 'darwin') app.quit();
});

// IPC Handler stubs for future Network Scanner logic
ipcMain.handle(IPC_CHANNELS.GET_INTERFACES, async () => {
  return getNetworkInterfaces();
});

ipcMain.handle(IPC_CHANNELS.SCAN_NETWORK, async (event, subnet) => {
  console.log(`Scan requested on subnet: ${subnet}`);
  
  startNetworkScan(
    subnet,
    (hostData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.HOST_FOUND, hostData);
    },
    (completeMsg) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.SCAN_COMPLETE, completeMsg);
    }
  );

  return { status: 'scanning' };
});

ipcMain.handle(IPC_CHANNELS.RUN_DEEP_SCAN, async (event, ip) => {
  console.log(`Deep scan requested for ${ip}`);
  
  // Run asynchronously without blocking
  runDeepScan(ip, (portData) => {
    if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.DEEP_SCAN_RESULT, { ip, ...portData });
  }, (progressData) => {
    if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.DEEP_SCAN_PROGRESS, progressData);
  }).then(() => {
    if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.DEEP_SCAN_COMPLETE, { ip });
  }).catch(err => {
    console.error(`Deep scan error on ${ip}:`, err);
  });

  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.CANCEL_DEEP_SCAN, async (event, ip) => {
  console.log(`Deep scan cancel requested for ${ip}`);
  cancelDeepScan(ip);
  return { status: 'cancelled' };
});

ipcMain.handle(IPC_CHANNELS.CHECK_NMAP, async () => {
  return await checkNmapInstalled();
});

// SNMP Handlers registered via snmpIpc.js

// --- Settings Management ---

ipcMain.handle(IPC_CHANNELS.GET_SETTING, (event, key) => {
  return getSetting(key);
});

ipcMain.handle(IPC_CHANNELS.SET_SETTING, (event, { key, value }) => {
  setSetting(key, value);
  return { success: true };
});

ipcMain.handle(IPC_CHANNELS.GET_ALL_SETTINGS, () => {
  return getAllSettings();
});

ipcMain.handle(IPC_CHANNELS.CHECK_DEPENDENCY, async (event, toolName) => {
  return await checkDependency(toolName);
});

// --- Node Scanning & Execution ---

ipcMain.handle(IPC_CHANNELS.RUN_NMAP_SCAN, async (event, payload) => {
  const { type, target } = payload;
  console.log(`Nmap scan requested: ${type} on ${typeof target === 'string' ? target : target.ip}`);
  
  runNmapScan(type, target, 
    (chunkData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_RESULT, { target, type, ...chunkData });
    },
    (completeData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_COMPLETE, { type, ...completeData });
    },
    (errorData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_ERROR, { target, type, ...errorData });
    }
  );

  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.CANCEL_NMAP_SCAN, async (event, target) => {
  console.log(`Nmap scan cancel requested for ${target}`);
  const success = cancelNmapScan(target);
  return { status: success ? 'cancelled' : 'not_found' };
});

ipcMain.handle(IPC_CHANNELS.GET_NMAP_SCRIPTS, async () => {
  return await getNmapScripts();
});

ipcMain.handle(IPC_CHANNELS.RUN_NCAT, async (event, payloadObj) => {
  console.log(`Ncat requested on ${payloadObj.target}:${payloadObj.port}`);
  runNcat(payloadObj, 
    (chunkData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_RESULT, { target: payloadObj.target, type: 'ncat', ...chunkData });
    },
    (completeData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_COMPLETE, { type: 'ncat', target: payloadObj.target, ...completeData });
    },
    (errorData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_ERROR, { target: payloadObj.target, type: 'ncat', ...errorData });
    }
  );
  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.STOP_SCAN, async (event) => {
  console.log('Stop requested');
  stopNetworkScan();
  return { status: 'stopped' };
});

ipcMain.handle(IPC_CHANNELS.OPEN_EXTERNAL_ACTION, async (event, { type, ip, port, username }) => {
  console.log(`External action requested: ${type} to ${ip}:${port}`);
  
  // Detailed Security Payload Validation
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (!ip || !ipRegex.test(ip)) {
     console.error('INVALID IP FORMAT REJECTED');
     return { success: false, error: 'Invalid IP address format' };
  }
  
  if (port) {
     const parsedPort = parseInt(port, 10);
     if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
       console.error('INVALID PORT BOUNDS REJECTED');
       return { success: false, error: 'Invalid port number' };
     }
  }

  try {
    if (type === 'http' || type === 'https') {
      await shell.openExternal(`${type}://${ip}${port ? ':' + port : ''}`);
    } else if (type === 'ssh') {
      const user = (username || 'root').replace(/[^a-zA-Z0-9_\-]/g, ''); // Basic sanitization
      if (process.platform === 'win32') {
        spawn('cmd.exe', ['/c', 'start', 'cmd.exe', '/k', `ssh ${user}@${ip}`]);
      } else if (process.platform === 'darwin') {
        exec(`osascript -e 'tell app "Terminal" to do script "ssh ${user}@${ip}"'`);
      } else {
        exec(`gnome-terminal -- ssh ${user}@${ip}`);
      }
    } else if (type === 'rdp') {
      if (process.platform === 'win32') {
        spawn('mstsc.exe', [`/v:${ip}`]);
      } else {
        console.warn('RDP launch only supported natively on Windows');
      }
    }
    return { success: true };
  } catch (err) {
    console.error(`Failed to launch external command:`, err);
    return { success: false, error: err.message };
  }
});

// --- Tshark (VLAN Discovery) ---

ipcMain.handle(IPC_CHANNELS.START_TSHARK, async (event, interfaceId) => {
  console.log(`Starting Tshark on interface: ${interfaceId}`);
  
  startTsharkCapture(interfaceId, 
    (vlanData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.TSHARK_VLAN_FOUND, vlanData);
    },
    (errorData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.TSHARK_ERROR, errorData);
    },
    (completeData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.TSHARK_COMPLETE, completeData);
    }
  );
  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.STOP_TSHARK, async () => {
  const stopped = stopTsharkCapture();
  return { status: stopped ? 'stopped' : 'not_running' };
});

// --- Passive Network Intelligence ---

function wirePcapLiveCapture(interfaceId, hostIp, options) {
  startLiveCapture(
    interfaceId,
    hostIp ?? options?.host,
    options,
    (summary) => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_PACKET_SUMMARY, summary),
    (stats)   => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_STATS_UPDATE, stats),
    (err)     => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_CAPTURE_ERROR, err),
    (msg)     => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_CAPTURE_COMPLETE, msg)
  );
}

const passiveStartHandlers = {
  dhcp: (iface, options, onError, onComplete) =>
    startDhcpDetection(iface,
      (alert) => mainWindow?.webContents.send(IPC_CHANNELS.PASSIVE_DHCP_ALERT, alert),
      onError, onComplete),
  creds: (iface, options, onError, onComplete) =>
    startCredentialSniffing(iface,
      (cred) => mainWindow?.webContents.send(IPC_CHANNELS.PASSIVE_CRED_FOUND, cred),
      onError, onComplete),
  dns: (iface, options, onError, onComplete) =>
    startDnsHarvesting(iface,
      (host) => mainWindow?.webContents.send(IPC_CHANNELS.PASSIVE_DNS_HOST, host),
      onError, onComplete),
  arp: (iface, options, onError, onComplete) =>
    startArpDetection(iface,
      (alert) => mainWindow?.webContents.send(IPC_CHANNELS.PASSIVE_ARP_ALERT, alert),
      onError, onComplete),
  'rogue-dns': (iface, options, onError, onComplete) =>
    startRogueDnsDetection(iface,
      (alert) => mainWindow?.webContents.send(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ALERT, alert),
      onError, onComplete),
  pcap: (iface, options, onError, onComplete) => {
    wirePcapLiveCapture(iface, options?.host, options);
    onComplete?.({ moduleId: 'pcap' });
    return true;
  }
};

const passiveStopHandlers = {
  dhcp: () => stopDhcpDetection(),
  creds: () => stopCredentialSniffing(),
  dns: () => stopDnsHarvesting(),
  arp: () => stopArpDetection(),
  'rogue-dns': () => stopRogueDnsDetection(),
  pcap: () => { stopLiveCapture(); return true; }
};

ipcMain.handle(IPC_CHANNELS.START_PASSIVE_CAPTURE, async (event, { moduleId, interfaceId, options }) => {
  console.log(`Starting passive capture module: ${moduleId} on ${interfaceId}`);

  const channelMap = {
    dhcp:       IPC_CHANNELS.PASSIVE_DHCP_ERROR,
    creds:      IPC_CHANNELS.PASSIVE_CRED_ERROR,
    dns:        IPC_CHANNELS.PASSIVE_DNS_ERROR,
    arp:        IPC_CHANNELS.PASSIVE_ARP_ERROR,
    'rogue-dns': IPC_CHANNELS.PASSIVE_ROGUE_DNS_ERROR,
    pcap:       IPC_CHANNELS.PCAP_CAPTURE_ERROR,
  };

  const onError = (errorMsg) => {
    const channel = channelMap[moduleId];
    if (mainWindow && channel) {
      mainWindow.webContents.send(channel, errorMsg);
    }
  };

  const onComplete = (data) => {
    if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE, data);
  };

  const startHandler = passiveStartHandlers[moduleId];
  const success = startHandler ? !!startHandler(interfaceId, options, onError, onComplete) : false;

  return { status: success ? 'started' : 'failed' };
});

ipcMain.handle(IPC_CHANNELS.STOP_PASSIVE_CAPTURE, async (event, moduleId) => {
  console.log(`Stopping passive capture module: ${moduleId}`);
  const stopHandler = passiveStopHandlers[moduleId];
  const stopped = stopHandler ? !!stopHandler() : false;
  return { status: stopped ? 'stopped' : 'not_running' };
});

ipcMain.handle(IPC_CHANNELS.STOP_ALL_PASSIVE, async () => {
  console.log('Stopping all passive capture modules');
  const stopped = stopAllPassive();
  return { status: 'stopped', modules: stopped };
});

ipcMain.handle(IPC_CHANNELS.EXPORT_PCAP, async (event, { interfaceId, hostIp, duration }) => {
  console.log('Starting PCAP export');
  return await exportPcap(
    mainWindow, 
    interfaceId, 
    hostIp, 
    duration,
    (data) => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_EXPORT_COMPLETE, data),
    (err) => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_EXPORT_ERROR, err)
  );
});

// --- PCAP Live Capture & Analysis ---

ipcMain.handle(IPC_CHANNELS.START_PCAP_CAPTURE, async (event, { interfaceId, hostIp, options }) => {
  console.log(`Starting PCAP live capture on ${interfaceId} for ${hostIp || 'all'}`);
  wirePcapLiveCapture(interfaceId, hostIp, options);
  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.STOP_PCAP_CAPTURE, async () => {
  console.log('Stopping PCAP live capture');
  stopLiveCapture();
  return { status: 'stopped' };
});

ipcMain.handle(IPC_CHANNELS.ANALYZE_PCAP_FILE, async (event, filePath) => {
  console.log(`Analyzing PCAP file: ${filePath}`);
  analyzePcapFile(filePath,
    (summary) => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_PACKET_SUMMARY, summary),
    (stats) => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_STATS_UPDATE, stats),
    (err) => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_CAPTURE_ERROR, err),
    (msg) => mainWindow?.webContents.send(IPC_CHANNELS.PCAP_CAPTURE_COMPLETE, msg)
  );
  return { status: 'started' };
});

// --- Offensive Pentest: Brute-Force ---

ipcMain.handle(IPC_CHANNELS.BRUTEFORCE_START, async (event, options) => {
  console.log(`Brute-force requested on ${options?.targetIp}:${options?.port} (${options?.protocol})`);

  // Validate basic input structure
  if (!options || typeof options !== 'object') {
    return { status: 'error', error: 'Invalid options payload' };
  }

  startBruteForce(options,
    (attempt)  => mainWindow?.webContents.send(IPC_CHANNELS.BRUTEFORCE_ATTEMPT, attempt),
    (result)   => mainWindow?.webContents.send(IPC_CHANNELS.BRUTEFORCE_RESULT, result),
    (progress) => mainWindow?.webContents.send(IPC_CHANNELS.BRUTEFORCE_PROGRESS, progress),
    (err)      => mainWindow?.webContents.send(IPC_CHANNELS.BRUTEFORCE_ERROR, err),
    (msg)      => mainWindow?.webContents.send(IPC_CHANNELS.BRUTEFORCE_COMPLETE, msg)
  );
  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.BRUTEFORCE_STOP, async () => {
  console.log('Brute-force stop requested');
  stopBruteForce();
  return { status: 'stopped' };
});

// --- Offensive Pentest: Reverse Shell Listener ---

ipcMain.handle(IPC_CHANNELS.REVSHELL_START, async (event, options) => {
  console.log(`Reverse shell listener requested on port ${options?.port} using ${options?.mode}`);
  
  if (!options || typeof options !== 'object') {
    return { status: 'error', error: 'Invalid options payload' };
  }

  startRevShell(options,
    (conn) => mainWindow?.webContents.send(IPC_CHANNELS.REVSHELL_CONNECTION, conn),
    (data) => mainWindow?.webContents.send(IPC_CHANNELS.REVSHELL_DATA, data),
    (err)  => mainWindow?.webContents.send(IPC_CHANNELS.REVSHELL_ERROR, err)
  );
  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.REVSHELL_STOP, async () => {
  console.log('Reverse shell listener stop requested');
  stopRevShell();
  return { status: 'stopped' };
});

ipcMain.handle(IPC_CHANNELS.REVSHELL_SEND, async (event, data) => {
  const success = sendRevShell(data);
  return { status: success ? 'sent' : 'failed' };
});

// --- Generic File Dialog ---

ipcMain.handle(IPC_CHANNELS.BROWSE_FILE, async (event, options) => {
  const opts = options || {};
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    title: opts.title || 'Select File',
    properties: ['openFile'],
    filters: opts.filters || [{ name: 'All Files', extensions: ['*'] }],
    defaultPath: opts.defaultPath || undefined,
  });
  if (canceled || filePaths.length === 0) return { status: 'cancelled' };
  return { status: 'selected', path: filePaths[0] };
});

// --- Offensive Pentest: Metasploit RPC ---

ipcMain.handle(IPC_CHANNELS.MSF_CONNECT, async (event, options) => {
  console.log(`MSF connect requested to ${options?.host}:${options?.port}`);
  if (!options || typeof options !== 'object') {
    return { status: 'error', error: 'Invalid options payload' };
  }
  try {
    const result = await msfConnect(options);
    mainWindow?.webContents.send(IPC_CHANNELS.MSF_STATUS, { state: 'connected', ...result });
    return result;
  } catch (err) {
    mainWindow?.webContents.send(IPC_CHANNELS.MSF_ERROR, { message: err.message });
    return { status: 'error', error: err.message };
  }
});

ipcMain.handle(IPC_CHANNELS.MSF_DISCONNECT, async () => {
  console.log('MSF disconnect requested');
  try {
    const result = await msfDisconnect();
    mainWindow?.webContents.send(IPC_CHANNELS.MSF_STATUS, { state: 'disconnected' });
    return result;
  } catch (err) {
    return { status: 'error', error: err.message };
  }
});

ipcMain.handle(IPC_CHANNELS.MSF_LIST_EXPLOITS, async (event, query) => {
  console.log(`MSF exploit search: ${query}`);
  try {
    const exploits = await msfListExploits(query);
    return { status: 'success', exploits };
  } catch (err) {
    mainWindow?.webContents.send(IPC_CHANNELS.MSF_ERROR, { message: err.message });
    return { status: 'error', error: err.message };
  }
});

ipcMain.handle(IPC_CHANNELS.MSF_RUN_EXPLOIT, async (event, options) => {
  console.log(`MSF run exploit: ${options?.modulePath} against ${options?.targetIp}`);
  if (!options || typeof options !== 'object') {
    return { status: 'error', error: 'Invalid exploit options' };
  }
  try {
    const result = await msfRunExploit(options);
    mainWindow?.webContents.send(IPC_CHANNELS.MSF_RESULT, result);
    return { status: 'started', ...result };
  } catch (err) {
    mainWindow?.webContents.send(IPC_CHANNELS.MSF_ERROR, { message: err.message });
    return { status: 'error', error: err.message };
  }
});

ipcMain.handle(IPC_CHANNELS.MSF_SESSION_LIST, async () => {
  try {
    const sessions = await msfGetSessions();
    return { status: 'success', sessions };
  } catch (err) {
    mainWindow?.webContents.send(IPC_CHANNELS.MSF_ERROR, { message: err.message });
    return { status: 'error', error: err.message };
  }
});

// --- Offensive Pentest: Share Enumeration (4D) ---

ipcMain.handle(IPC_CHANNELS.SHARE_ENUMERATE, async (event, options) => {
  const { targetIp, credentials } = options || {};
  console.log(`Share enumeration requested on ${targetIp}`);

  if (!options || typeof options !== 'object') {
    return { status: 'error', error: 'Invalid options payload' };
  }

  enumerateShares(
    targetIp,
    credentials || null,
    (result) => mainWindow?.webContents.send(IPC_CHANNELS.SHARE_RESULT, result),
    (err)    => mainWindow?.webContents.send(IPC_CHANNELS.SHARE_ERROR, err)
  );
  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.SHARE_BROWSE, async (event, options) => {
  const { targetIp, shareName, remotePath, credentials } = options || {};
  console.log(`Share browse requested: //${targetIp}/${shareName}${remotePath || '/'}`);

  if (!options || !targetIp || !shareName) {
    return { status: 'error', error: 'targetIp and shareName are required' };
  }

  await browseShare(
    targetIp,
    shareName,
    remotePath || '',
    credentials || null,
    (result) => mainWindow?.webContents.send(IPC_CHANNELS.SHARE_RESULT, { type: 'browse', ...result }),
    (err)    => mainWindow?.webContents.send(IPC_CHANNELS.SHARE_ERROR, err)
  );
  return { status: 'done' };
});

ipcMain.handle(IPC_CHANNELS.SHARE_DOWNLOAD, async (event, options) => {
  const { targetIp, shareName, remoteFile, credentials } = options || {};
  console.log(`Share download requested: //${targetIp}/${shareName}/${remoteFile}`);

  if (!targetIp || !shareName || !remoteFile) {
    return { status: 'error', error: 'targetIp, shareName, and remoteFile are required' };
  }

  // Prompt user to choose save location
  const filename = remoteFile.split(/[\\/]/).filter(Boolean).pop() || 'download';
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save Downloaded File',
    defaultPath: path.join(app.getPath('downloads'), filename),
  });

  if (canceled || !filePath) return { status: 'cancelled' };

  const ok = await downloadShareFile(
    targetIp,
    shareName,
    remoteFile,
    filePath,
    credentials || null,
    (err) => mainWindow?.webContents.send(IPC_CHANNELS.SHARE_ERROR, err)
  );

  if (ok) {
    return { status: 'downloaded', localPath: filePath };
  }
  return { status: 'error', error: 'Download failed — check share error stream' };
});

// --- Offensive Pentest: Web Directory Fuzzing (4E) ---

ipcMain.handle(IPC_CHANNELS.DIRFUZZ_START, async (event, options) => {
  console.log(`Dir fuzz requested on ${options?.targetUrl}`);

  if (!options || typeof options !== 'object') {
    return { status: 'error', error: 'Invalid options payload' };
  }

  // startDirFuzz is async and streams results; fire and don't await
  startDirFuzz(
    options,
    (hit)      => mainWindow?.webContents.send(IPC_CHANNELS.DIRFUZZ_HIT, hit),
    (progress) => mainWindow?.webContents.send(IPC_CHANNELS.DIRFUZZ_PROGRESS, progress),
    (complete) => mainWindow?.webContents.send(IPC_CHANNELS.DIRFUZZ_COMPLETE, complete),
    (err)      => mainWindow?.webContents.send(IPC_CHANNELS.DIRFUZZ_ERROR, err)
  );

  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.DIRFUZZ_STOP, async () => {
  console.log('Dir fuzz stop requested');
  stopDirFuzz();
  return { status: 'stopped' };
});

// --- Feature 5A: Hardening Monitor ---

ipcMain.handle(IPC_CHANNELS.HARDENING_START_MONITOR, async (_e, { subnet, options }) => {
  console.log(`[hardening] Start monitor requested for ${subnet}`);
  if (typeof subnet !== 'string') return { ok: false, error: 'subnet is required' };
  startHardeningMonitor(subnet, options || {}, mainWindow);
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.HARDENING_STOP_MONITOR, async (_e, { subnet }) => {
  console.log(`[hardening] Stop monitor requested for ${subnet}`);
  stopHardeningMonitor(subnet);
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.HARDENING_SET_BASELINE, async (_e, { subnet, hosts }) => {
  console.log(`[hardening] Set baseline for ${subnet} — ${hosts?.length || 0} hosts`);
  if (!Array.isArray(hosts)) return { ok: false, error: 'hosts must be an array' };
  setHardeningBaseline(subnet, hosts);
  return { ok: true };
});

ipcMain.handle(IPC_CHANNELS.HARDENING_GET_BASELINE, async (_e, { subnet }) => {
  const result = getHardeningBaseline(subnet);
  return result || { hosts: [], setAt: null, subnet };
});

ipcMain.handle(IPC_CHANNELS.HARDENING_GET_SCHEDULES, async () => {
  return getActiveMonitors();
});

// --- Feature 5B: Credential Spray ---

ipcMain.handle(IPC_CHANNELS.CREDSPRAY_START, async (event, options) => {
  console.log(`CredSpray requested`);

  if (!options || typeof options !== 'object') {
    return { status: 'error', error: 'Invalid options payload' };
  }

  // startCredSpray is async but we don't await the whole loop here
  startCredSpray(
    options,
    (hit)      => mainWindow?.webContents.send(IPC_CHANNELS.CREDSPRAY_HIT, hit),
    (progress) => mainWindow?.webContents.send(IPC_CHANNELS.CREDSPRAY_PROGRESS, progress),
    (complete) => mainWindow?.webContents.send(IPC_CHANNELS.CREDSPRAY_COMPLETE, complete),
    (err)      => mainWindow?.webContents.send(IPC_CHANNELS.CREDSPRAY_ERROR, err)
  );

  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.CREDSPRAY_STOP, async () => {
  console.log('CredSpray stop requested');
  stopCredSpray();
  return { status: 'stopped' };
});

// --- Results Management ---

ipcMain.handle(IPC_CHANNELS.SAVE_RESULTS, async (event, results) => {
  console.log('Save requested', results?.length || 0);
  try {
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: 'Save NetSpecter Scan',
      defaultPath: path.join(app.getPath('documents'), 'scan_results.json'),
      filters: [{ name: 'JSON Files', extensions: ['json'] }]
    });

    if (canceled || !filePath) return { status: 'cancelled' };

    fs.writeFileSync(filePath, JSON.stringify(results, null, 2));
    return { status: 'saved', path: filePath };
  } catch (e) {
    console.error('Save failed:', e);
    return { status: 'error', error: e.message };
  }
});

ipcMain.handle(IPC_CHANNELS.LOAD_RESULTS, async (event) => {
  console.log('Load requested');
  try {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      title: 'Load NetSpecter Scan',
      properties: ['openFile'],
      filters: [{ name: 'JSON Files', extensions: ['json'] }]
    });

    if (canceled || filePaths.length === 0) return { status: 'cancelled' };

    const savePath = filePaths[0];
    if (fs.existsSync(savePath)) {
      const data = JSON.parse(fs.readFileSync(savePath, 'utf8'));
      return { status: 'loaded', data, path: savePath };
    }
    
    return { status: 'no_file' };
  } catch (e) {
    console.error('Load failed:', e);
    return { status: 'error', error: e.message };
  }
});

ipcMain.handle(IPC_CHANNELS.CLEAR_RESULTS, async (event) => {
  console.log('Clear requested');
  return { status: 'cleared' };
});

ipcMain.on(IPC_CHANNELS.EXIT_APP, () => {
  app.quit();
});

// --- Target Scope Management ---

ipcMain.handle(IPC_CHANNELS.IMPORT_SCOPE_FILE, async () => {
  try {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      title: 'Import Scope File',
      properties: ['openFile'],
      filters: [
        { name: 'Scope Files', extensions: ['txt', 'csv', 'tsv'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });

    if (canceled || filePaths.length === 0) return { status: 'cancelled' };

    const content = await fs.promises.readFile(filePaths[0], 'utf8');
    const lines = content.split(/[\\r\\n]+/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    const hosts = [];
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const cidrRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/;
    const seen = new Set();

    let processedCount = 0;

    for (const line of lines) {
      // Yield to event loop every 100 items to prevent UI freezes on massive scopes
      if (++processedCount % 100 === 0) {
        await new Promise(setImmediate);
      }

      // Handle CSV/TSV — take first column
      const entry = line.split(/[,\\t]/)[0].trim();
      if (!entry) continue;

      if (cidrRegex.test(entry)) {
        // Expand CIDR range
        const expanded = expandCIDR(entry);
        for (const ip of expanded) {
          if (!seen.has(ip)) {
            seen.add(ip);
            hosts.push({ ip, source: 'imported', hostname: '', mac: '', vendor: '', os: '' });
          }
        }
      } else if (ipRegex.test(entry)) {
        if (!seen.has(entry)) {
          seen.add(entry);
          hosts.push({ ip: entry, source: 'imported', hostname: '', mac: '', vendor: '', os: '' });
        }
      } else {
        // Treat as hostname, attempt DNS lookup
        try {
           const lookupResult = await dnsPromises.lookup(entry, { family: 4 });
           if (lookupResult && lookupResult.address) {
             const resolvedIp = lookupResult.address;
             if (!seen.has(resolvedIp)) {
                seen.add(resolvedIp);
                hosts.push({ ip: resolvedIp, source: 'imported', hostname: entry, mac: '', vendor: '', os: '' });
             }
           }
        } catch (err) {
           console.warn(`Failed to resolve imported hostname ${entry}:`, err.message);
        }
      }
    }

    console.log(`Scope import: parsed ${hosts.length} hosts from ${filePaths[0]}`);
    return { status: 'imported', hosts, path: filePaths[0] };
  } catch (e) {
    console.error('Scope import failed:', e);
    return { status: 'error', error: e.message };
  }
});

ipcMain.handle(IPC_CHANNELS.IMPORT_NMAP_XML, async () => {
  try {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      title: 'Import Nmap XML',
      properties: ['openFile'],
      filters: [
        { name: 'Nmap XML Files', extensions: ['xml'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });

    if (canceled || filePaths.length === 0) return { status: 'cancelled' };

    const hosts = parseNmapXml(filePaths[0]);
    console.log(`Nmap XML import: parsed ${hosts.length} hosts from ${filePaths[0]}`);
    return { status: 'imported', hosts, path: filePaths[0] };
  } catch (e) {
    console.error('Nmap XML import failed:', e);
    return { status: 'error', error: e.message };
  }
});

ipcMain.handle(IPC_CHANNELS.PING_HOST, async (event, ip) => {
  try {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ip || !ipRegex.test(ip)) {
      return { alive: false, time: null, error: 'Invalid IP format' };
    }
    const res = await ping.promise.probe(ip, { timeout: 2 });
    return { alive: res.alive, time: res.time };
  } catch (e) {
    return { alive: false, time: null, error: e.message };
  }
});

ipcMain.handle(IPC_CHANNELS.PROBE_HOST, async (event, ip) => {
  try {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ip || !ipRegex.test(ip)) {
      return { error: 'Invalid IP format' };
    }
    const result = await probeHost(ip);
    return result;
  } catch (e) {
    return { ip, error: e.message, alive: false };
  }
});
