import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import net from 'net';
import pkg from 'electron-updater';
const { autoUpdater } = pkg;
import path from 'path';
import { fileURLToPath } from 'url';

// --- Linux Root/Sandbox Detection ---
// Chromium refuses to start with sandboxing when running as root (UID 0).
// Network scanning tools are often launched with sudo on Linux,
// so we defensively disable the sandbox in that case.
if (process.platform === 'linux' && process.getuid && process.getuid() === 0) {
  app.commandLine.appendSwitch('no-sandbox');
  console.warn('[NetSpecter] Running as root — Chromium sandbox disabled via --no-sandbox.');
}

import { createMainWindow } from './windowManager.js';
import { registerSnmpHandlers } from './snmpIpc.js';
import { registerIpcHandlers as registerBruteForceHandlers, cleanupBruteForce } from './bruteForce.js';
import { registerIpcHandlers as registerMsfHandlers, cleanupMsf } from './metasploitRpc.js';
import { registerIpcHandlers as registerRevShellHandlers, stopListener as stopRevShell } from './revShellListener.js';
import { registerIpcHandlers as registerShareHandlers, cleanupShares } from './shareEnumerator.js';
import { registerIpcHandlers as registerDirFuzzHandlers, cleanupDirFuzz } from './dirFuzzer.js';
import { registerIpcHandlers as registerHardeningHandlers, stopAllMonitors } from './hardeningMonitor.js';
import { registerIpcHandlers as registerCredSprayHandlers, cleanupCredSpray } from './credSpray.js';
import { registerIpcHandlers as registerCloudEnumHandlers, cleanupCloudEnum } from './cloudEnum.js';
import { registerIpcHandlers as registerWebappHandlers, cleanupWebapp } from './webapp/ipc/webappIpc.js';
import { registerIpcHandlers as registerScanHandlers } from './ipc/scanIpc.js';
import { registerIpcHandlers as registerSettingsHandlers } from './ipc/settingsIpc.js';
import { registerIpcHandlers as registerFileHandlers } from './ipc/fileIpc.js';
import { registerIpcHandlers as registerUtilHandlers } from './ipc/utilIpc.js';
import { registerIpcHandlers as registerPassiveHandlers } from './ipc/passiveIpc.js';

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

  const getWindow = () => mainWindow;

  // Register all IPC handler groups
  registerSnmpHandlers(ipcMain, mainWindow);
  registerScanHandlers(ipcMain, getWindow);
  registerSettingsHandlers(ipcMain, getWindow);
  registerFileHandlers(ipcMain, getWindow);
  registerUtilHandlers(ipcMain, getWindow);
  registerPassiveHandlers(ipcMain, getWindow);
  registerBruteForceHandlers(ipcMain, getWindow);
  registerRevShellHandlers(ipcMain, getWindow);
  registerMsfHandlers(ipcMain, getWindow);
  registerShareHandlers(ipcMain, getWindow);
  registerDirFuzzHandlers(ipcMain, getWindow);
  registerHardeningHandlers(ipcMain, getWindow);
  registerCredSprayHandlers(ipcMain, getWindow);
  registerCloudEnumHandlers(ipcMain, getWindow);
  registerWebappHandlers(ipcMain, getWindow);
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
}).catch((error) => {
  console.error('Failed to initialize application in app.whenReady():', error);
});

app.on('window-all-closed', function () {
  cleanupBruteForce();
  cleanupMsf();
  stopRevShell();
  cleanupShares();
  cleanupDirFuzz();
  stopAllMonitors();
  cleanupCredSpray();
  cleanupCloudEnum();
  cleanupWebapp();
  if (process.platform !== 'darwin') app.quit();
});
