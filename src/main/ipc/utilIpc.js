import { app, shell } from 'electron';
import { spawn, exec } from 'child_process';
import { IPC_CHANNELS } from '#shared/ipc.js';
import { ipRegex } from '#shared/networkConstants.js';

export function registerIpcHandlers(ipcMain, _getWindow) {
  ipcMain.handle(IPC_CHANNELS.OPEN_EXTERNAL_ACTION, async (_event, { type, ip, port, username }) => {
    console.log(`External action requested: ${type} to ${ip}:${port}`);

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
      if (type === 'https') {
        // Only allow https:// for shell.openExternal — http is intentionally excluded
        await shell.openExternal(`https://${ip}${port ? ':' + port : ''}`);
      } else if (type === 'http') {
        await shell.openExternal(`http://${ip}${port ? ':' + port : ''}`);
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

  // Open an http/https URL in the system default browser.
  // Separate from OPEN_EXTERNAL_ACTION which is IP-based for network tools.
  ipcMain.handle(IPC_CHANNELS.OPEN_URL, async (_event, { url } = {}) => {
    if (!url || typeof url !== 'string') {
      return { success: false, error: 'url is required' };
    }
    let parsed;
    try { parsed = new URL(url); } catch {
      return { success: false, error: 'Invalid URL' };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { success: false, error: 'Only http and https URLs are allowed' };
    }
    try {
      await shell.openExternal(url);
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.on(IPC_CHANNELS.EXIT_APP, () => {
    app.quit();
  });
}
