import { app, dialog } from 'electron';
import path from 'path';
import fs from 'fs';
import dns from 'dns';
const dnsPromises = dns.promises;

import { IPC_CHANNELS } from '#shared/ipc.js';
import { expandCIDR } from '#shared/networkConstants.js';
import { parseNmapXml } from '../nmapXmlParser.js';

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.BROWSE_FILE, async (_event, options) => {
    const opts = options || {};
    const { canceled, filePaths } = await dialog.showOpenDialog(getWindow(), {
      title: opts.title || 'Select File',
      properties: ['openFile'],
      filters: opts.filters || [{ name: 'All Files', extensions: ['*'] }],
      defaultPath: opts.defaultPath || undefined,
    });
    if (canceled || filePaths.length === 0) return { status: 'cancelled' };
    return { status: 'selected', path: filePaths[0] };
  });

  ipcMain.handle(IPC_CHANNELS.SAVE_RESULTS, async (_event, results) => {
    console.log('Save requested', results?.length || 0);
    try {
      const { canceled, filePath } = await dialog.showSaveDialog(getWindow(), {
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

  ipcMain.handle(IPC_CHANNELS.LOAD_RESULTS, async () => {
    console.log('Load requested');
    try {
      const { canceled, filePaths } = await dialog.showOpenDialog(getWindow(), {
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

  ipcMain.handle(IPC_CHANNELS.CLEAR_RESULTS, async () => {
    console.log('Clear requested');
    return { status: 'cleared' };
  });

  ipcMain.handle(IPC_CHANNELS.IMPORT_SCOPE_FILE, async () => {
    try {
      const { canceled, filePaths } = await dialog.showOpenDialog(getWindow(), {
        title: 'Import Scope File',
        properties: ['openFile'],
        filters: [
          { name: 'Scope Files', extensions: ['txt', 'csv', 'tsv'] },
          { name: 'All Files', extensions: ['*'] }
        ]
      });

      if (canceled || filePaths.length === 0) return { status: 'cancelled' };

      const content = await fs.promises.readFile(filePaths[0], 'utf8');
      const lines = content.split(/[\r\n]+/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
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
        const entry = line.split(/[,\t]/)[0].trim();
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
      const { canceled, filePaths } = await dialog.showOpenDialog(getWindow(), {
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
}
