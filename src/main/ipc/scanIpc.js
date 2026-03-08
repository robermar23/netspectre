import { IPC_CHANNELS } from '#shared/ipc.js';
import { isValidIpOrHostname } from '#shared/validate.js';
import { startNetworkScan, stopNetworkScan, getNetworkInterfaces, probeHost } from '../scanner.js';
import { runDeepScan, cancelDeepScan } from '../deepScanner.js';
import { checkNmapInstalled, runNmapScan, cancelNmapScan, runNcat, getNmapScripts } from '../nmapScanner.js';
import ping from 'ping';

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.GET_INTERFACES, async () => {
    return getNetworkInterfaces();
  });

  ipcMain.handle(IPC_CHANNELS.SCAN_NETWORK, async (event, subnet) => {
    console.log(`Scan requested on subnet: ${subnet}`);

    startNetworkScan(
      subnet,
      (hostData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.HOST_FOUND, hostData);
      },
      (completeMsg) => {
        getWindow()?.webContents.send(IPC_CHANNELS.SCAN_COMPLETE, completeMsg);
      }
    );

    return { status: 'scanning' };
  });

  ipcMain.handle(IPC_CHANNELS.RUN_DEEP_SCAN, async (event, ip) => {
    console.log(`Deep scan requested for ${ip}`);

    // Run asynchronously without blocking
    runDeepScan(ip, (portData) => {
      getWindow()?.webContents.send(IPC_CHANNELS.DEEP_SCAN_RESULT, { ip, ...portData });
    }, (progressData) => {
      getWindow()?.webContents.send(IPC_CHANNELS.DEEP_SCAN_PROGRESS, progressData);
    }).then(() => {
      getWindow()?.webContents.send(IPC_CHANNELS.DEEP_SCAN_COMPLETE, { ip });
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

  ipcMain.handle(IPC_CHANNELS.STOP_SCAN, async () => {
    console.log('Stop requested');
    stopNetworkScan();
    return { status: 'stopped' };
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

  ipcMain.handle(IPC_CHANNELS.RUN_NMAP_SCAN, async (event, payload) => {
    const { type, target } = payload;
    const targetStr = typeof target === 'string' ? target : target?.ip;
    console.log(`Nmap scan requested: ${type} on ${targetStr}`);

    if (!isValidIpOrHostname(targetStr)) {
      return { status: 'error', error: 'Invalid IP address or hostname' };
    }

    runNmapScan(type, target,
      (chunkData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.NMAP_SCAN_RESULT, { target, type, ...chunkData });
      },
      (completeData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.NMAP_SCAN_COMPLETE, { type, ...completeData });
      },
      (errorData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.NMAP_SCAN_ERROR, { target, type, ...errorData });
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
        getWindow()?.webContents.send(IPC_CHANNELS.NMAP_SCAN_RESULT, { target: payloadObj.target, type: 'ncat', ...chunkData });
      },
      (completeData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.NMAP_SCAN_COMPLETE, { type: 'ncat', target: payloadObj.target, ...completeData });
      },
      (errorData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.NMAP_SCAN_ERROR, { target: payloadObj.target, type: 'ncat', ...errorData });
      }
    );
    return { status: 'started' };
  });
}
