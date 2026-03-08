import { IPC_CHANNELS } from '#shared/ipc.js';
import { startTsharkCapture, stopTsharkCapture } from '../tsharkScanner.js';
import { startDhcpDetection, stopDhcpDetection } from '../rogueDhcpDetector.js';
import { startCredentialSniffing, stopCredentialSniffing } from '../credentialSniffer.js';
import { startDnsHarvesting, stopDnsHarvesting } from '../dnsHarvester.js';
import { startArpDetection, stopArpDetection } from '../arpSpoofDetector.js';
import { exportPcap } from '../pcapExporter.js';
import { stopAll as stopAllPassive } from '../passiveCapture.js';
import { startLiveCapture, stopLiveCapture, analyzePcapFile } from '../pcapAnalyzer.js';
import { startRogueDnsDetection, stopRogueDnsDetection } from '../rogueDnsDetector.js';

export function registerIpcHandlers(ipcMain, getWindow) {
  // ---- Tshark (VLAN Discovery) ----

  ipcMain.handle(IPC_CHANNELS.START_TSHARK, async (_event, interfaceId) => {
    console.log(`Starting Tshark on interface: ${interfaceId}`);

    startTsharkCapture(interfaceId,
      (vlanData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.TSHARK_VLAN_FOUND, vlanData);
      },
      (errorData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.TSHARK_ERROR, errorData);
      },
      (completeData) => {
        getWindow()?.webContents.send(IPC_CHANNELS.TSHARK_COMPLETE, completeData);
      }
    );
    return { status: 'started' };
  });

  ipcMain.handle(IPC_CHANNELS.STOP_TSHARK, async () => {
    const stopped = stopTsharkCapture();
    return { status: stopped ? 'stopped' : 'not_running' };
  });

  // ---- Passive Network Intelligence ----

  function wirePcapLiveCapture(interfaceId, hostIp, options) {
    startLiveCapture(
      interfaceId,
      hostIp ?? options?.host,
      options,
      (summary) => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_PACKET_SUMMARY, summary),
      (stats)   => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_STATS_UPDATE, stats),
      (err)     => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_CAPTURE_ERROR, err),
      (msg)     => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_CAPTURE_COMPLETE, msg)
    );
  }

  const passiveStartHandlers = {
    dhcp: (iface, options, onError, onComplete) =>
      startDhcpDetection(iface,
        (alert) => getWindow()?.webContents.send(IPC_CHANNELS.PASSIVE_DHCP_ALERT, alert),
        onError, onComplete),
    creds: (iface, options, onError, onComplete) =>
      startCredentialSniffing(iface,
        (cred) => getWindow()?.webContents.send(IPC_CHANNELS.PASSIVE_CRED_FOUND, cred),
        onError, onComplete),
    dns: (iface, options, onError, onComplete) =>
      startDnsHarvesting(iface,
        (host) => getWindow()?.webContents.send(IPC_CHANNELS.PASSIVE_DNS_HOST, host),
        onError, onComplete),
    arp: (iface, options, onError, onComplete) =>
      startArpDetection(iface,
        (alert) => getWindow()?.webContents.send(IPC_CHANNELS.PASSIVE_ARP_ALERT, alert),
        onError, onComplete),
    'rogue-dns': (iface, options, onError, onComplete) =>
      startRogueDnsDetection(iface,
        (alert) => getWindow()?.webContents.send(IPC_CHANNELS.PASSIVE_ROGUE_DNS_ALERT, alert),
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

  ipcMain.handle(IPC_CHANNELS.START_PASSIVE_CAPTURE, async (_event, { moduleId, interfaceId, options }) => {
    console.log(`Starting passive capture module: ${moduleId} on ${interfaceId}`);

    const channelMap = {
      dhcp:        IPC_CHANNELS.PASSIVE_DHCP_ERROR,
      creds:       IPC_CHANNELS.PASSIVE_CRED_ERROR,
      dns:         IPC_CHANNELS.PASSIVE_DNS_ERROR,
      arp:         IPC_CHANNELS.PASSIVE_ARP_ERROR,
      'rogue-dns': IPC_CHANNELS.PASSIVE_ROGUE_DNS_ERROR,
      pcap:        IPC_CHANNELS.PCAP_CAPTURE_ERROR,
    };

    const onError = (errorMsg) => {
      const channel = channelMap[moduleId];
      const win = getWindow();
      if (win && channel) {
        win.webContents.send(channel, errorMsg);
      }
    };

    const onComplete = (data) => {
      getWindow()?.webContents.send(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE, data);
    };

    const startHandler = passiveStartHandlers[moduleId];
    const success = startHandler ? !!startHandler(interfaceId, options, onError, onComplete) : false;

    return { status: success ? 'started' : 'failed' };
  });

  ipcMain.handle(IPC_CHANNELS.STOP_PASSIVE_CAPTURE, async (_event, moduleId) => {
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

  ipcMain.handle(IPC_CHANNELS.EXPORT_PCAP, async (_event, { interfaceId, hostIp, duration }) => {
    console.log('Starting PCAP export');
    return await exportPcap(
      getWindow(),
      interfaceId,
      hostIp,
      duration,
      (data) => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_EXPORT_COMPLETE, data),
      (err)  => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_EXPORT_ERROR, err)
    );
  });

  // ---- PCAP Live Capture & Analysis ----

  ipcMain.handle(IPC_CHANNELS.START_PCAP_CAPTURE, async (_event, { interfaceId, hostIp, options }) => {
    console.log(`Starting PCAP live capture on ${interfaceId} for ${hostIp || 'all'}`);
    wirePcapLiveCapture(interfaceId, hostIp, options);
    return { status: 'started' };
  });

  ipcMain.handle(IPC_CHANNELS.STOP_PCAP_CAPTURE, async () => {
    console.log('Stopping PCAP live capture');
    stopLiveCapture();
    return { status: 'stopped' };
  });

  ipcMain.handle(IPC_CHANNELS.ANALYZE_PCAP_FILE, async (_event, filePath) => {
    console.log(`Analyzing PCAP file: ${filePath}`);
    analyzePcapFile(filePath,
      (summary) => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_PACKET_SUMMARY, summary),
      (stats)   => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_STATS_UPDATE, stats),
      (err)     => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_CAPTURE_ERROR, err),
      (msg)     => getWindow()?.webContents.send(IPC_CHANNELS.PCAP_CAPTURE_COMPLETE, msg)
    );
    return { status: 'started' };
  });
}
