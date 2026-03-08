/**
 * hardeningMonitor.js — Continuous Delta Monitoring (Feature 5A)
 *
 * Runs scheduled re-scans of a target subnet and diffs each snapshot
 * against a persisted baseline to detect:
 *   - New hosts appearing on the network
 *   - Existing hosts disappearing
 *   - Port changes (new open or newly closed ports)
 *   - MAC address or hostname changes
 *
 * Security notes:
 * - Subnet input validated as CIDR (prefix 16-32) before any use
 * - All net.createConnection calls are timeout-bounded
 * - No shell string interpolation — pure Node.js net/ping
 * - Baselines stored in a dedicated electron-store namespace (no overlap with app settings)
 */

import ping from 'ping';
import Store from 'electron-store';
import { Notification } from 'electron';
import { expandCIDR } from '#shared/networkConstants.js';
import { IPC_CHANNELS } from '#shared/ipc.js';
import { enrichHost, getArpTable } from './scanner.js';

// ---- Store ----------------------------------------------------------------

const store = new Store({ name: 'hardening-baselines' });

// ---- State ----------------------------------------------------------------

/**
 * @type {Map<string, {
 *   intervalId: ReturnType<typeof setInterval>|null,
 *   running: boolean,
 *   lastRun: number|null,
 *   nextRun: number|null,
 *   options: object,
 * }>}
 */
const activeMonitors = new Map();

// ---- Validation -----------------------------------------------------------

const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

/**
 * Validate that a string is a safe CIDR notation (prefix 16-32).
 * Throws on invalid input.
 * @param {string} subnet
 * @returns {string} the validated subnet string
 */
export function validateCidr(subnet) {
  if (typeof subnet !== 'string' || !CIDR_RE.test(subnet)) {
    throw new Error(`Invalid CIDR notation: "${subnet}"`);
  }
  const prefix = parseInt(subnet.split('/')[1], 10);
  if (prefix < 20 || prefix > 32) {
    throw new Error(`Prefix /${prefix} out of safe range (20–32)`);
  }
  return subnet;
}

// ---- Lightweight probing --------------------------------------------------

/**
 * Ping a single IP. Returns { alive, time }.
 * @param {string} ip
 * @returns {Promise<{alive: boolean, time: number|null}>}
 */
export async function pingHost(ip) {
  try {
    const res = await ping.promise.probe(ip, { timeout: 1 });
    return {
      alive: res.alive,
      time: res.time !== 'unknown' ? parseFloat(res.time) : null,
    };
  } catch {
    return { alive: false, time: null };
  }
}

/**
 * Ping-sweep a CIDR subnet with bounded concurrency.
 * Returns the list of alive IPs.
 * @param {string} cidr
 * @param {AbortSignal} [signal]
 * @returns {Promise<string[]>}
 */
export async function sweepSubnet(cidr, signal) {
  let ips = expandCIDR(cidr);
  
  const CONCURRENCY = 25;
  const alive = [];

  for (let i = 0; i < ips.length; i += CONCURRENCY) {
    if (signal?.aborted) break;
    const batch = ips.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(ip => pingHost(ip)));
    for (let j = 0; j < batch.length; j++) {
      if (results[j].alive) alive.push(batch[j]);
    }
  }

  return alive;
}

// ---- Diffing --------------------------------------------------------------

/**
 * Compute the structural delta between two host snapshots.
 * Returns a delta object, or null if nothing changed.
 *
 * @param {Array<{ip,mac,hostname,ports}>} baseline
 * @param {Array<{ip,mac,hostname,ports}>} current
 * @returns {object|null}
 */
export function diffSnapshots(baseline, current) {
  if (!Array.isArray(baseline)) baseline = [];
  if (!Array.isArray(current)) current = [];

  const baseMap = new Map(baseline.map(h => [h.ip, h]));
  const currMap = new Map(current.map(h => [h.ip, h]));

  const newHosts = [];
  const removedHosts = [];
  const changedHosts = [];

  // New hosts: in current but not baseline
  for (const [ip, host] of currMap) {
    if (!baseMap.has(ip)) newHosts.push({ ...host });
  }

  // Removed hosts: in baseline but not current
  for (const [ip, host] of baseMap) {
    if (!currMap.has(ip)) {
      removedHosts.push({ ip: host.ip, mac: host.mac || '', hostname: host.hostname || '' });
    }
  }

  // Changed hosts: same IP in both — compare ports, MAC, hostname
  for (const [ip, baseHost] of baseMap) {
    const currHost = currMap.get(ip);
    if (!currHost) continue;

    const basePorts = new Set(baseHost.ports || []);
    const currPorts = new Set(currHost.ports || []);

    const newPorts    = [...currPorts].filter(p => !basePorts.has(p));
    const closedPorts = [...basePorts].filter(p => !currPorts.has(p));

    const macChanged      = !!(baseHost.mac && currHost.mac && baseHost.mac !== currHost.mac);
    const hostnameChanged = !!(baseHost.hostname && currHost.hostname && baseHost.hostname !== currHost.hostname);

    if (newPorts.length || closedPorts.length || macChanged || hostnameChanged) {
      changedHosts.push({
        ip,
        newPorts,
        closedPorts,
        macChanged,
        hostnameChanged,
        prevHostname: hostnameChanged ? baseHost.hostname : undefined,
        currHostname: hostnameChanged ? currHost.hostname : undefined,
        prevMac: macChanged ? baseHost.mac : undefined,
        currMac: macChanged ? currHost.mac : undefined,
        hostname: currHost.hostname || '',
        mac: currHost.mac || '',
        ports: currHost.ports || [],
      });
    }
  }

  const hasChanges = newHosts.length > 0 || removedHosts.length > 0 || changedHosts.length > 0;
  if (!hasChanges) return null;

  // Derive severity from the most impactful change type
  let severity = 'info';
  if (newHosts.length > 0 || changedHosts.some(h => h.newPorts.length > 0)) {
    severity = 'critical';
  } else if (removedHosts.length > 0 || changedHosts.some(h => h.closedPorts.length > 0 || h.macChanged || h.hostnameChanged)) {
    severity = 'warning';
  }

  return {
    subnet: null, // filled by caller
    timestamp: Date.now(),
    newHosts,
    removedHosts,
    changedHosts,
    severity,
  };
}

// ---- OS Notification -------------------------------------------------------

function buildAlertSummary(delta) {
  const parts = [];
  if (delta.newHosts.length > 0) {
    parts.push(`${delta.newHosts.length} new host${delta.newHosts.length > 1 ? 's' : ''}`);
  }
  if (delta.removedHosts.length > 0) {
    parts.push(`${delta.removedHosts.length} host${delta.removedHosts.length > 1 ? 's' : ''} gone`);
  }
  const withNewPorts = (delta.changedHosts || []).filter(h => h.newPorts.length > 0).length;
  if (withNewPorts > 0) {
    parts.push(`${withNewPorts} host${withNewPorts > 1 ? 's' : ''} with new open port${withNewPorts > 1 ? 's' : ''}`);
  }
  return parts.join(' · ') || 'Network change detected';
}

function sendSystemNotification(delta) {
  if (!Notification.isSupported()) return;
  try {
    new Notification({
      title: `NetSpecter Alert — ${delta.subnet}`,
      body: buildAlertSummary(delta),
      urgency: delta.severity === 'critical' ? 'critical' : 'normal',
    }).show();
  } catch {
    // OS notification API unavailable — silently ignore
  }
}

// ---- Monitor cycle --------------------------------------------------------

/**
 * Execute one complete monitor cycle for the given subnet.
 * Sweeps the network, scans ports on live hosts, diffs against baseline,
 * and emits IPC events to the renderer.
 *
 * @param {string} subnet
 * @param {object} options
 * @param {Electron.BrowserWindow} mainWindow
 */
async function runMonitorCycle(subnet, options, mainWindow) {
  const monitor = activeMonitors.get(subnet);
  if (!monitor || monitor.running) return; // prevent overlapping cycles

  monitor.running = true;
  monitor.lastRun = Date.now();

  const send = (channel, payload) => mainWindow?.webContents.send(channel, payload);

  try {
    // Notify renderer: scanning in progress
    send(IPC_CHANNELS.HARDENING_MONITOR_STATUS, {
      subnet,
      state: 'scanning',
      lastRun: monitor.lastRun,
      nextRun: monitor.nextRun,
    });

    // Step 1: lightweight ping sweep
    const controller = new AbortController();
    const aliveIps = await sweepSubnet(subnet, controller.signal);

    // Step 2: retrieve baseline; fetch ARP table once for the whole cycle
    const baselineEntry = getBaseline(subnet);
    const baseline = baselineEntry?.hosts || [];
    const baseMap  = new Map(baseline.map(h => [h.ip, h]));
    const deepScan = options?.deepScan !== false;

    // Single ARP fetch shared across all host enrichments this cycle
    const arpTable = await getArpTable().catch(() => ({}));

    const currentHosts = await Promise.all(
      aliveIps.map(async (ip) => {
        const isKnown = baseMap.has(ip);

        // Always enrich for fresh hostname / MAC / vendor / OS.
        // For known hosts with deepScan disabled, reuse baseline ports to
        // avoid a full TCP scan on every cycle.
        const enriched = await enrichHost(ip, {
          arpTable,
          skipPorts: !deepScan && isKnown,
        });

        const ports = (!deepScan && isKnown)
          ? (baseMap.get(ip)?.ports || enriched.ports || [])
          : (enriched.ports || []);

        const hostRecord = {
          ip,
          mac:             enriched.mac      || baseMap.get(ip)?.mac      || '',
          hostname:        enriched.hostname  || baseMap.get(ip)?.hostname  || '',
          vendor:          enriched.vendor    || baseMap.get(ip)?.vendor    || '',
          os:              enriched.os        || baseMap.get(ip)?.os        || '',
          ports,
          source:          'monitor',
          monitorStatus:   'online',
          monitorLastSeen: Date.now(),
          firstSeen:       baseMap.get(ip)?.firstSeen || Date.now(),
          lastSeen:        Date.now(),
        };

        // Stream this host to the renderer as soon as its scan is done —
        // mirrors the HOST_FOUND pattern so the grid updates incrementally.
        send(IPC_CHANNELS.HARDENING_HOST_UPDATE, hostRecord);

        return hostRecord;
      })
    );

    // Step 3: diff against baseline
    const delta = diffSnapshots(baseline, currentHosts);

    if (delta) {
      delta.subnet = subnet;

      // Mark removed hosts offline and stream each one to the renderer
      for (const removed of delta.removedHosts) {
        send(IPC_CHANNELS.HARDENING_HOST_UPDATE, {
          ip:              removed.ip,
          mac:             removed.mac  || '',
          hostname:        removed.hostname || '',
          ports:           baseMap.get(removed.ip)?.ports || [],
          source:          'monitor',
          monitorStatus:   'offline',
          monitorLastSeen: Date.now(),
        });
      }

      // Tag changed hosts with their specific alert data
      for (const changed of delta.changedHosts) {
        send(IPC_CHANNELS.HARDENING_HOST_UPDATE, {
          ip:              changed.ip,
          mac:             changed.mac  || '',
          hostname:        changed.hostname || '',
          ports:           changed.ports || [],
          source:          'monitor',
          monitorStatus:   'changed',
          monitorLastSeen: Date.now(),
          monitorAlerts:   [delta],
        });
      }

      send(IPC_CHANNELS.HARDENING_DELTA_ALERT, delta);
      send(IPC_CHANNELS.HARDENING_DELTA_REPORT, {
        subnet,
        delta,
        currentHosts,
        baseline,
      });

      sendSystemNotification(delta);
    }

    // Update next-run timestamp
    const intervalMs = options?.intervalMs || 15 * 60 * 1000;
    monitor.nextRun = Date.now() + intervalMs;

    // Notify renderer: cycle complete
    send(IPC_CHANNELS.HARDENING_MONITOR_STATUS, {
      subnet,
      state: 'idle',
      lastRun: monitor.lastRun,
      nextRun: monitor.nextRun,
      hostCount: currentHosts.length,
      deltaCount: delta
        ? delta.newHosts.length + delta.removedHosts.length + delta.changedHosts.length
        : 0,
    });

  } catch (err) {
    console.error(`[hardeningMonitor] Cycle error for ${subnet}:`, err.message);
    send(IPC_CHANNELS.HARDENING_MONITOR_STATUS, {
      subnet,
      state: 'error',
      error: err.message,
    });
  } finally {
    if (activeMonitors.has(subnet)) {
      activeMonitors.get(subnet).running = false;
    }
  }
}

// ---- Public API -----------------------------------------------------------

/**
 * Start continuous monitoring for a subnet.
 * Runs an immediate probe cycle, then schedules recurring cycles.
 *
 * @param {string} subnet   CIDR notation, e.g. "192.168.1.0/24"
 * @param {object} options
 * @param {number}  [options.intervalMs=900000]  Milliseconds between cycles (min 60 000)
 * @param {boolean} [options.deepScan=true]      Port-scan hosts on every cycle
 * @param {Electron.BrowserWindow} mainWindow
 */
export function startMonitor(subnet, options, mainWindow) {
  try {
    validateCidr(subnet);
  } catch (err) {
    mainWindow?.webContents.send(IPC_CHANNELS.HARDENING_MONITOR_STATUS, {
      subnet,
      state: 'error',
      error: err.message,
    });
    return;
  }

  // Stop any existing monitor for this subnet before starting a new one
  if (activeMonitors.has(subnet)) stopMonitor(subnet);

  const intervalMs = Math.max(
    typeof options?.intervalMs === 'number' ? options.intervalMs : 15 * 60 * 1000,
    60 * 1000 // enforce minimum 1-minute interval
  );

  // Normalize options for storage/display
  const effectiveOptions = { ...options, intervalMs };

  const entry = {
    intervalId: null,
    running: false,
    lastRun: null,
    nextRun: Date.now() + intervalMs,
    options: effectiveOptions,
  };
  activeMonitors.set(subnet, entry);

  mainWindow?.webContents.send(IPC_CHANNELS.HARDENING_MONITOR_STATUS, {
    subnet,
    state: 'started',
    lastRun: null,
    nextRun: entry.nextRun,
  });

  // Run immediately, then on each interval
  runMonitorCycle(subnet, effectiveOptions, mainWindow);

  entry.intervalId = setInterval(() => {
    runMonitorCycle(subnet, effectiveOptions, mainWindow);
    if (activeMonitors.has(subnet)) {
      activeMonitors.get(subnet).nextRun = Date.now() + intervalMs;
    }
  }, intervalMs);

  console.log(`[hardeningMonitor] Started monitoring ${subnet} every ${intervalMs / 1000}s`);
}

/**
 * Stop monitoring for a specific subnet.
 * @param {string} subnet
 */
export function stopMonitor(subnet) {
  const entry = activeMonitors.get(subnet);
  if (entry) {
    if (entry.intervalId) clearInterval(entry.intervalId);
    activeMonitors.delete(subnet);
    console.log(`[hardeningMonitor] Stopped monitoring ${subnet}`);
  }
}

/**
 * Stop all active monitors. Called on app quit.
 */
export function stopAllMonitors() {
  for (const subnet of [...activeMonitors.keys()]) {
    stopMonitor(subnet);
  }
}

/**
 * Persist a host array as the named baseline for a subnet.
 * @param {string} subnet
 * @param {Array}  hosts
 */
export function setBaseline(subnet, hosts) {
  if (!Array.isArray(hosts)) return;
  const key = `baseline.${subnet.replace(/[^a-z0-9]/gi, '_')}`;
  store.set(key, { hosts, setAt: Date.now(), subnet });
  console.log(`[hardeningMonitor] Baseline saved for ${subnet}: ${hosts.length} hosts`);
}

/**
 * Retrieve the stored baseline for a subnet.
 * @param {string} subnet
 * @returns {Array|null}
 */
export function getBaseline(subnet) {
  const key = `baseline.${subnet.replace(/[^a-z0-9]/gi, '_')}`;
  const entry = store.get(key);
  if (!entry) return null;
  return { hosts: entry.hosts || [], setAt: entry.setAt, subnet: entry.subnet };
}

/**
 * Return all active monitor states as a plain serialisable object.
 * @returns {object}
 */
export function getActiveMonitors() {
  const result = {};
  for (const [subnet, entry] of activeMonitors.entries()) {
    result[subnet] = {
      running:  entry.running,
      lastRun:  entry.lastRun,
      nextRun:  entry.nextRun,
      options:  entry.options,
    };
  }
  return result;
}

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.HARDENING_START_MONITOR, async (_e, { subnet, options }) => {
    console.log(`[hardening] Start monitor requested for ${subnet}`);
    if (typeof subnet !== 'string') return { ok: false, error: 'subnet is required' };
    startMonitor(subnet, options || {}, getWindow());
    return { ok: true };
  });

  ipcMain.handle(IPC_CHANNELS.HARDENING_STOP_MONITOR, async (_e, { subnet }) => {
    console.log(`[hardening] Stop monitor requested for ${subnet}`);
    stopMonitor(subnet);
    return { ok: true };
  });

  ipcMain.handle(IPC_CHANNELS.HARDENING_SET_BASELINE, async (_e, { subnet, hosts }) => {
    console.log(`[hardening] Set baseline for ${subnet} — ${hosts?.length || 0} hosts`);
    if (!Array.isArray(hosts)) return { ok: false, error: 'hosts must be an array' };
    setBaseline(subnet, hosts);
    return { ok: true };
  });

  ipcMain.handle(IPC_CHANNELS.HARDENING_GET_BASELINE, async (_e, { subnet }) => {
    const result = getBaseline(subnet);
    return result || { hosts: [], setAt: null, subnet };
  });

  ipcMain.handle(IPC_CHANNELS.HARDENING_GET_SCHEDULES, async () => {
    return getActiveMonitors();
  });
}
