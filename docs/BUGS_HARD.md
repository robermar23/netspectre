# Hardening Monitor — Bug Fix Implementation Plan

> Comprehensive plan to resolve ALL unresolved bugs from [BUGS.md](file:///e:/AntiGravityCode/NetworkDetection/docs/BUGS.md) related to the Hardening Monitor feature (lines 36–45), plus two additional bugs uncovered during analysis.

---

## Bug Inventory

| Bug ID | BUGS.md Line | Summary | Severity | Root Cause |
|--------|-------------|---------|----------|------------|
| HM-01 | 39 | Investigate button does nothing | 🔴 Critical | `_openDetailsPanel(ip)` passes an IP **string**, but `openDetailsPanel()` expects a **host object** |
| HM-02 | 37 | Cannot add individual discovered host to monitor from host details | 🟡 Medium | No "Add to Monitor" button in `hostDetails.js::buildHostMonitorActions()` |
| HM-03 | 38 | Cannot add all discovered hosts from monitor panel | 🟡 Medium | No "Import Discovered Hosts" button exists in the hardening panel |
| HM-04 | 40 | Investigate button should show host details panel | 🔴 Critical | Same root cause as HM-01 |
| HM-05 | 41 | Host details not always showing monitor status after baseline set | 🟡 Medium | `monitorStatus` only set during HARDENING_HOST_UPDATE IPC events; not applied when baseline is set against already-discovered hosts |
| SMB-01 | 36 | SMB/NFS share browse missing from host details for share-related ports | 🟡 Medium | NFS deferred to future feature; SMB quick-action already exists for 139/445 but may need expansion |
| CRED-01 | 42–45 | Capture creds shows `pop.request.org` tshark field error | 🔴 Critical | **`pop.request.arg` is NOT a valid tshark 4.6.4 field.** Valid POP3 fields: `pop.request`, `pop.request.data`, `pop.request.command`. The `-e pop.request.arg` extraction argument causes tshark to exit with code 1 |

---

## Root Cause Analysis

### HM-01 / HM-04: Investigate Button Does Nothing

**File:** [hardeningMonitor.js](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/modules/hardeningMonitor.js#L264-L267)

```javascript
// Line 264–266: passes an IP string
actionDiv.querySelector('.btn-investigate')?.addEventListener('click', (e) => {
    const ip = e.currentTarget.dataset.ip;
    if (ip && typeof _openDetailsPanel === 'function') _openDetailsPanel(ip);
});
```

But `openDetailsPanel()` in [hostDetails.js:222](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/modules/hostDetails.js#L222) expects a full host object with `{ ip, mac, hostname, ports, ... }`. Passing a raw IP string causes `host.ip` to be `undefined` and the panel to break silently.

**Fix:** Look up the host object from `state.hosts` using the IP, or construct a minimal host stub if the host hasn't been added to scope yet.

---

### HM-02: Add Individual Host to Monitor from Host Details

**File:** [hostDetails.js](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/modules/hostDetails.js#L61-L112)

The `buildHostMonitorActions()` function provides "Open Monitor Panel" and "Monitor {subnet}" buttons, but there is no button to add a **single host** to the hardening monitor baseline directly from its details.

**Fix:** Add a "➕ Add to Monitor" button that:
1. Derives the subnet CIDR from the host's IP
2. Fetches the existing baseline via `api.hardeningMonitor.getBaseline(subnet)`
3. Appends the current host if not already present
4. Saves back via `api.hardeningMonitor.setBaseline(subnet, updatedHosts)`

---

### HM-03: Add All Discovered Hosts from Monitor Panel

**File:** [hardeningMonitor.js](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/modules/hardeningMonitor.js#L419-L437)

No explicit "Import Discovered Hosts" button exists. The "Set Baseline" button uses `state.hosts` as a fallback but doesn't clearly communicate this to the user.

**Fix:** Add a new `btn-hardening-add-all` button in the hardening panel HTML, placed inline next to the existing "Set Baseline" button (row 2, line 1140 of index.html). This follows the existing flex layout pattern with compact sizing.

---

### HM-05: Host Details Not Showing Monitor Status After Baseline Set

After setting a baseline, hosts whose IPs match are not retroactively updated with `monitorStatus` in `state.hosts[]`. The `monitorStatus` field is only populated via `HARDENING_HOST_UPDATE` IPC events during active cycles.

**Fix:** After saving a baseline (`btnSetBaseline` and `btnPromote` handlers), iterate `state.hosts[]` and set `monitorStatus = 'monitored'` for matching hosts, then call `_debouncedRenderAllHosts()`.

---

### CRED-01: Tshark `pop.request.arg` Field Error

**File:** [credentialSniffer.js](file:///e:/AntiGravityCode/NetworkDetection/src/main/credentialSniffer.js#L17-L28)

Verified with `tshark -G fields | Select-String "pop\.request"` on tshark 4.6.4:

| Field | Status |
|-------|--------|
| `pop.request` | ✅ Valid |
| `pop.request.data` | ✅ Valid |
| `pop.request.command` | ✅ Valid |
| `pop.request.arg` | ❌ **NOT VALID** |

The `-e pop.request.arg` extraction argument causes tshark to exit immediately with code 1. The user's error message `pop.request.org` was likely a transcription of `pop.request.arg`.

**Fix:** Replace `pop.request.arg` with `pop.request.data` (which contains the argument portion of POP3 requests). Update the parsing logic in `onLineParsed` accordingly.

---

### SMB-01: Share Browse for SMB/NFS Ports

NFS support is **deferred** to a future feature addition per user direction. The existing SMB quick-action already handles ports 139/445. No code changes needed for this item at this time.

---

## Proposed Changes

### Component 1: Renderer — Hardening Monitor Module

#### [MODIFY] [hardeningMonitor.js](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/modules/hardeningMonitor.js)

**Change 1: Fix investigate button (HM-01/HM-04) — Line 264–267**

```diff
   actionDiv.querySelector('.btn-investigate')?.addEventListener('click', (e) => {
     const ip = e.currentTarget.dataset.ip;
-    if (ip && typeof _openDetailsPanel === 'function') _openDetailsPanel(ip);
+    if (ip && typeof _openDetailsPanel === 'function') {
+      // Resolve full host object from state; fall back to a minimal stub
+      const host = state.hosts.find(h => h.ip === ip) || {
+        ip, mac: '', hostname: '', vendor: '', os: '',
+        ports: [], source: 'monitor', monitorStatus: 'online',
+      };
+      _openDetailsPanel(host);
+    }
   });
```

**Change 2: Add "Import Discovered Hosts" button wiring (HM-03)**

Add element reference and event handler in `init()`:

```javascript
const btnHardeningAddAll = document.getElementById('btn-hardening-add-all');

btnHardeningAddAll?.addEventListener('click', async () => {
  const subnet = hardeningSubnetInput?.value.trim();
  if (!subnet) { showHardeningError('Enter a subnet first.'); return; }

  const prefix = subnet.split('/')[0].split('.').slice(0, 3).join('.');
  const matchingHosts = state.hosts
    .filter(h => h.ip.startsWith(prefix + '.'))
    .map(h => ({
      ip: h.ip, mac: h.mac || '', hostname: h.hostname || '',
      ports: h.ports?.map(p => p.port || p) || [],
      firstSeen: h.firstSeen || Date.now(), lastSeen: h.lastSeen || Date.now(),
    }));

  if (matchingHosts.length === 0) {
    showHardeningError('No discovered hosts match this subnet.');
    return;
  }

  try {
    await api.hardeningMonitor.setBaseline(subnet, matchingHosts);
    clearHardeningError();
    refreshBaselineSummary();
    // Also mark hosts as monitored in state
    for (const mh of matchingHosts) {
      const idx = state.hosts.findIndex(h => h.ip === mh.ip);
      if (idx >= 0) state.hosts[idx].monitorStatus = state.hosts[idx].monitorStatus || 'monitored';
    }
    if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();
    btnHardeningAddAll.textContent = `✓ Imported ${matchingHosts.length}`;
    btnHardeningAddAll.disabled = true;
    setTimeout(() => {
      btnHardeningAddAll.textContent = '📋 Import Hosts';
      btnHardeningAddAll.disabled = false;
    }, 2000);
  } catch (err) {
    showHardeningError(`Failed to import: ${err.message}`);
  }
});
```

**Change 3: Update monitorStatus after baseline set (HM-05)**

In `btnSetBaseline` click handler (line ~468–484), after successful `setBaseline`:

```javascript
// After await api.hardeningMonitor.setBaseline(subnet, hosts):
for (const bHost of hosts) {
  const idx = state.hosts.findIndex(h => h.ip === bHost.ip);
  if (idx >= 0) {
    state.hosts[idx].monitorStatus = state.hosts[idx].monitorStatus || 'monitored';
    state.hosts[idx].monitorLastSeen = state.hosts[idx].monitorLastSeen || Date.now();
  }
}
if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();
```

Same pattern for `btnPromote` handler (line ~302–313).

---

### Component 2: Renderer — Host Details Module

#### [MODIFY] [hostDetails.js](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/modules/hostDetails.js)

**Change 1: Add "Add to Monitor" button (HM-02) — In `buildHostMonitorActions()`**

```diff
 function buildHostMonitorActions(host, monSection, subnetGuess) {
   const actionRow = document.createElement('div');
   actionRow.style.cssText = 'display:flex; gap:6px; flex-wrap:wrap; margin-top:8px;';

+  const btnAddToMonitor = document.createElement('button');
+  btnAddToMonitor.className = 'btn-action';
+  btnAddToMonitor.style.cssText = 'font-size:10px; padding:3px 8px; border-color:var(--success); color:var(--success);';
+  btnAddToMonitor.textContent = '➕ Add to Monitor';
+  btnAddToMonitor.addEventListener('click', async () => {
+    try {
+      const existing = await api.hardeningMonitor.getBaseline(subnetGuess);
+      const hosts = existing?.hosts || [];
+      if (!hosts.some(h => h.ip === host.ip)) {
+        hosts.push({
+          ip: host.ip, mac: host.mac || '', hostname: host.hostname || '',
+          ports: host.ports?.map(p => p.port || p) || [],
+          firstSeen: host.firstSeen || Date.now(), lastSeen: host.lastSeen || Date.now(),
+        });
+      }
+      await api.hardeningMonitor.setBaseline(subnetGuess, hosts);
+      const idx = state.hosts.findIndex(h => h.ip === host.ip);
+      if (idx >= 0) state.hosts[idx].monitorStatus = state.hosts[idx].monitorStatus || 'monitored';
+      btnAddToMonitor.textContent = '✓ Added';
+      btnAddToMonitor.disabled = true;
+    } catch { btnAddToMonitor.textContent = '⚠ Error'; }
+  });
+  actionRow.appendChild(btnAddToMonitor);

   const btnOpenMonitor = document.createElement('button');
```

---

### Component 3: Hardening Panel HTML

#### [MODIFY] [index.html](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/index.html#L1140-L1145)

Add "Import Hosts" button inline with "Set Baseline" in the Row 2 flex container:

```diff
             <div style="flex:1;"></div>
+            <button id="btn-hardening-add-all" class="btn secondary"
+              style="font-size:11px; padding:5px 10px; white-space:nowrap;"
+              title="Import all discovered hosts matching this subnet as the baseline">
+              📋 Import Hosts
+            </button>
             <button id="btn-hardening-set-baseline" class="btn secondary"
```

This places the button immediately before "Set Baseline" in the same row, creating a natural left-to-right flow: `[Import Hosts] [Set Baseline]`.

---

### Component 4: Credential Sniffer

#### [MODIFY] [credentialSniffer.js](file:///e:/AntiGravityCode/NetworkDetection/src/main/credentialSniffer.js#L25-L26)

Replace invalid `pop.request.arg` with `pop.request.data`:

```diff
     '-e', 'pop.request.command',
-    '-e', 'pop.request.arg',
+    '-e', 'pop.request.data',
```

---

## Files Changed Summary

| File | Change Type | Bug(s) Fixed |
|------|------------|--------------|
| [hardeningMonitor.js](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/modules/hardeningMonitor.js) | MODIFY | HM-01, HM-03, HM-04, HM-05 |
| [hostDetails.js](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/modules/hostDetails.js) | MODIFY | HM-02 |
| [index.html](file:///e:/AntiGravityCode/NetworkDetection/src/renderer/index.html) | MODIFY | HM-03 |
| [credentialSniffer.js](file:///e:/AntiGravityCode/NetworkDetection/src/main/credentialSniffer.js) | MODIFY | CRED-01 |

---

## Verification Plan

### Automated Tests

**Framework:** Vitest (`npm run test` / `vitest run`)

#### Existing Tests (must remain green)

[test/hardeningMonitor.test.js](file:///e:/AntiGravityCode/NetworkDetection/test/hardeningMonitor.test.js) — 9 existing test cases covering: `validateCidr`, `pingHost`, `sweepSubnet`, `diffSnapshots` (new hosts, removed hosts, port changes, MAC/hostname changes, null delta), baseline management, monitor lifecycle (start/stop, errors, minimum interval, cycle delta, sweep abort, batch sweep).

```bash
# Run all tests
npm run test

# Run only hardening monitor tests
npx vitest run test/hardeningMonitor.test.js
```

#### New Tests

None of the existing tests cover the renderer-side logic being changed. The renderer modules run in a browser environment and would need jsdom/happy-dom. Since the existing test infrastructure does not include renderer tests for the hardening module, **no new automated tests are proposed** — the changes are UI-layer DOM wiring that is best verified manually.

### Manual Verification

> All manual tests require: `npm run dev` to start the application.

#### 1. Investigate Button (HM-01/HM-04)

1. Open app → Add hosts to scope (scan your local subnet or import)
2. Click **🛡 Monitor** → enter a subnet CIDR → click **▶ Start**
3. Wait for one scan cycle to complete (set interval to 1 min for testing)
4. If new hosts are detected, alert cards should appear
5. Click **🔍 Investigate** on an alert card
6. ✅ **Expected:** The host details panel opens with IP, MAC, hostname, ports filled in

#### 2. Add Individual Host to Monitor (HM-02)

1. Open host details for any discovered host (click "View Details" on a host card)
2. Scroll to the "🛡 Hardening Monitor" section
3. Click **➕ Add to Monitor**
4. ✅ **Expected:** Button changes to "✓ Added" and the host is now in the baseline
5. Open the Monitor panel and check the Baseline Summary confirms the host count increased

#### 3. Import All Discovered Hosts (HM-03)

1. Discover some hosts via network scan
2. Open Hardening Monitor panel → enter matching subnet CIDR
3. Click **📋 Import Hosts**
4. ✅ **Expected:** All matching hosts imported as baseline; baseline summary shows correct count
5. Button shows "✓ Imported N" temporarily

#### 4. Monitor Status Sync (HM-05)

1. Discover hosts → open Monitor panel → set baseline
2. Close the monitor panel
3. Check host cards in the main grid
4. ✅ **Expected:** Host cards for baselined hosts show monitor status dot

#### 5. Credential Capture (CRED-01)

1. Go to **🕵️ Passive Intelligence** → select network interface
2. Toggle the **Credentials** capture on
3. ✅ **Expected:** No tshark error; capture starts and status shows "Capturing"
4. Check console for no `pop.request.arg` errors
