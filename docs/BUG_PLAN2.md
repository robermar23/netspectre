# NetSpecter Bug Fix Implementation Plan — Round 2

> **Date:** 2026-03-14
> **Branch:** `cloud-enum`
> **Scope:** 4 remaining unresolved bugs from `docs/BUGS.md`

---

## Overview

| # | Bug ID | Short Title | Files Affected | Complexity |
|---|--------|-------------|----------------|------------|
| 1 | BUG-CE-001 | CloudEnum "Scan Host" button does nothing | `renderer/modules/cloudEnum.js`, `renderer/index.js` | Low |
| 2 | BUG-NSE-001 | Nmap-scripts NSE Explorer lost risk/info display | `main/nmapScanner.js`, `renderer/modules/hostDetails.js` | Medium |
| 3 | BUG-CE-002 | Cloud evidence not stored per-host; no host-details section; badges don't survive re-render | `renderer/modules/cloudEnum.js`, `renderer/modules/hostDetails.js`, `renderer/modules/scanControls.js` | Medium |
| 4 | BUG-PORT-001 | Port connect-actions (SSH/RDP/HTTP) only appear for native deep scan, not all sources | `renderer/modules/hostDetails.js` | Medium |

---

## Bug 1 — CloudEnum "Scan Host" Button Does Nothing

### Root Cause Analysis

**File:** `src/renderer/modules/cloudEnum.js`, line 206–208

```js
btnScan.addEventListener('click', () => {
  if (window.__openDetailsPanel) window.__openDetailsPanel(finding.ip);
});
```

The button calls `window.__openDetailsPanel(finding.ip)`, but this global is **never set anywhere** in the codebase.

`hostDetails.js` returns `{ openPanel, showHost, renderActionButtons }` from its `init()`, but the caller (`index.js`) never exposes it on `window`. The analogous `window.__openCloudEnumPanel` **is** correctly exposed in `cloudEnum.js` init (line 460), making this an oversight during the module refactor.

### Evidence

- `src/renderer/index.js` line 48: `const cloudEnum = initCloudEnum(); // eslint-disable-line no-unused-vars` — the comment signals cloudEnum's return value is discarded.
- `src/renderer/index.js` line 58–67: `hostDetails = initHostDetails(...)` — openPanel is available here but not exposed globally.
- `grep window.__openDetailsPanel` → zero results.

### Fix Plan

**Step 1 — Expose `openDetailsPanel` globally in `src/renderer/index.js`**

After line 67 (where `hostDetails` is defined), add:

```js
// Expose for cross-module use (CloudEnum "Scan Host", future deep-links)
window.__openDetailsPanel = hostDetails.openPanel;
```

This follows the established pattern already used for `window.__openCloudEnumPanel`, `window.__openSharePanel`, and `window.__openDirFuzzPanel`.

**Step 2 — Verify the host exists in `state.hosts` before opening**

The button calls `window.__openDetailsPanel(finding.ip)`. The `openDetailsPanel` function in hostDetails.js currently accepts a `host` object, not a raw IP string. Inspect the function signature:

- `openDetailsPanel(host)` — takes the full host object from `state.hosts`.

Therefore the cloudEnum button must look up the host by IP first:

```js
btnScan.addEventListener('click', () => {
  const host = state.hosts.find(h => h.ip === finding.ip);
  if (host && window.__openDetailsPanel) {
    window.__openDetailsPanel(host);
  } else if (window.__openDetailsPanel) {
    // Host not yet in state (found via single-IP mode) — create a minimal stub
    window.__openDetailsPanel({ ip: finding.ip, ports: [], hostname: '', mac: '' });
  }
});
```

**Files to change:**
- `src/renderer/index.js` — add `window.__openDetailsPanel = hostDetails.openPanel;`
- `src/renderer/modules/cloudEnum.js` — fix the Scan Host click handler to look up host from `state.hosts`

**Tests to update:**
- `test/renderer/cloudEnum.test.js` — add a test verifying `window.__openDetailsPanel` is called with the correct host object when "Scan Host" is clicked.

---

## Bug 2 — Nmap-Scripts NSE Explorer Lost Risk/Info Display

### Root Cause Analysis

**Two-layer failure:**

**Layer 1 — Backend truncated data model:**
`src/main/nmapScanner.js` `getNmapScripts()` (line 272–275) only returns `{ id, categories }`. The `.nse` file header also contains a `description` field (a multi-line Lua string) and a `license` field. The `description` is the "info on each script" that used to be shown.

```lua
description = [[
  Detects the Stuxnet worm by checking for specific registry keys.
  ...
]]
categories = {"malware", "safe", "discovery"}
```

**Layer 2 — Renderer omits all metadata from the dropdown:**
`src/renderer/modules/hostDetails.js` `renderNseDropdown()` (line 1114–1126) only renders `script.id` in a single `<div>`. Categories and description are never shown even if they were present.

```js
// Current (broken):
item.innerHTML = `<div style="font-weight: 500; color: var(--text-main);" class="nse-title-node"></div>`;
item.querySelector('.nse-title-node').textContent = script.id;
```

### NSE Category → Risk Level Mapping

Nmap NSE categories map to risk levels:

| Category | Risk | Color |
|----------|------|-------|
| `exploit` | CRITICAL | `var(--danger)` (#ef4444) |
| `vuln` | HIGH | `var(--warning)` (#f97316) |
| `brute` | HIGH | `var(--warning)` |
| `malware` | MEDIUM | #f59e0b |
| `dos` | MEDIUM | #f59e0b |
| `intrusive` | MEDIUM | #f59e0b |
| `auth` | LOW | `var(--info)` |
| `discovery` | INFO | `var(--info)` (#38bdf8) |
| `safe` | SAFE | `var(--success)` (#22c55e) |
| `default` | INFO | `var(--text-muted)` |

### Fix Plan

**Step 1 — Extend backend data model (`src/main/nmapScanner.js`)**

Within the existing `getNmapScripts()` loop, after parsing `categories`, also parse the `description` field from the 2KB header buffer:

```js
// Parse description = [[ ... ]] (Lua long string)
let description = '';
const descMatch = content.match(/description\s*=\s*\[\[([^\]]*(?:\][^\]]+)*)\]\]/s);
if (descMatch && descMatch[1]) {
  description = descMatch[1].trim().replace(/\s+/g, ' ').slice(0, 200); // truncate for IPC
}

scripts.push({ id, categories, description });
```

Notes:
- The regex uses the `s` (dotAll) flag to match multi-line descriptions.
- Truncate to 200 characters to keep IPC payload small (600+ scripts × 200 chars = ~120KB, acceptable).
- No new file reads needed; uses the existing 2KB buffer.

**Step 2 — Compute risk level from categories (renderer util)**

Add a pure function at the top of the NSE rendering block in `src/renderer/modules/hostDetails.js`:

```js
function nseRiskLevel(categories) {
  if (categories.includes('exploit'))   return { label: 'CRITICAL', color: 'var(--danger)' };
  if (categories.includes('vuln'))      return { label: 'HIGH',     color: 'var(--warning)' };
  if (categories.includes('brute'))     return { label: 'HIGH',     color: 'var(--warning)' };
  if (categories.includes('malware'))   return { label: 'MEDIUM',   color: '#f59e0b' };
  if (categories.includes('dos'))       return { label: 'MEDIUM',   color: '#f59e0b' };
  if (categories.includes('intrusive')) return { label: 'MEDIUM',   color: '#f59e0b' };
  if (categories.includes('auth'))      return { label: 'LOW',      color: 'var(--info)' };
  if (categories.includes('discovery')) return { label: 'INFO',     color: 'var(--info)' };
  if (categories.includes('safe'))      return { label: 'SAFE',     color: 'var(--success)' };
  return { label: 'INFO', color: 'var(--text-muted)' };
}
```

**Step 3 — Rebuild `renderNseDropdown` item template**

Replace the current single-line item with a structured layout:

```js
matches.forEach(script => {
  const item = document.createElement('div');
  item.className = 'nse-dropdown-item';

  const risk = nseRiskLevel(script.categories || []);

  // Row 1: script name + risk badge
  const row1 = document.createElement('div');
  row1.style.cssText = 'display:flex; align-items:center; gap:6px; margin-bottom:3px;';

  const nameEl = document.createElement('span');
  nameEl.style.cssText = 'font-weight:600; font-size:12px; color:var(--text-main); font-family:monospace; flex:1;';
  nameEl.textContent = script.id;

  const riskBadge = document.createElement('span');
  riskBadge.style.cssText = `font-size:9px; padding:1px 5px; border-radius:8px; font-weight:700; border:1px solid ${risk.color}; color:${risk.color};`;
  riskBadge.textContent = risk.label;

  row1.append(nameEl, riskBadge);

  // Row 2: categories as small tags
  const row2 = document.createElement('div');
  row2.style.cssText = 'display:flex; gap:3px; flex-wrap:wrap; margin-bottom:3px;';
  (script.categories || []).forEach(cat => {
    const tag = document.createElement('span');
    tag.style.cssText = 'font-size:9px; padding:1px 4px; border-radius:3px; background:rgba(255,255,255,0.07); color:var(--text-muted);';
    tag.textContent = cat;
    row2.appendChild(tag);
  });

  // Row 3: description (if available)
  const row3 = document.createElement('div');
  if (script.description) {
    row3.style.cssText = 'font-size:10px; color:var(--text-muted); line-height:1.4;';
    row3.textContent = script.description.length > 120
      ? script.description.slice(0, 120) + '…'
      : script.description;
  }

  item.append(row1, row2, row3);

  item.addEventListener('click', () => {
    selectedNseScript = script.id;
    nseSearchInput.value = script.id;
    nseDropdown.classList.remove('show');
    btnNmapCustom.disabled = false;
  });
  nseDropdown.appendChild(item);
});
```

**Step 4 — CSS for NSE dropdown item height**

The `.nse-dropdown-item` may need a `max-height` or `min-height` update in `style.css` to accommodate the 3-row layout without becoming too tall when many results show. Add:

```css
.nse-dropdown-item {
  padding: 8px 10px;
  cursor: pointer;
  border-bottom: 1px solid rgba(255,255,255,0.05);
  transition: background 0.15s;
}
.nse-dropdown-item:hover {
  background: rgba(255,255,255,0.07);
}
```

**Files to change:**
- `src/main/nmapScanner.js` — parse `description` from .nse header, include in returned object
- `src/renderer/modules/hostDetails.js` — add `nseRiskLevel()` helper, rebuild `renderNseDropdown` item template
- `src/renderer/style.css` — ensure `.nse-dropdown-item` padding accommodates 3-row layout

**Tests to update:**
- `test/nmapScanner.test.js` — add tests for `getNmapScripts()` returning `description` field; test truncation at 200 chars; test description parsing with multi-line Lua strings
- `test/renderer/` — not strictly unit-testable (DOM), but can verify `nseRiskLevel()` is exported and returns correct values for each category

---

## Bug 3 — Cloud Evidence Not Stored Per-Host; Missing Host Details Section; Badges Lost on Re-render

### Root Cause Analysis

**Three distinct failures:**

**Failure A — Findings not attached to host objects:**
`state.cloudFindings` is a flat global array. When `vm.appendFinding(finding)` runs, it pushes to that array but does NOT update the matching host in `state.hosts`. This means:
- Host details panel has no access to cloud findings for a specific host.
- Cloud findings data is session-only and not part of the per-host state model.

**Failure B — Host details panel has no cloud section:**
`openDetailsPanel(host)` in `hostDetails.js` never checks `host.cloudFindings`. No section for cloud evidence exists in the generated HTML.

**Failure C — Dashboard badges not re-applied on re-render:**
`_updateHostBadge(ip, severity)` (cloudEnum.js line 230) updates badges in the live DOM. When `debouncedRenderAllHosts()` is called (re-renders all cards), the old cards are destroyed and new ones created. The new cards never get the badge re-applied because `_updateHostBadge` is only called from `vm.appendFinding` which only runs when a new finding arrives.

### Fix Plan

**Step 1 — Attach findings to host objects in `state.hosts` (`src/renderer/modules/cloudEnum.js`)**

In `vm.appendFinding(finding)`, after pushing to `state.cloudFindings`, also attach to the host:

```js
appendFinding(finding) {
  state.cloudFindings.push(finding);
  this.updateStats();

  // Attach finding to the matching host object for persistence across re-renders
  const hostEntry = state.hosts.find(h => h.ip === finding.ip);
  if (hostEntry) {
    if (!hostEntry.cloudFindings) hostEntry.cloudFindings = [];
    // Avoid duplicates (idempotent in case of re-delivery)
    const isDupe = hostEntry.cloudFindings.some(
      f => f.ip === finding.ip && f.service === finding.service &&
           f.port === finding.port && f.title === finding.title
    );
    if (!isDupe) hostEntry.cloudFindings.push(finding);

    // Track worst severity on the host for badge rendering
    const rank = { critical: 2, warning: 1, info: 0 };
    const currentRank = rank[hostEntry.cloudSeverity] ?? -1;
    if ((rank[finding.severity] ?? 0) > currentRank) {
      hostEntry.cloudSeverity = finding.severity;
    }
  }

  // ... rest of existing code
}
```

**Step 2 — Re-apply badges after host card re-renders (`src/renderer/modules/cloudEnum.js`)**

The module already exports `init()` which returns `{ openPanel }`. Extend it to also export a `reapplyBadges()` function and wire it into `scanControls.js`.

**In `cloudEnum.js` init():**
```js
// New exported function
function reapplyHostBadges() {
  state.hosts.forEach(host => {
    if (host.cloudSeverity) {
      _updateHostBadge(host.ip, host.cloudSeverity);
    }
  });
}

export function init() {
  // ... existing setup ...
  return { openPanel: openCloudEnumPanel, reapplyBadges: reapplyHostBadges };
}
```

**In `src/renderer/index.js`:**
Wire `reapplyBadges` into `debouncedRenderAllHosts` post-render hook. Since `debouncedRenderAllHosts` is defined in `scanControls.js`, the cleanest approach is to pass `reapplyBadges` as a callback:

```js
const cloudEnum = initCloudEnum();

initScanControls({
  openDetailsPanel: hostDetails.openPanel,
  onHostsRendered: cloudEnum.reapplyBadges,  // NEW
});
```

**In `src/renderer/modules/scanControls.js`**, accept and call `onHostsRendered` after the host grid is rebuilt:

```js
// In the debouncedRenderAllHosts / renderAllHosts function, at the very end:
if (typeof _onHostsRendered === 'function') _onHostsRendered();
```

**Alternative (simpler):** Instead of passing a callback, call `state.hosts.forEach(h => h.cloudSeverity && _updateHostBadge(h.ip, h.cloudSeverity))` at the end of `renderAllHosts` in scanControls directly, by importing `reapplyBadges` from `cloudEnum.js`. However, that creates a circular module dependency. The callback pattern is cleaner.

**Step 3 — Add Cloud Evidence section to host details panel (`src/renderer/modules/hostDetails.js`)**

After the existing vulnerabilities section (`dp-vulns-section`, around line 656), add a new cloud evidence section. This should be built by a dedicated helper function:

```js
function renderCloudFindingsSection(host, container) {
  const findings = host.cloudFindings;
  if (!findings || findings.length === 0) return;

  const section = document.createElement('div');
  section.className = 'dp-section';
  section.style.cssText = 'margin-top: 12px;';

  const label = document.createElement('div');
  label.className = 'dp-section-label';
  label.style.cssText = 'color: var(--cloudenum-btn); display:flex; align-items:center; gap:6px;';
  label.innerHTML = '🐳 Cloud / Container Evidence';
  section.appendChild(label);

  // Summary badge row
  const summaryRow = document.createElement('div');
  summaryRow.style.cssText = 'display:flex; gap:6px; margin:6px 0; flex-wrap:wrap;';
  const severities = ['critical', 'warning', 'info'];
  severities.forEach(sev => {
    const count = findings.filter(f => f.severity === sev).length;
    if (count === 0) return;
    const SEVERITY_COLORS = {
      critical: 'var(--cloudenum-critical)',
      warning: 'var(--cloudenum-warning)',
      info: 'var(--cloudenum-info)'
    };
    const badge = document.createElement('span');
    badge.style.cssText = `font-size:10px; padding:2px 8px; border-radius:8px; font-weight:700; border:1px solid ${SEVERITY_COLORS[sev]}; color:${SEVERITY_COLORS[sev]};`;
    badge.textContent = `${count} ${sev.toUpperCase()}`;
    summaryRow.appendChild(badge);
  });
  section.appendChild(summaryRow);

  // Individual finding cards (collapsed by default via <details>)
  findings.forEach(f => {
    const SEVERITY_COLORS = {
      critical: 'var(--cloudenum-critical)',
      warning: 'var(--cloudenum-warning)',
      info: 'var(--cloudenum-info)'
    };
    const details = document.createElement('details');
    details.style.cssText = 'margin-top:6px; border-left:3px solid ' + (SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info) + '; padding:4px 8px; border-radius:2px; background:rgba(56,189,248,0.04);';

    const summary = document.createElement('summary');
    summary.style.cssText = 'cursor:pointer; font-size:11px; font-weight:600; color:var(--text-main); user-select:none;';
    // Use textContent (not innerHTML) to avoid XSS
    summary.textContent = `[${f.service}:${f.port}] ${f.title}`;
    details.appendChild(summary);

    const body = document.createElement('div');
    body.style.cssText = 'padding:6px 0; font-size:11px; color:var(--text-muted); font-family:monospace; word-break:break-all;';
    body.textContent = f.evidence;
    details.appendChild(body);

    const remDiv = document.createElement('div');
    remDiv.style.cssText = 'font-size:10px; color:var(--text-secondary); margin-top:4px; line-height:1.4;';
    remDiv.textContent = f.remediation;
    details.appendChild(remDiv);

    // "View in Cloud Panel" button
    const viewBtn = document.createElement('button');
    viewBtn.className = 'btn-action';
    viewBtn.style.cssText = 'font-size:10px; padding:2px 8px; margin-top:6px; border-color:var(--cloudenum-btn); color:var(--cloudenum-btn);';
    viewBtn.textContent = '🐳 View in Cloud Panel';
    viewBtn.addEventListener('click', () => {
      if (window.__openCloudEnumPanel) window.__openCloudEnumPanel(f.ip);
    });
    details.appendChild(viewBtn);

    section.appendChild(details);
  });

  container.appendChild(section);
}
```

Call this function in `openDetailsPanel` after the vulnerabilities section renders:

```js
// After the nmapData.vulnerabilities block (around line 673):
renderCloudFindingsSection(host, document.getElementById('dp-vulns-section').parentElement);
```

**Step 4 — Handle `clearFindings()` also clearing host-attached data**

When `vm.clearFindings()` is called (user clicks "Clear" in the cloud panel), also clear host-level data:

```js
clearFindings() {
  // Clear per-host cloud findings too
  state.hosts.forEach(host => {
    delete host.cloudFindings;
    delete host.cloudSeverity;
  });
  state.cloudFindings = [];
  // ... rest of existing clear logic
}
```

**Files to change:**
- `src/renderer/modules/cloudEnum.js` — `vm.appendFinding()` attaches to host, `vm.clearFindings()` clears host fields, export `reapplyBadges()`
- `src/renderer/modules/hostDetails.js` — add `renderCloudFindingsSection()` helper, call it from `openDetailsPanel()`
- `src/renderer/modules/scanControls.js` — accept and call `onHostsRendered` callback
- `src/renderer/index.js` — pass `cloudEnum.reapplyBadges` as `onHostsRendered`

**Tests to update:**
- `test/renderer/cloudEnum.test.js` — add tests for:
  - `appendFinding` attaches to `state.hosts` entry
  - `appendFinding` escalates `host.cloudSeverity` correctly
  - `clearFindings` removes `host.cloudFindings` and `host.cloudSeverity`
  - `reapplyBadges` calls `_updateHostBadge` for all hosts with `cloudSeverity`

---

## Bug 4 — Port Connect-Actions Only Appear for Native Deep Scan Results

### Root Cause Analysis

The `renderActionButtons(container, ip, data)` function (hostDetails.js line 192–256) generates connect-action buttons (Open HTTP, Open HTTPS, Connect SSH, Remote Desktop, Enumerate Shares, Brute-Force) for each port. However, it is **only called** from `renderSavedHistory()` (line 303), which iterates `host.deepAudit.history[]`.

The main ports section (line 549–561) renders badge `<span class="port-item">` elements for each entry in `host.ports[]`. Clicking these badges only triggers an Nmap port scan (line 1179–1198). No connect-action buttons are rendered from `host.ports[]` directly.

`host.ports[]` is correctly populated by ALL scan sources:
- Native scan → `scanControls.js` line 56
- Deep scan → `deepScan.js` line 296
- Passive intel (future) → any module that calls `state.hosts[i].ports = ...`

So: **if nmap, deep scan, brute force result, or any other tool discovers port 22 and merges it into `host.ports`, that port should show an SSH connect button in the main ports section.**

### Fix Plan

**Step 1 — Create `buildConnectActionsSection(ip, ports)` helper function**

Add a new function in `hostDetails.js` that builds a "Quick Connect & Actions" strip from the canonical `host.ports[]`:

```js
function buildConnectActionsSection(ip, ports) {
  if (!ports || ports.length === 0) return null;

  // Define all port → action mappings (superset of renderActionButtons)
  const connectActions = [
    {
      port: 80,   label: '🌐 HTTP',       type: 'http'
    },
    {
      port: 8080, label: '🌐 HTTP:8080',  type: 'http', portArg: 8080
    },
    {
      port: 443,  label: '🔒 HTTPS',      type: 'https'
    },
    {
      port: 8443, label: '🔒 HTTPS:8443', type: 'https', portArg: 8443
    },
    {
      port: 22,   label: '⌨️ SSH',        type: 'ssh',  needsUsername: true
    },
    {
      port: 3389, label: '🖥️ RDP',        type: 'rdp'
    },
    {
      port: 5900, label: '🖥️ VNC',        type: 'vnc'
    },
    {
      port: 23,   label: '⌨️ Telnet',     type: 'telnet'
    },
  ];

  const matchingActions = connectActions.filter(a => ports.includes(a.port));
  if (matchingActions.length === 0) return null;

  const section = document.createElement('div');
  section.style.cssText = 'margin-top: 10px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap;';

  const label = document.createElement('span');
  label.style.cssText = 'font-size: 11px; color: var(--text-muted); flex-basis: 100%;';
  label.textContent = '🔗 Quick Connect:';
  section.appendChild(label);

  matchingActions.forEach(action => {
    if (action.needsUsername) {
      // SSH-style: username input + connect button
      const wrapper = document.createElement('div');
      wrapper.style.cssText = 'display:flex; gap:4px; align-items:center;';

      const usernameInput = document.createElement('input');
      usernameInput.type = 'text';
      usernameInput.className = 'text-input';
      usernameInput.style.cssText = 'width:70px; padding:3px 6px; font-size:11px;';
      usernameInput.placeholder = 'user';
      usernameInput.value = 'root';
      usernameInput.title = 'SSH Username';

      const btn = document.createElement('button');
      btn.className = 'btn-action';
      btn.style.cssText = 'font-size: 10px; padding: 3px 8px;';
      btn.textContent = action.label;
      btn.addEventListener('click', () => {
        window.electronAPI.openExternalAction({
          type: action.type,
          ip,
          username: usernameInput.value || 'root'
        });
      });

      wrapper.append(usernameInput, btn);
      section.appendChild(wrapper);
    } else {
      const btn = document.createElement('button');
      btn.className = 'btn-action';
      btn.style.cssText = 'font-size: 10px; padding: 3px 8px;';
      btn.textContent = action.label;
      btn.addEventListener('click', () => {
        window.electronAPI.openExternalAction({
          type: action.type,
          ip,
          port: action.portArg || action.port
        });
      });
      section.appendChild(btn);
    }
  });

  return section;
}
```

**Step 2 — Call `buildConnectActionsSection` from `openDetailsPanel`**

After the port badges block (around line 560), and before the Share Enumeration section (line 564), insert:

```js
// Quick Connect actions for ALL discovered ports (any scan source)
const connectSection = buildConnectActionsSection(host.ip, host.ports);
if (connectSection) portsList.parentElement.appendChild(connectSection);
```

This ensures the section appears directly under the ports badges, above the Shares/DirFuzz/BruteForce sections, giving a clean logical flow:

```
[ Port Badges ]       ← port numbers from host.ports[]
[ Quick Connect ]     ← NEW: SSH/HTTP/HTTPS/RDP/VNC/Telnet buttons
[ 📂 Enumerate Shares ]
[ 🔎 Dir Fuzz ]
[ ⚔️ Brute-Force ]
[ 💧 Cred Spray ]
[ 🐳 Cloud Enum ]
```

**Step 3 — SMB/Shares in Quick Connect section**

The SMB "Enumerate Shares" button already has its own dedicated section (line 564–581). To avoid duplication, exclude ports 445 and 139 from `buildConnectActionsSection` since they are handled elsewhere. Document this exclusion in a comment.

**Step 4 — Source attribution in port badges**

Optionally (stretch goal for clarity): annotate port badges with their discovery source. This requires tracking source per port in the host model:

```
[ 22 (nmap) ] [ 80 (deep) ] [ 3389 (passive) ]
```

This requires a data model change (`host.portSources = { 22: 'nmap', 80: 'deepScan' }`) and is **not required** for the bug fix. Mark as a future enhancement.

**Files to change:**
- `src/renderer/modules/hostDetails.js` — add `buildConnectActionsSection()` function, call it from `openDetailsPanel()`

**Tests to update:**
- `test/renderer/` — `buildConnectActionsSection` is a pure DOM builder; test that given `ports = [22, 80, 443]` it creates buttons for SSH, HTTP, and HTTPS; test that ports 445/139 are excluded (handled by Shares section).

---

## Execution Order

The bugs are independent and can be fixed in any order. Recommended sequence for least merge risk:

```
1. BUG-CE-001  (2 lines changed, no new functions)
2. BUG-PORT-001 (new function + one call site, self-contained)
3. BUG-NSE-001  (backend + renderer, no cross-module deps)
4. BUG-CE-002   (most complex, touches 4 files + state model)
```

---

## Test Strategy

### Unit Tests (Vitest)

| Test File | New Tests |
|-----------|-----------|
| `test/nmapScanner.test.js` | `getNmapScripts` returns `description`; description truncated at 200 chars; multi-line Lua string parsed correctly; missing description returns empty string |
| `test/renderer/cloudEnum.test.js` | `appendFinding` attaches to `state.hosts[i].cloudFindings`; severity escalation on `host.cloudSeverity`; `clearFindings` deletes per-host fields; `reapplyBadges` calls DOM update; "Scan Host" button calls `window.__openDetailsPanel` with host object |

### Manual Smoke Tests

| Test | Pass Criteria |
|------|---------------|
| CloudEnum → run scan → click "🔍 Scan Host" | Host details panel opens for that IP |
| NSE Explorer → type "smb" | Dropdown shows script name, risk badge (e.g. HIGH), categories (e.g. "safe", "discovery"), and description text |
| NSE Explorer → type "exploit" | Scripts with `exploit` category show CRITICAL red badge |
| CloudEnum → run scan → close panel → re-render grid | 🐳 badges still present on host cards |
| CloudEnum → run scan → click host card with findings → host details | "Cloud / Container Evidence" section shows findings with severity summary |
| Host with port 22 from nmap scan → host details | "Quick Connect" section shows "⌨️ SSH" button |
| Host with port 80 from deep scan (not native) → host details | "Quick Connect" section shows "🌐 HTTP" button |
| Host with port 445 → host details | Quick Connect section does NOT duplicate "Enumerate Shares" (SMB section handles it) |

---

## Architecture Notes

### Security Considerations

- All `textContent` is used (not `innerHTML`) when rendering user-visible data from findings — prevents XSS from crafted server responses.
- `escapeHtml` is already present in `hostDetails.js`; use it as a fallback for any attribute values.
- The `description` field parsed from `.nse` files is read from the local filesystem under the nmap install directory — not user input. Truncation prevents degenerate cases. No sanitization strictly needed, but truncating to 200 chars limits UI damage from malformed scripts.
- The `openExternalAction` IPC call in `buildConnectActionsSection` passes validated IP from host data (already in `state.hosts`) — not raw user input.

### IPC Payload Size

Adding `description` to `getNmapScripts()` output increases payload size. Nmap ships ~600 scripts. At 200 chars max per description:
- Worst case: 600 × ~300 bytes (id + categories + description) = ~180KB
- This is a one-time `ipcRenderer.invoke` at startup, acceptable.

### State Consistency

`host.cloudFindings` and `host.cloudSeverity` are in-memory fields, not persisted to `electron-store`. They survive for the app session but are lost on restart. This matches the behavior of `host.deepAudit.history` and other in-session data. Persistence is a future enhancement if needed.

---

## Files Summary

| File | Changes | Bug(s) |
|------|---------|--------|
| `src/renderer/index.js` | Expose `window.__openDetailsPanel`; pass `onHostsRendered` callback | 1, 3 |
| `src/renderer/modules/cloudEnum.js` | Fix Scan Host handler; attach findings to host; export reapplyBadges; clear host fields on clear | 1, 3 |
| `src/renderer/modules/hostDetails.js` | Add `nseRiskLevel()`; rebuild NSE dropdown; add `buildConnectActionsSection()`; add `renderCloudFindingsSection()` | 2, 3, 4 |
| `src/renderer/modules/scanControls.js` | Accept + call `onHostsRendered` callback after grid re-render | 3 |
| `src/main/nmapScanner.js` | Parse `description` from .nse header; include in returned script objects | 2 |
| `src/renderer/style.css` | NSE dropdown item padding for 3-row layout | 2 |
| `test/nmapScanner.test.js` | Tests for description parsing | 2 |
| `test/renderer/cloudEnum.test.js` | Tests for host attachment, severity escalation, reapplyBadges, Scan Host button | 1, 3 |
