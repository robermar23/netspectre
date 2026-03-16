# NetSpecter Header / Toolbar Redesign — Implementation Plan

## Executive Summary

The existing `<header>` is a single monolithic row that always renders all controls regardless
of the active workspace. Network-only tools (RevShell, Cred Spray, Shares, Monitor, Cloud Enum,
Dir Fuzz, VLAN Discovery, Passive Intel, host filters, view toggles) are visible even when the
user is in the Web App workspace, and conversely the Web App workspace has zero dedicated header
actions. The header also has inline `style=""` attributes scattered throughout and no clear
semantic grouping.

This plan replaces the monolithic header with a **two-tier, workspace-aware toolbar system**:

| Tier | Always visible | Switches with workspace |
|------|---------------|------------------------|
| Row 1 — Universal | Logo · Status · Workspace switcher · Save/Load · Settings · Exit | — |
| Row 2 — Contextual | — | Network toolbar **or** Web App toolbar |

---

## 0. Guiding Principles

1. **Context-first**: show only what applies to the current workspace.
2. **No inline styles**: all layout lives in CSS classes.
3. **Extensible by design**: adding a future workspace or tool requires only a new CSS class +
   a registration call — no touching existing toolbar code.
4. **Dependency-aware visibility preserved**: `.nmap-only`, `.tshark-only`, `.hydra-only`,
   `.smbclient-only`, `.msf-only` continue to work, applied to individual buttons within their
   contextual row.
5. **Keyboard-first accessibility**: every toolbar button has a `title` attribute and is
   reachable by Tab / keyboard navigation.
6. **Security**: no behaviour changes to IPC, spawn, or validation layers — this is a pure
   UI/UX refactor.

---

## 1. Current State Audit

### 1.1 HTML — `src/renderer/index.html` (lines 36–163)

```
<header class="glass-panel main-header" style="flex-direction: column; gap: 16px; …">
  <div class="header-top" style="display: flex; …">         ← universal + network mixed
    <div class="header-titles"> Logo + status </div>
    <div class="control-group">                             ← 14 buttons, all workspaces
      Add Hosts · Blacklist · Save · Load · Clear ·
      Settings · Metasploit · RevShell · Cred Spray ·
      Shares · Dir Fuzz · Monitor · Cloud Enum · Exit
    </div>
  </div>
  <div class="header-bottom" style="display: flex; …">     ← network-only filters/views
    Filter inputs · Sort · Result count · Scan-All ·
    VLAN Discovery · Passive Intelligence · View toggles
  </div>
</header>
```

**Problems:**
- 14 buttons in one `control-group`, no semantic sectioning.
- Network-only tools visible in Web App workspace.
- Web App workspace has zero toolbar actions.
- All layout via `style=""` — not themeable or responsive.
- Dir Fuzz is primarily a **web** tool but lives in the network toolbar.
- Workspace switcher bar is below the header (`<nav id="workspace-bar">`), disconnected from
  the logo/status row.

### 1.2 CSS — `src/renderer/style.css`

- `.main-header`, `.header-titles`, `.control-group`, `.divider` — exist, minimal.
- No class for contextual toolbar rows.
- Dependency visibility uses `display: none` toggled by JS — preserved as-is.

### 1.3 CSS — `src/renderer/webapp.css`

- `.workspace-bar`, `.workspace-tab`, `.workspace-tab.active` — the workspace switcher styles.
- Will be absorbed into the universal header row.

### 1.4 JavaScript — workspace switching

`src/renderer/modules/webapp/index.js` → `_initWorkspaceSwitcher()`:
- Reads `.workspace-tab` buttons, sets `state.activeWorkspace`.
- Toggles `#ws-network` / `#ws-webapp` display.
- Does **not** currently toggle header rows.

`src/renderer/modules/init.js`:
- Calls `checkDependency(...)` and applies `.nmap-only` etc visibility.

`src/renderer/modules/settings.js`:
- `applySettingsUI()` re-runs dependency visibility after settings saved.

---

## 2. Target Architecture

```
<header class="glass-panel main-header">

  <!-- ROW 1: Universal — always visible -->
  <div class="header-universal">
    <div class="header-brand">
      <img …/> <h1>NetSpecter</h1> <p id="status-text">…</p>
    </div>

    <!-- Workspace switcher moved here -->
    <nav class="workspace-switcher" aria-label="Workspace">
      <button class="ws-tab active" data-workspace="network"> 🌐 Network </button>
      <button class="ws-tab"        data-workspace="webapp">  🕷️ Web App  </button>
    </nav>

    <div class="header-global-actions">
      <button id="btn-save">Save</button>
      <button id="btn-load">Load</button>
      <div class="h-divider"></div>
      <button id="btn-settings">⚙️ Settings</button>
      <div class="h-divider"></div>
      <button id="btn-exit">Exit</button>
    </div>
  </div>

  <!-- ROW 2a: Network contextual toolbar — shown when workspace = network -->
  <div class="header-contextual header-network" aria-label="Network tools">

    <!-- Group A: Scope management -->
    <div class="toolbar-group" data-group="scope">
      <button id="btn-add-hosts">＋ Add Hosts</button>
      <button id="btn-blacklist">🛡️ Blacklist</button>
      <button id="btn-clear">Clear</button>
    </div>

    <div class="h-divider"></div>

    <!-- Group B: Offensive pentest tools -->
    <div class="toolbar-group" data-group="offense">
      <button id="btn-revshell-open">💻 RevShell</button>
      <button id="btn-credspray-open">🔑 Cred Spray</button>
      <button id="btn-share-enum-open" class="smbclient-only">📂 Shares</button>
      <button id="btn-msf-open"        class="msf-only">💀 Metasploit</button>
    </div>

    <div class="h-divider"></div>

    <!-- Group C: Passive / monitoring -->
    <div class="toolbar-group" data-group="passive">
      <button id="btn-hardening-open">🛡 Monitor</button>
      <button id="btn-cloudenum-open">🐳 Cloud Enum</button>
      <button id="btn-toggle-vlan-panel"    class="tshark-only">🦈 VLAN</button>
      <button id="btn-toggle-passive-panel" class="tshark-only">🕵️ Intel</button>
    </div>

    <div class="h-divider"></div>

    <!-- Group D: Filters + view options -->
    <div class="toolbar-group toolbar-group--filters" data-group="filters">
      <input id="filter-ip"     placeholder="IP…">
      <input id="filter-os"     placeholder="OS…">
      <input id="filter-vendor" placeholder="Vendor…">
      <select id="sort-select">…</select>
      <button id="btn-sort-dir">⬇️</button>
      <span id="result-count-text">…</span>
    </div>

    <!-- Group E: Scan-all + view toggles (right-aligned) -->
    <div class="toolbar-group toolbar-group--right" data-group="view">
      <div id="scan-all-group">…</div>
      <div class="view-toggles">…</div>
    </div>

  </div>

  <!-- ROW 2b: Web App contextual toolbar — shown when workspace = webapp -->
  <div class="header-contextual header-webapp" aria-label="Web App tools" hidden>

    <!-- Group A: Target + proxy -->
    <div class="toolbar-group" data-group="target">
      <input id="webapp-target-url" placeholder="https://target.example.com">
      <button id="btn-proxy-intercept">⏸ Intercept</button>
    </div>

    <div class="h-divider"></div>

    <!-- Group B: Active tools -->
    <div class="toolbar-group" data-group="webtools">
      <button id="btn-webapp-scanner-open">🔬 Scanner</button>
      <button id="btn-webapp-repeater-open">↩ Repeater</button>
      <button id="btn-webapp-intruder-open">⚡ Intruder</button>
      <button id="btn-webapp-dirfuzz-open">🔎 Dir Fuzz</button>
    </div>

    <div class="h-divider"></div>

    <!-- Group C: Session management -->
    <div class="toolbar-group" data-group="session">
      <button id="btn-webapp-history-clear">🗑 Clear History</button>
      <button id="btn-webapp-export-har">⬇ Export HAR</button>
    </div>

    <!-- Group D: Right-aligned status -->
    <div class="toolbar-group toolbar-group--right" data-group="webapp-status">
      <span id="webapp-request-count" class="toolbar-badge">0 requests</span>
      <span id="webapp-finding-count" class="toolbar-badge toolbar-badge--warn">0 findings</span>
    </div>

  </div>

</header>
```

---

## 3. Detailed Implementation Steps

### Step 1 — CSS Design Tokens & New Classes

**File:** `src/renderer/style.css`

#### 3.1.1 New CSS variables (add to `:root`)

```css
/* Header layout */
--header-row-height:    44px;
--toolbar-group-gap:    8px;
--toolbar-divider-w:    1px;
--toolbar-divider-h:    20px;
--toolbar-divider-clr:  rgba(255, 255, 255, 0.08);

/* Contextual toolbar accent colours */
--network-toolbar-accent: rgba(94, 114, 235, 0.06);
--webapp-toolbar-accent:  rgba(139, 92, 246, 0.06);
```

#### 3.1.2 Restructured `.main-header` rule

```css
.main-header {
  display: flex;
  flex-direction: column;
  gap: 0;                   /* rows handle their own padding */
  padding: 0;
  flex-shrink: 0;
  position: relative;
  z-index: 10;
  overflow: visible;
}
```

#### 3.1.3 Universal row

```css
.header-universal {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px 20px;
  border-bottom: 1px solid var(--border-glass);
}

.header-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}

.header-brand img {
  height: 34px;
  width: auto;
  object-fit: contain;
  filter: drop-shadow(0 0 8px rgba(0, 255, 128, 0.4));
}

.header-brand h1 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.5px;
  line-height: 1.2;
}

/* Workspace switcher embedded in universal row */
.workspace-switcher {
  display: flex;
  gap: 4px;
  background: rgba(0, 0, 0, 0.25);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius-sm);
  padding: 3px;
  margin: 0 auto; /* pushes global-actions to the right */
}

.ws-tab {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 14px;
  font-size: 13px;
  font-weight: 500;
  background: transparent;
  border: 1px solid transparent;
  border-radius: calc(var(--radius-sm) - 2px);
  color: var(--text-muted);
  cursor: pointer;
  transition: all var(--transition-fast);
  position: relative;
  -webkit-app-region: no-drag;
}

.ws-tab:hover { color: var(--text-main); background: rgba(255,255,255,0.06); }

.ws-tab.active[data-workspace="network"] {
  background: rgba(94, 114, 235, 0.18);
  border-color: var(--primary);
  color: var(--text-main);
}

.ws-tab.active[data-workspace="webapp"] {
  background: rgba(139, 92, 246, 0.18);
  border-color: var(--webapp-btn);
  color: var(--text-main);
}

.header-global-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}
```

#### 3.1.4 Contextual toolbar row (shared)

```css
.header-contextual {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 20px;
  min-height: var(--header-row-height);
  transition: opacity var(--transition-fast), max-height var(--transition-smooth);
  overflow-x: auto;
  overflow-y: visible;
  scrollbar-width: none;
}

.header-contextual::-webkit-scrollbar { display: none; }

.header-network { background: var(--network-toolbar-accent); }
.header-webapp  { background: var(--webapp-toolbar-accent); }

/* Hide/show contextual rows */
.header-contextual[hidden] {
  display: none;
}
```

#### 3.1.5 Toolbar groups

```css
.toolbar-group {
  display: flex;
  align-items: center;
  gap: var(--toolbar-group-gap);
  flex-shrink: 0;
}

/* Filters group can grow to fill space */
.toolbar-group--filters {
  flex-shrink: 1;
  min-width: 0;
}

/* Right-aligned group pushes to the end */
.toolbar-group--right {
  margin-left: auto;
  flex-shrink: 0;
}

/* Vertical divider between groups */
.h-divider {
  width: var(--toolbar-divider-w);
  height: var(--toolbar-divider-h);
  background: var(--toolbar-divider-clr);
  flex-shrink: 0;
}
```

#### 3.1.6 Toolbar badge (status counters)

```css
.toolbar-badge {
  font-size: 11px;
  font-weight: 600;
  padding: 3px 8px;
  border-radius: 99px;
  background: rgba(255,255,255,0.06);
  border: 1px solid var(--border-glass);
  color: var(--text-muted);
  white-space: nowrap;
}

.toolbar-badge--warn {
  background: rgba(235, 94, 94, 0.12);
  border-color: rgba(235, 94, 94, 0.3);
  color: var(--danger);
}
```

#### 3.1.7 Remove `.workspace-bar` from `webapp.css`

The `<nav id="workspace-bar">` HTML element and `.workspace-bar` / `.workspace-tab` CSS rules
in `webapp.css` are replaced by `.workspace-switcher` / `.ws-tab` inside the universal header
row. Delete those rules from `webapp.css`.

---

### Step 2 — HTML Refactor

**File:** `src/renderer/index.html`

#### 3.2.1 Replace the entire `<header>` block (lines 36–163) and the separate
`<nav id="workspace-bar">` (lines 165–174) with the new structure:

```html
<!-- ── Header ───────────────────────────────────────────────────── -->
<header class="glass-panel main-header">

  <!-- Row 1: Universal — always visible -->
  <div class="header-universal">

    <div class="header-brand">
      <img src="./icon.png" alt="NetSpecter Icon">
      <div>
        <h1>NetSpecter</h1>
        <p class="subtitle" id="status-text">Ready to scan.</p>
      </div>
    </div>

    <nav class="workspace-switcher" aria-label="Workspace">
      <button class="ws-tab active" data-workspace="network" title="Network Scanning Workspace">
        <span class="icon">🌐</span> Network
      </button>
      <button class="ws-tab" data-workspace="webapp" title="Web Application Security Workspace">
        <span class="icon">🕷️</span> Web App
        <span id="proxy-intercept-badge" class="intercept-badge" style="display:none;"></span>
      </button>
    </nav>

    <div class="header-global-actions">
      <button id="btn-save"     class="btn secondary">Save</button>
      <button id="btn-load"     class="btn secondary">Load</button>
      <div class="h-divider"></div>
      <button id="btn-settings" class="btn secondary" title="Settings">
        <span class="icon">⚙️</span> Settings
      </button>
      <div class="h-divider"></div>
      <button id="btn-exit"     class="btn danger-outline">Exit</button>
    </div>

  </div><!-- /.header-universal -->

  <!-- ── Row 2a: Network contextual toolbar ──────────────────────── -->
  <div class="header-contextual header-network" id="toolbar-network" role="toolbar"
       aria-label="Network workspace tools">

    <!-- A: Scope management -->
    <div class="toolbar-group" data-group="scope">
      <button id="btn-add-hosts" class="btn primary" title="Add hosts to scan">
        <span class="icon">＋</span> Add Hosts
      </button>
      <button id="btn-blacklist" class="btn secondary" title="Manage Out-of-Scope Blacklist">
        <span class="icon">🛡️</span> Blacklist
      </button>
      <button id="btn-clear" class="btn secondary" title="Clear all discovered hosts">
        Clear
      </button>
    </div>

    <div class="h-divider"></div>

    <!-- B: Offensive pentest tools -->
    <div class="toolbar-group" data-group="offense">
      <button id="btn-revshell-open" class="btn pentest" title="Reverse Shell Listener">
        <span class="icon">💻</span> RevShell
      </button>
      <button id="btn-credspray-open" class="btn pentest" title="Default Credential Spray">
        <span class="icon">🔑</span> Cred Spray
      </button>
      <button id="btn-share-enum-open" class="btn pentest smbclient-only"
              title="SMB/NFS Share Enumeration" style="display:none;">
        <span class="icon">📂</span> Shares
      </button>
      <button id="btn-msf-open" class="btn pentest msf-only"
              title="Metasploit RPC" style="display:none;">
        <span class="icon">💀</span> Metasploit
      </button>
    </div>

    <div class="h-divider"></div>

    <!-- C: Passive / monitoring -->
    <div class="toolbar-group" data-group="passive">
      <button id="btn-hardening-open" class="btn hardening"
              title="Hardening Monitor — Continuous Delta Monitoring">
        <span class="icon">🛡</span> Monitor
        <span id="hardening-alert-badge" class="hardening-badge" style="display:none;"></span>
      </button>
      <button id="btn-cloudenum-open" class="btn cloudenum"
              title="Container &amp; Cloud Enumeration">
        <span class="icon">🐳</span> Cloud Enum
        <span id="cloudenum-finding-badge" class="cloudenum-badge" style="display:none;"></span>
      </button>
      <button id="btn-toggle-vlan-panel" class="btn secondary tshark-only"
              title="VLAN Discovery" style="display:none;">
        <span class="icon">🦈</span> VLAN
      </button>
      <button id="btn-toggle-passive-panel" class="btn secondary tshark-only"
              title="Passive Intelligence" style="display:none;">
        <span class="icon">🕵️</span> Intel
      </button>
    </div>

    <div class="h-divider"></div>

    <!-- D: Filters -->
    <div class="toolbar-group toolbar-group--filters" data-group="filters">
      <input type="text" id="filter-ip"     class="text-input" placeholder="IP…">
      <input type="text" id="filter-os"     class="text-input" placeholder="OS…">
      <input type="text" id="filter-vendor" class="text-input" placeholder="Vendor…">
      <div class="h-divider"></div>
      <select id="sort-select" class="dropdown-select">
        <option value="ip">Sort IP</option>
        <option value="os">Sort OS</option>
        <option value="vendor">Sort Vendor</option>
      </select>
      <button id="btn-sort-dir" class="btn secondary icon-only"
              title="Toggle Sort Direction" data-dir="asc">⬇️</button>
      <div class="h-divider"></div>
      <span class="subtitle" id="result-count-text">Showing 0 of 0 hosts</span>
    </div>

    <!-- E: Scan-all + view toggles (right-aligned) -->
    <div class="toolbar-group toolbar-group--right" data-group="view">

      <div id="scan-all-group" class="scan-all-group" style="display:none;">
        <button id="btn-deep-scan-all" class="btn info scan-all-main"
                title="Run selected scan type against all visible hosts">
          <span class="icon">⚡</span>
          <span id="scan-all-label">Deep Scan All</span>
        </button>
        <button id="btn-scan-all-menu" class="btn info scan-all-toggle"
                title="Choose scan type">▾</button>
        <div id="scan-all-dropdown" class="scan-all-dropdown hidden">
          <button class="scan-all-option active"
                  data-scan-type="native" data-label="Deep Scan All">
            <span class="icon">⚡</span> Native Deep Scan
          </button>
          <button class="scan-all-option nmap-only"
                  data-scan-type="nmap-host" data-label="Nmap Host Scan All"
                  style="display:none;">
            <span class="icon">🖥️</span> Nmap Host Scan
          </button>
          <button class="scan-all-option nmap-only"
                  data-scan-type="nmap-vuln" data-label="Nmap Vuln Scan All"
                  style="display:none;">
            <span class="icon">🛡️</span> Nmap Vuln Scan
          </button>
          <button class="scan-all-option nmap-only"
                  data-scan-type="nmap-deep" data-label="Nmap Deep Scan All"
                  style="display:none;">
            <span class="icon">☢️</span> Nmap Deep Scan
          </button>
        </div>
      </div>

      <div class="view-toggles">
        <button id="btn-view-grid"     class="btn icon-only active" title="Grid View">⏹️</button>
        <button id="btn-view-list"     class="btn icon-only"        title="List View">☰</button>
        <button id="btn-view-table"    class="btn icon-only"        title="Table View">🗄️</button>
        <button id="btn-view-topology" class="btn icon-only"        title="Topology View">📡</button>
      </div>

    </div>

  </div><!-- /#toolbar-network -->

  <!-- ── Row 2b: Web App contextual toolbar ──────────────────────── -->
  <div class="header-contextual header-webapp" id="toolbar-webapp" role="toolbar"
       aria-label="Web App workspace tools" hidden>

    <!-- A: Target + proxy control -->
    <div class="toolbar-group" data-group="target">
      <input type="url" id="webapp-target-url" class="text-input text-input--wide"
             placeholder="https://target.example.com" title="Active target URL">
      <button id="btn-proxy-intercept" class="btn webapp intercept-off"
              title="Toggle proxy intercept (pause/forward requests)">
        <span class="icon">⏸</span> Intercept
      </button>
    </div>

    <div class="h-divider"></div>

    <!-- B: Active analysis tools -->
    <div class="toolbar-group" data-group="webtools">
      <button id="btn-webapp-scanner-open" class="btn webapp"
              title="Active Vulnerability Scanner">
        <span class="icon">🔬</span> Scanner
        <span id="webapp-vuln-badge" class="toolbar-vuln-badge" style="display:none;"></span>
      </button>
      <button id="btn-webapp-repeater-open" class="btn webapp"
              title="HTTP Repeater — manually craft &amp; resend requests">
        <span class="icon">↩</span> Repeater
      </button>
      <button id="btn-webapp-intruder-open" class="btn webapp"
              title="Intruder — automated attack campaigns">
        <span class="icon">⚡</span> Intruder
      </button>
      <button id="btn-webapp-dirfuzz-open" class="btn webapp"
              title="Web Directory Fuzzer">
        <span class="icon">🔎</span> Dir Fuzz
      </button>
    </div>

    <div class="h-divider"></div>

    <!-- C: Session management -->
    <div class="toolbar-group" data-group="session">
      <button id="btn-webapp-history-clear" class="btn secondary"
              title="Clear all captured proxy history">
        <span class="icon">🗑</span> Clear History
      </button>
      <button id="btn-webapp-export-har" class="btn secondary"
              title="Export captured history as HAR 1.2 file">
        <span class="icon">⬇</span> Export HAR
      </button>
    </div>

    <!-- D: Right-aligned live counters -->
    <div class="toolbar-group toolbar-group--right" data-group="webapp-status">
      <span id="webapp-request-count" class="toolbar-badge" title="Captured requests">
        0 requests
      </span>
      <span id="webapp-finding-count" class="toolbar-badge toolbar-badge--warn"
            title="Open vulnerability findings" style="display:none;">
        0 findings
      </span>
    </div>

  </div><!-- /#toolbar-webapp -->

</header>
<!-- ── (workspace-bar <nav> REMOVED — switcher is now in .header-universal) ── -->
```

---

### Step 3 — JavaScript: Workspace Switcher Refactor

**File:** `src/renderer/modules/webapp/index.js`

#### 3.3.1 Update `_initWorkspaceSwitcher()`

The switcher now reads `.ws-tab` (not `.workspace-tab`), and additionally shows/hides the two
contextual toolbar rows:

```js
function _initWorkspaceSwitcher() {
  const tabs        = document.querySelectorAll('.ws-tab');
  const networkWs   = document.getElementById('ws-network');
  const webappWs    = document.getElementById('ws-webapp');
  const netToolbar  = document.getElementById('toolbar-network');
  const webToolbar  = document.getElementById('toolbar-webapp');

  if (!tabs.length || !networkWs) return;

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const ws = tab.dataset.workspace;
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeWorkspace = ws;

      const isNetwork = ws === 'network';

      networkWs.style.display = isNetwork ? '' : 'none';
      networkWs.classList.toggle('active', isNetwork);

      if (webappWs) {
        webappWs.style.display = isNetwork ? 'none' : '';
        webappWs.classList.toggle('active', !isNetwork);
      }

      // Toggle contextual toolbars
      netToolbar.hidden = !isNetwork;
      webToolbar.hidden =  isNetwork;
    });
  });
}
```

#### 3.3.2 Dir Fuzz pivot in Web App toolbar

The new `#btn-webapp-dirfuzz-open` in the Web App toolbar opens the **Web App** dir fuzz panel
(already managed by `src/renderer/modules/webapp/dirfuzz.js` if it exists, otherwise by
`dirFuzz.js` module with the web-workspace mode flag set). The network-side Dir Fuzz button in
host details continues to fire `window.__openDirFuzzPanel(url)` which sets the active workspace
to `webapp` first.

Update `window.__openDirFuzzPanel(url)`:

```js
window.__openDirFuzzPanel = (url) => {
  // Switch to Web App workspace first
  document.querySelector('.ws-tab[data-workspace="webapp"]')?.click();
  // Then open the dir fuzz panel within the webapp sidebar
  document.querySelector('#webapp-sidebar [data-panel="dirfuzz"]')?.click();
  if (url) document.getElementById('webapp-target-url').value = url;
};
```

---

### Step 4 — JavaScript: Init Module Updates

**File:** `src/renderer/modules/init.js`

No structural changes required. The dependency-toggle helpers (`syncDependencyToggle`,
`applySettingsUI`) that set `el.style.display = 'none'` / `''` on `.nmap-only`, `.tshark-only`
etc. continue to work unchanged because those CSS classes are still applied to the same button
elements — just in a different parent container.

**Verify** that `applySettingsUI()` does not hard-code the old `.control-group` selector.
If it does, update it to use `document.querySelectorAll('[class*="-only"]')` or the
individual class selectors directly (preferred).

---

### Step 5 — Web App Toolbar: New Button Wiring

**File:** `src/renderer/modules/webapp/index.js`

Add a new private function `_initWebToolbar()` called from the module's `init()`:

```js
function _initWebToolbar() {
  // Scanner button → open scanner panel via sidebar
  document.getElementById('btn-webapp-scanner-open')
    ?.addEventListener('click', () => {
      document.querySelector('#webapp-sidebar [data-panel="scanner"]')?.click();
    });

  // Repeater button → open repeater panel via sidebar
  document.getElementById('btn-webapp-repeater-open')
    ?.addEventListener('click', () => {
      document.querySelector('#webapp-sidebar [data-panel="repeater"]')?.click();
    });

  // Intruder button → open intruder panel via sidebar
  document.getElementById('btn-webapp-intruder-open')
    ?.addEventListener('click', () => {
      document.querySelector('#webapp-sidebar [data-panel="intruder"]')?.click();
    });

  // Dir Fuzz button → open dirfuzz panel via sidebar
  document.getElementById('btn-webapp-dirfuzz-open')
    ?.addEventListener('click', () => {
      document.querySelector('#webapp-sidebar [data-panel="dirfuzz"]')?.click();
    });

  // Clear history
  document.getElementById('btn-webapp-history-clear')
    ?.addEventListener('click', () => {
      if (confirm('Clear all captured proxy history? This cannot be undone.')) {
        window.electronAPI.proxy.clearHistory?.();
      }
    });

  // Export HAR
  document.getElementById('btn-webapp-export-har')
    ?.addEventListener('click', () => {
      window.electronAPI.proxy.exportHar?.();
    });
}
```

#### 5.1 Intercept Toggle Button State

The proxy module (`src/renderer/modules/webapp/proxy.js`) already manages intercept state.
It should additionally reflect state in the new toolbar button:

```js
// Inside proxy.js, wherever intercept toggle is handled:
function _syncInterceptBtn(isActive) {
  const btn = document.getElementById('btn-proxy-intercept');
  if (!btn) return;
  btn.classList.toggle('intercept-on',  isActive);
  btn.classList.toggle('intercept-off', !isActive);
  btn.querySelector('.icon').textContent = isActive ? '⏹' : '⏸';
  btn.title = isActive
    ? 'Intercept ON — click to forward all requests'
    : 'Intercept OFF — click to start intercepting';
}
```

Add CSS to `webapp.css`:

```css
.btn.webapp.intercept-on {
  background: rgba(239, 68, 68, 0.2);
  border-color: var(--intercept-active);
  color: var(--intercept-active);
  animation: intercept-pulse 1.5s ease infinite;
}

@keyframes intercept-pulse {
  0%, 100% { box-shadow: 0 0 0 0   var(--intercept-pulse); }
  50%       { box-shadow: 0 0 0 6px transparent; }
}
```

#### 5.2 Live Counters

```js
// Call from proxy.js whenever history changes:
function _updateRequestCount(n) {
  const el = document.getElementById('webapp-request-count');
  if (el) el.textContent = `${n} request${n !== 1 ? 's' : ''}`;
}

// Call from scanner.js whenever findings change:
function _updateFindingCount(n) {
  const el = document.getElementById('webapp-finding-count');
  if (!el) return;
  el.style.display = n > 0 ? '' : 'none';
  el.textContent   = `${n} finding${n !== 1 ? 's' : ''}`;
}
```

---

### Step 6 — Web App Sidebar: Add Dir Fuzz Entry

The Web App sidebar (`#webapp-sidebar` in `index.html`) currently has entries for:
Proxy, Sitemap, Scanner, Repeater, Intruder, Sequencer, Decoder, Comparer.

**Add a Dir Fuzz sidebar entry** so the toolbar button has a target panel to activate:

```html
<!-- Inside #webapp-sidebar, after Scanner -->
<button class="sidebar-item" data-panel="dirfuzz" title="Web Directory Fuzzer">
  <span class="icon">🔎</span>
  <span class="sidebar-label">Dir Fuzz</span>
</button>
```

```html
<!-- Inside #webapp-main, a new panel -->
<div id="webapp-panel-dirfuzz" class="webapp-panel" style="display:none;">
  <!-- Reuse the existing dirfuzz panel contents or embed via JS init -->
</div>
```

**Note:** The existing Dir Fuzz implementation (`src/main/dirFuzzer.js`) is workspace-agnostic.
The Web App sidebar panel wraps the same IPC calls. The network workspace no longer shows a
"Dir Fuzz" toolbar button — the tool is accessed via the Web App toolbar or via the host details
"Dir Fuzz" quick-action (which pivots to the Web App workspace).

---

### Step 7 — Remove Old `<nav id="workspace-bar">`

**File:** `src/renderer/index.html`

Delete the `<nav id="workspace-bar">` element entirely — the workspace switcher now lives inside
`.header-universal`.

**File:** `src/renderer/webapp.css`

Remove the `.workspace-bar`, `.workspace-tab`, `.workspace-tab:hover`, `.workspace-tab.active`
rule blocks (approximately lines 24–61).

---

### Step 8 — Save / Load Scope Clarification

Currently **Save** and **Load** serialise and restore the network host list only. Once the Web
App workspace has session data (proxy history, findings), Save/Load should be
workspace-aware or offer a unified project file.

**Short-term (this refactor):**
- Save / Load remain in the universal row.
- In the Web App workspace, Save serialises both network hosts + web proxy history + findings.
- The IPC handler `FILE_SAVE` / `FILE_LOAD` is extended (separate ticket / future step).
- Document this gap in `docs/HEADER_PLAN.md` (this section).

**Long-term:**
- Introduce a **Project** concept: a single JSON file that contains both workspaces' state.
- The universal **Save** writes the project file; **Load** restores it.

---

### Step 9 — Target URL Input: Network → Web App Integration

The new `#webapp-target-url` input in the Web App toolbar serves as the single source of truth
for what the user is testing. Integrate it across modules:

1. **Proxy module** (`proxy.js`): When proxy intercepts a request, extract its origin and
   populate `#webapp-target-url` if empty.
2. **Scanner module** (`scanner.js`): Pre-populate target with `#webapp-target-url` value when
   the user opens Scanner in "URL" mode.
3. **Sitemap module** (`sitemap.js`): Use `#webapp-target-url` as the seed URL when the user
   clicks "Map Site".
4. **Network pivot**: `window.__openScannerPanel(url)` already sets target; also set
   `#webapp-target-url` value at the same time.

```js
// In webapp/index.js _initWebToolbar():
document.getElementById('webapp-target-url')?.addEventListener('change', (e) => {
  state.webAppTargetUrl = e.target.value.trim();
  // Notify sub-modules
  document.dispatchEvent(new CustomEvent('webapp:targetChanged',
    { detail: { url: state.webAppTargetUrl } }));
});
```

---

### Step 10 — Accessibility & Drag Region

The `titlebar-drag-region` overlay (`height: 35px`) sits above everything. Toolbar buttons must
be `-webkit-app-region: no-drag` to remain clickable.

Add to the shared rule:

```css
.header-universal *,
.header-contextual * {
  -webkit-app-region: no-drag;
}
```

The drag region is preserved — the transparent overlay only covers 35px at the top, which is
above the header content area.

---

### Step 11 — Responsive / Overflow Handling

If the window is too narrow for all toolbar buttons:

```css
.header-contextual {
  overflow-x: auto;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,0.1) transparent;
}
```

For very narrow widths, add optional icon-only mode for toolbar buttons:

```css
@media (max-width: 1100px) {
  .toolbar-group[data-group="offense"] .btn span:not(.icon),
  .toolbar-group[data-group="passive"] .btn span:not(.icon) {
    display: none;
  }
}
```

---

## 4. File-by-File Change Summary

| File | Change type | Description |
|------|-------------|-------------|
| `src/renderer/index.html` | Major refactor | Replace `<header>` + `<nav#workspace-bar>` with new two-row header |
| `src/renderer/style.css` | Additions | New CSS vars + `.header-universal`, `.header-contextual`, `.header-network`, `.header-webapp`, `.toolbar-group`, `.h-divider`, `.ws-tab`, `.toolbar-badge` rules; remove old `.main-header` inline-style-equivalent rules |
| `src/renderer/webapp.css` | Deletions | Remove `.workspace-bar`, `.workspace-tab` rules; add `.intercept-on` animation, `.toolbar-vuln-badge` |
| `src/renderer/modules/webapp/index.js` | Modification | Update `_initWorkspaceSwitcher()` to use `.ws-tab` and toggle `#toolbar-network` / `#toolbar-webapp`; add `_initWebToolbar()` |
| `src/renderer/modules/webapp/proxy.js` | Addition | `_syncInterceptBtn()`, `_updateRequestCount()` |
| `src/renderer/modules/webapp/scanner.js` | Addition | `_updateFindingCount()` |
| `src/renderer/modules/init.js` | Verify | Confirm dependency-toggle selectors do not rely on old parent container |
| `src/renderer/modules/dirFuzz.js` | Modification | Remove `#btn-dirfuzz-open` binding from network context; add `#btn-webapp-dirfuzz-open` binding in web context |
| `src/renderer/state.js` | Addition | `webAppTargetUrl: ''` field |

---

## 5. Testing Plan

### 5.1 Unit Tests

**File:** `test/renderer/header.test.js` (new)

```
describe('Workspace-aware header')
  ✓ Clicking Network tab shows #toolbar-network, hides #toolbar-webapp
  ✓ Clicking Web App tab shows #toolbar-webapp, hides #toolbar-network
  ✓ Network tab active class applied correctly
  ✓ Web App tab active class applied correctly
  ✓ state.activeWorkspace updated on tab click
  ✓ .nmap-only buttons remain hidden when nmap not installed
  ✓ .smbclient-only buttons remain hidden when smbclient not installed
  ✓ .tshark-only buttons remain hidden when tshark not installed
  ✓ .msf-only buttons remain hidden when msf not installed

describe('Web App toolbar')
  ✓ #btn-webapp-scanner-open activates scanner sidebar panel
  ✓ #btn-webapp-repeater-open activates repeater sidebar panel
  ✓ #btn-webapp-intruder-open activates intruder sidebar panel
  ✓ #btn-webapp-dirfuzz-open activates dirfuzz sidebar panel
  ✓ #btn-proxy-intercept toggles .intercept-on class
  ✓ _updateRequestCount() updates #webapp-request-count text
  ✓ _updateFindingCount(0) hides #webapp-finding-count
  ✓ _updateFindingCount(3) shows #webapp-finding-count with "3 findings"

describe('Network toolbar')
  ✓ #btn-add-hosts visible when network workspace active
  ✓ #btn-add-hosts not in DOM when checking webapp toolbar
  ✓ All network action buttons present and have title attributes

describe('Dir Fuzz pivot')
  ✓ window.__openDirFuzzPanel(url) switches workspace to webapp
  ✓ window.__openDirFuzzPanel(url) populates #webapp-target-url
  ✓ window.__openDirFuzzPanel(url) activates dirfuzz sidebar panel
```

### 5.2 Visual / Manual Checklist

- [ ] Launch app → header shows Network toolbar by default
- [ ] Switch to Web App → only web toolbar visible, no RevShell/Cred Spray etc.
- [ ] Switch back to Network → full network toolbar restored
- [ ] Install-state: disable nmap → `.nmap-only` buttons absent in network toolbar
- [ ] Install-state: enable tshark → VLAN + Intel buttons appear in network toolbar
- [ ] Window resize to 1024px → toolbar buttons scroll horizontally without layout break
- [ ] Window resize to 800px → icon-only mode active for offense/passive groups
- [ ] Proxy intercept ON → button pulses red; OFF → normal appearance
- [ ] Dir Fuzz from host details port → switches to Web App workspace; `#webapp-target-url` populated
- [ ] Save button in universal row → works from both workspaces
- [ ] Settings button in universal row → modal opens from both workspaces
- [ ] Exit button → confirmation dialog (existing behaviour preserved)
- [ ] Tab navigation: Tab key cycles through all toolbar buttons in logical order
- [ ] Titlebar drag region: window can be dragged by clicking empty area above toolbar

### 5.3 Regression Tests

Run the full test suite after changes:

```bash
npm test
```

Expected: all 536+ existing tests pass unchanged (this is a renderer HTML/CSS/JS refactor with
no changes to main process IPC handlers, spawn logic, or data models).

---

## 6. Migration Notes & Risks

| Risk | Mitigation |
|------|-----------|
| Button IDs renamed | All button IDs are **preserved** (`#btn-add-hosts` etc). Only their parent container changes. |
| `.workspace-tab` selector used in tests | Update to `.ws-tab` in any test that queries by that class |
| `proxy-intercept-badge` moved | ID preserved, now a child of `.ws-tab[data-workspace="webapp"]` — ensure proxy.js references by ID not by parent traversal |
| Dir Fuzz removed from network toolbar | Existing network-host "Dir Fuzz" quick-action remains; it calls `window.__openDirFuzzPanel()` which pivots to web workspace |
| Save/Load universal row placement | No IPC changes; existing `#btn-save` / `#btn-load` IDs preserved |
| Web App sidebar needs Dir Fuzz entry | Add `data-panel="dirfuzz"` sidebar item + matching panel container |

---

## 7. Future Extensibility

The new architecture makes it trivial to add:

1. **New workspace** (e.g., "Bluetooth", "RF", "OSINT"):
   - Add a `.ws-tab` button with a new `data-workspace` value.
   - Add a corresponding `<div class="header-contextual header-{ws}" id="toolbar-{ws}" hidden>`.
   - Add `<div id="ws-{ws}" class="workspace-container">` for the main content area.
   - The `_initWorkspaceSwitcher()` function handles any number of tabs by iterating all
     `.ws-tab` elements.

2. **New network tool** (e.g., "SNMP Walker"):
   - Add a `<button>` to `toolbar-group[data-group="offense"]` or a new group within
     `#toolbar-network`.
   - Apply the appropriate dependency CSS class (e.g., `.snmpwalk-only`).
   - Wire the button in the relevant module's `init()`.

3. **New web tool** (e.g., "JWT Analyzer"):
   - Add a `<button>` to `toolbar-group[data-group="webtools"]` within `#toolbar-webapp`.
   - Add a `data-panel="jwt"` sidebar item + panel.
   - Wire in `_initWebToolbar()`.

4. **Collapsible toolbar**:
   - `.header-contextual` already has a smooth height transition.
   - A single "collapse toolbar" button in `.header-universal` can toggle a
     `.toolbar-collapsed` class that sets `max-height: 0; padding: 0; overflow: hidden`.

5. **Toolbar customisation / persistence**:
   - Each `toolbar-group` has a `data-group` attribute — user-preferred group visibility
     can be stored in `electron-store` keyed by `data-group` value.

---

## 8. Acceptance Criteria

- [ ] The header has exactly two rows: universal (always visible) and contextual (workspace-aware).
- [ ] The workspace switcher is embedded in the universal row (not a separate `<nav>` below the header).
- [ ] Switching workspaces shows/hides the correct contextual toolbar with no flicker.
- [ ] All previously accessible features remain accessible in their workspace context.
- [ ] Dir Fuzz is accessible from the Web App toolbar; the network host-card shortcut pivots correctly.
- [ ] No inline `style=""` attributes remain on structural layout elements (only on elements
      controlled by JS show/hide logic such as `.nmap-only`, `.smbclient-only` etc.).
- [ ] All button `id` attributes are preserved (no ID regressions).
- [ ] All 536+ existing Vitest tests pass.
- [ ] New header unit tests achieve ≥ 80 % coverage of the new HTML/JS interactions.
- [ ] Manual checklist above is fully green.

---

*Plan authored: 2026-03-15*
