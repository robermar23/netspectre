import { api } from '../api.js';

function escapeHtml(unsafe) {
  if (unsafe == null) return '';
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

const msfModalOverlay = document.getElementById('msf-modal-overlay');
const btnCloseMsfModal = document.getElementById('btn-close-msf-modal');
const msfStatusDot = document.getElementById('msf-status-dot');
const msfStatusLabel = document.getElementById('msf-status-label');
const msfHostLabel = document.getElementById('msf-host-label');
const msfHost = document.getElementById('msf-host');
const msfPort = document.getElementById('msf-port');
const msfUsername = document.getElementById('msf-username');
const msfPassword = document.getElementById('msf-password');
const msfSsl = document.getElementById('msf-ssl');
const btnMsfConnect = document.getElementById('btn-msf-connect');
const btnMsfDisconnect = document.getElementById('btn-msf-disconnect');
const msfRemoteWarning = document.getElementById('msf-remote-warning');
const msfExploitSearch = document.getElementById('msf-exploit-search');
const btnMsfSearch = document.getElementById('btn-msf-search');
const msfExploitTbody = document.getElementById('msf-exploit-tbody');
const msfSessionsContainer = document.getElementById('msf-sessions-container');
const btnMsfRefreshSessions = document.getElementById('btn-msf-refresh-sessions');
const msfErrorDisplay = document.getElementById('msf-error-display');

const msfRunModalOverlay = document.getElementById('msf-run-modal-overlay');
const btnCloseMsfRunModal = document.getElementById('btn-close-msf-run-modal');
const msfRunModule = document.getElementById('msf-run-module');
const msfRunTargetIp = document.getElementById('msf-run-target-ip');
const msfRunTargetPort = document.getElementById('msf-run-target-port');
const msfRunPayload = document.getElementById('msf-run-payload');
const msfRunLhost = document.getElementById('msf-run-lhost');
const msfRunLport = document.getElementById('msf-run-lport');
const btnMsfRunExecute = document.getElementById('btn-msf-run-execute');
const btnMsfRunCancel = document.getElementById('btn-msf-run-cancel');

let msfConnected = false;

function showMsfError(msg) {
  if (!msfErrorDisplay) return;
  msfErrorDisplay.textContent = msg;
  msfErrorDisplay.style.display = 'block';
  setTimeout(() => { msfErrorDisplay.style.display = 'none'; }, 8000);
}

function clearMsfError() {
  if (msfErrorDisplay) msfErrorDisplay.style.display = 'none';
}

function updateMsfStatusUI(statusState, label) {
  if (msfStatusDot) {
    msfStatusDot.className = `msf-status-dot ${statusState}`;
  }
  if (msfStatusLabel) {
    msfStatusLabel.textContent = label || statusState.charAt(0).toUpperCase() + statusState.slice(1);
  }
}

function setMsfConnectedState(connected, host, port) {
  msfConnected = connected;
  if (connected) {
    updateMsfStatusUI('connected', 'Connected');
    if (msfHostLabel) msfHostLabel.textContent = `${host}:${port}`;
    if (btnMsfConnect) btnMsfConnect.style.display = 'none';
    if (btnMsfDisconnect) btnMsfDisconnect.style.display = '';
    if (msfExploitSearch) msfExploitSearch.disabled = false;
    if (btnMsfSearch) btnMsfSearch.disabled = false;
    if (btnMsfRefreshSessions) btnMsfRefreshSessions.disabled = false;
    [msfHost, msfPort, msfUsername, msfPassword, msfSsl].forEach(el => {
      if (el) el.disabled = true;
    });
  } else {
    updateMsfStatusUI('disconnected', 'Disconnected');
    if (msfHostLabel) msfHostLabel.textContent = '';
    if (btnMsfConnect) btnMsfConnect.style.display = '';
    if (btnMsfDisconnect) btnMsfDisconnect.style.display = 'none';
    if (msfExploitSearch) msfExploitSearch.disabled = true;
    if (btnMsfSearch) btnMsfSearch.disabled = true;
    if (btnMsfRefreshSessions) btnMsfRefreshSessions.disabled = true;
    [msfHost, msfPort, msfUsername, msfPassword, msfSsl].forEach(el => {
      if (el) el.disabled = false;
    });
  }
}

export function openModal() {
  clearMsfError();
  msfModalOverlay?.classList.remove('hidden');
}

function closeMsfModal() {
  msfModalOverlay?.classList.add('hidden');
}

export function openRunExploitModal(modulePath, targetIp) {
  clearMsfError();
  if (msfRunModule) msfRunModule.value = modulePath;
  if (msfRunTargetIp) msfRunTargetIp.value = targetIp || '';
  if (msfRunTargetPort) msfRunTargetPort.value = '';
  if (msfRunPayload) msfRunPayload.value = '';
  if (msfRunLhost) msfRunLhost.value = '';
  if (msfRunLport) msfRunLport.value = '4444';
  msfRunModalOverlay?.classList.remove('hidden');
}

async function searchMsfExploits() {
  const query = (msfExploitSearch?.value || '').trim();
  if (!query) return;
  if (!msfConnected) {
    showMsfError('Not connected to Metasploit RPC');
    return;
  }

  clearMsfError();
  msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">Searching...</td></tr>';

  try {
    const result = await api.msfListExploits(query);
    if (result.status === 'error') {
      showMsfError(result.error);
      msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--danger); padding: 24px;">Search failed</td></tr>';
      return;
    }

    const exploits = result.exploits || [];
    if (exploits.length === 0) {
      msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">No results found</td></tr>';
      return;
    }

    msfExploitTbody.innerHTML = '';
    exploits.slice(0, 100).forEach(mod => {
      const row = document.createElement('tr');
      const rankClass = (mod.rank || 'normal').toLowerCase();
      row.innerHTML = `
        <td style="font-family: monospace; font-size: 10px;" title="${escapeHtml(mod.fullname)}">${escapeHtml(mod.fullname || mod.name)}</td>
        <td><span class="msf-rank ${escapeHtml(rankClass)}">${escapeHtml(mod.rank)}</span></td>
        <td style="font-size: 10px; color: var(--text-muted);">${escapeHtml(mod.date)}</td>
        <td style="font-size: 10px;" title="${escapeHtml(mod.description)}">${escapeHtml((mod.description || '').substring(0, 80))}${(mod.description || '').length > 80 ? '...' : ''}</td>
        <td><button class="btn-msf-run" data-module="${escapeHtml(mod.fullname || mod.name)}">Run</button></td>
      `;
      msfExploitTbody.appendChild(row);
    });
  } catch (err) {
    showMsfError(err.message);
    msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--danger); padding: 24px;">Search error</td></tr>';
  }
}

async function refreshMsfSessions() {
  if (!msfConnected) return;
  try {
    const result = await api.msfSessionList();
    if (result.status === 'error') {
      showMsfError(result.error);
      return;
    }

    const sessions = result.sessions || [];
    if (sessions.length === 0) {
      msfSessionsContainer.innerHTML = '<div class="ds-record" style="text-align:center; color: var(--text-muted); opacity: 0.7; padding: 24px;">No active sessions</div>';
      return;
    }

    msfSessionsContainer.innerHTML = '';
    sessions.forEach(sess => {
      const card = document.createElement('div');
      card.className = 'msf-session-card';
      card.innerHTML = `
        <div class="session-header">
          <span class="session-id">Session #${escapeHtml(sess.id)}</span>
          <span class="session-type">${escapeHtml(sess.type)}</span>
        </div>
        <div class="session-details">
          <span><strong>Target:</strong> ${escapeHtml(sess.target)}${sess.port ? ':' + escapeHtml(sess.port) : ''}</span>
          <span><strong>Platform:</strong> ${escapeHtml(sess.platform || 'unknown')}</span>
          <span><strong>Via:</strong> ${escapeHtml(sess.via || 'n/a')}</span>
          ${sess.info ? `<span><strong>Info:</strong> ${escapeHtml(sess.info)}</span>` : ''}
        </div>
      `;
      msfSessionsContainer.appendChild(card);
    });
  } catch (err) {
    showMsfError(err.message);
  }
}

export function init() {
  btnCloseMsfModal?.addEventListener('click', closeMsfModal);
  msfModalOverlay?.addEventListener('click', (e) => {
    if (e.target === msfModalOverlay) closeMsfModal();
  });

  // MSF Tab Switching
  document.querySelectorAll('[data-msf-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('[data-msf-tab]').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.msf-tab-pane').forEach(p => p.style.display = 'none');
      tab.classList.add('active');
      const pane = document.getElementById(`msf-tab-${tab.getAttribute('data-msf-tab')}`);
      if (pane) pane.style.display = 'block';
    });
  });

  // Non-localhost Warning
  msfHost?.addEventListener('input', () => {
    const val = (msfHost.value || '').trim();
    const isLocal = val === '127.0.0.1' || val === 'localhost' || val === '::1' || val === '';
    if (msfRemoteWarning) msfRemoteWarning.style.display = isLocal ? 'none' : 'block';
  });

  // Connect
  btnMsfConnect?.addEventListener('click', async () => {
    clearMsfError();
    const host = (msfHost?.value || '127.0.0.1').trim();
    const port = parseInt(msfPort?.value || '55553', 10);
    const username = (msfUsername?.value || 'msf').trim();
    const password = msfPassword?.value || '';
    const ssl = msfSsl?.checked || false;

    if (!password) {
      showMsfError('Password is required');
      msfPassword?.focus();
      return;
    }

    updateMsfStatusUI('connecting', 'Connecting...');
    btnMsfConnect.disabled = true;

    try {
      const result = await api.msfConnect({ host, port, username, password, ssl });
      if (result.status === 'error') {
        updateMsfStatusUI('error', 'Connection Failed');
        showMsfError(result.error || 'Failed to connect');
        btnMsfConnect.disabled = false;
      } else {
        setMsfConnectedState(true, host, port);
        if (result.warning) showMsfError(result.warning);
        refreshMsfSessions();
      }
    } catch (err) {
      updateMsfStatusUI('error', 'Connection Failed');
      showMsfError(err.message || 'Failed to connect');
      btnMsfConnect.disabled = false;
    }
  });

  // Disconnect
  btnMsfDisconnect?.addEventListener('click', async () => {
    clearMsfError();
    try {
      await api.msfDisconnect();
    } catch (_) { /* ignore */ }
    setMsfConnectedState(false);
    btnMsfConnect.disabled = false;
    msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">Connect to msfrpcd and search for exploits</td></tr>';
    msfSessionsContainer.innerHTML = '<div class="ds-record" style="text-align:center; color: var(--text-muted); opacity: 0.7; padding: 24px;">No active sessions</div>';
  });

  // Exploit Search
  let msfSearchTimeout = null;
  btnMsfSearch?.addEventListener('click', searchMsfExploits);
  msfExploitSearch?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      clearTimeout(msfSearchTimeout);
      searchMsfExploits();
    }
  });
  msfExploitSearch?.addEventListener('input', () => {
    clearTimeout(msfSearchTimeout);
    msfSearchTimeout = setTimeout(searchMsfExploits, 600);
  });

  // Run Exploit from search table
  msfExploitTbody?.addEventListener('click', (e) => {
    const btn = e.target.closest('.btn-msf-run');
    if (!btn) return;
    const modulePath = btn.getAttribute('data-module');
    if (!modulePath) return;
    openRunExploitModal(modulePath);
  });

  btnCloseMsfRunModal?.addEventListener('click', () => msfRunModalOverlay?.classList.add('hidden'));
  btnMsfRunCancel?.addEventListener('click', () => msfRunModalOverlay?.classList.add('hidden'));
  msfRunModalOverlay?.addEventListener('click', (e) => {
    if (e.target === msfRunModalOverlay) msfRunModalOverlay.classList.add('hidden');
  });

  btnMsfRunExecute?.addEventListener('click', async () => {
    const modulePath = msfRunModule?.value;
    const targetIp = (msfRunTargetIp?.value || '').trim();
    const targetPort = msfRunTargetPort?.value ? parseInt(msfRunTargetPort.value, 10) : undefined;
    const payload = (msfRunPayload?.value || '').trim() || undefined;

    if (!modulePath || !targetIp) {
      showMsfError('Module path and target IP are required');
      return;
    }

    const options = {};
    const lhost = (msfRunLhost?.value || '').trim();
    const lport = msfRunLport?.value ? parseInt(msfRunLport.value, 10) : undefined;
    if (lhost) options.LHOST = lhost;
    if (lport) options.LPORT = String(lport);

    btnMsfRunExecute.disabled = true;
    btnMsfRunExecute.textContent = 'Executing...';

    try {
      const result = await api.msfRunExploit({
        modulePath, targetIp, targetPort, payload, options,
      });

      if (result.status === 'error') {
        showMsfError(result.error);
      } else {
        msfRunModalOverlay?.classList.add('hidden');
        setTimeout(refreshMsfSessions, 2000);
      }
    } catch (err) {
      showMsfError(err.message);
    } finally {
      btnMsfRunExecute.disabled = false;
      btnMsfRunExecute.innerHTML = '<span class="icon">🚀</span> Execute';
    }
  });

  btnMsfRefreshSessions?.addEventListener('click', refreshMsfSessions);

  // Open MSF modal button in header
  const msfOpenBtn = document.getElementById('btn-msf-open');
  msfOpenBtn?.addEventListener('click', openModal);

  // IPC Event Listeners
  window.electronAPI.onMsfStatus?.((data) => {
    if (data.state === 'connected') {
      setMsfConnectedState(true, data.host || msfHost?.value, data.port || msfPort?.value);
    } else if (data.state === 'disconnected') {
      setMsfConnectedState(false);
    }
  });

  window.electronAPI.onMsfError?.((data) => {
    showMsfError(data.message || 'Unknown Metasploit error');
  });

  window.electronAPI.onMsfResult?.((data) => {
    console.log('[MSF Result]', data);
    setTimeout(refreshMsfSessions, 1500);
  });

  return { openModal, openRunExploitModal };
}
