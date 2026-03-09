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

function openPanelHelper(panelEl, sidebarResizerEl) {
  panelEl.style.display = 'flex';
  setTimeout(() => panelEl.classList.add('open'), 10);
  if (sidebarResizerEl) sidebarResizerEl.style.display = 'block';
}

function closePanelHelper(panelEl, sidebarResizerEl) {
  panelEl.classList.remove('open');
  setTimeout(() => {
    panelEl.style.display = 'none';
    if (sidebarResizerEl) sidebarResizerEl.style.display = 'none';
  }, 300);
}

const sharePanel           = document.getElementById('share-panel');
const shareResizer         = document.getElementById('share-resizer');
const btnCloseSharePanel   = document.getElementById('btn-close-share-panel');
const shareTargetIp        = document.getElementById('share-target-ip');
const shareUsername        = document.getElementById('share-username');
const sharePassword        = document.getElementById('share-password');
const shareDomain          = document.getElementById('share-domain');
const btnShareEnumerate    = document.getElementById('btn-share-enumerate');
const shareErrorBanner     = document.getElementById('share-error-banner');
const shareStatusText      = document.getElementById('share-status-text');
const shareSpinner         = document.getElementById('share-spinner');
const shareListSmb         = document.getElementById('share-list-smb');
const shareListNfs         = document.getElementById('share-list-nfs');
const shareFileTbody       = document.getElementById('share-file-tbody');
const shareBreadcrumb      = document.getElementById('share-breadcrumb');
const shareFooterInfo      = document.getElementById('share-footer-info');
const btnShareClear        = document.getElementById('btn-share-clear');
const btnShareEnumOpen     = document.getElementById('btn-share-enum-open');

let shareCurrentIp         = '';
let shareCurrentShare      = '';
let shareEnumerating       = false;

function showShareError(msg) {
  if (!shareErrorBanner) return;
  shareErrorBanner.textContent = msg;
  shareErrorBanner.style.display = 'block';
  setTimeout(() => { shareErrorBanner.style.display = 'none'; }, 10000);
}

function clearShareError() {
  if (shareErrorBanner) shareErrorBanner.style.display = 'none';
}

function setShareStatus(msg, spinning = false) {
  if (shareStatusText) shareStatusText.textContent = msg;
  if (shareSpinner) shareSpinner.style.display = spinning ? 'inline-block' : 'none';
}

function getShareCredentials() {
  const username = shareUsername?.value?.trim() || '';
  const password = sharePassword?.value || '';
  const domain   = shareDomain?.value?.trim() || '';
  if (!username) return null;
  return { username, password, domain: domain || undefined };
}

function renderShareItem(share, container) {
  const typeIcons = { disk: '🗂️', ipc: '🔒', printer: '🖨️', 'print-queue': '🖨️', nfs: '📦' };
  const icon = typeIcons[share.type] || '📁';

  const btn = document.createElement('button');
  btn.className = 'share-item';
  btn.dataset.shareName = share.name;
  btn.dataset.shareType = share.type;

  const iconSpan = document.createElement('span');
  iconSpan.className = 'share-item-icon';
  iconSpan.textContent = icon;

  const nameSpan = document.createElement('span');
  nameSpan.className = 'share-item-name';
  nameSpan.textContent = share.name;

  const badge = document.createElement('span');
  badge.className = `share-type-badge ${share.type}`;
  badge.textContent = share.type;

  btn.appendChild(iconSpan);
  btn.appendChild(nameSpan);
  btn.appendChild(badge);

  if (share.comment) {
    btn.title = share.comment;
  }

  if (share.type === 'disk') {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));
      btn.classList.add('active');
      browseShareDir(shareCurrentIp, share.name, '');
    });
  } else {
    btn.style.opacity = '0.6';
    btn.style.cursor = 'default';
    btn.title = `${share.type.toUpperCase()} share — not browsable`;
  }

  container.appendChild(btn);
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function buildBreadcrumb(shareName, remotePath) {
  if (!shareBreadcrumb) return;
  shareBreadcrumb.innerHTML = '';

  const root = document.createElement('span');
  root.className = 'share-breadcrumb-part';
  root.textContent = shareName;
  root.title = `Browse root of \\\\${shareCurrentIp}\\${shareName}`;
  root.addEventListener('click', () => browseShareDir(shareCurrentIp, shareName, ''));
  shareBreadcrumb.appendChild(root);

  if (remotePath) {
    const parts = remotePath.replace(/^\/+/, '').split('/').filter(Boolean);
    let cumulativePath = '';
    parts.forEach((part) => {
      const sep = document.createElement('span');
      sep.className = 'share-breadcrumb-sep';
      sep.textContent = ' / ';
      shareBreadcrumb.appendChild(sep);

      cumulativePath = cumulativePath ? `${cumulativePath}/${part}` : part;
      const crumb = document.createElement('span');
      crumb.className = 'share-breadcrumb-part';
      crumb.textContent = part;
      const pathForCrumb = cumulativePath;
      crumb.addEventListener('click', () => browseShareDir(shareCurrentIp, shareName, pathForCrumb));
      shareBreadcrumb.appendChild(crumb);
    });
  }
}

function getFileIcon(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  const map = {
    pdf: '📄', doc: '📝', docx: '📝', xls: '📊', xlsx: '📊', ppt: '📑', pptx: '📑',
    txt: '📃', csv: '📃', log: '📃', md: '📃',
    zip: '🗜️', rar: '🗜️', gz: '🗜️', tar: '🗜️', '7z': '🗜️',
    jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', bmp: '🖼️', svg: '🖼️',
    mp3: '🎵', wav: '🎵', flac: '🎵',
    mp4: '🎬', avi: '🎬', mkv: '🎬', mov: '🎬',
    exe: '⚙️', dll: '⚙️', bat: '⚙️', sh: '⚙️',
    conf: '🔧', cfg: '🔧', ini: '🔧', env: '🔧', json: '🔧', xml: '🔧', yaml: '🔧',
    db: '🗄️', sql: '🗄️', sqlite: '🗄️',
  };
  return map[ext] || '📄';
}

function renderFileBrowser(shareName, remotePath, entries) {
  if (!shareFileTbody) return;
  shareFileTbody.innerHTML = '';
  shareCurrentShare = shareName;

  buildBreadcrumb(shareName, remotePath);

  if (entries.length === 0) {
    shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">Empty directory</td></tr>';
    if (shareFooterInfo) shareFooterInfo.textContent = '0 items';
    return;
  }

  const sorted = [...entries].sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  sorted.forEach((entry) => {
    const tr = document.createElement('tr');
    tr.className = entry.type === 'dir' ? 'share-dir-row' : 'share-file-row';

    const iconTd = document.createElement('td');
    iconTd.style.textAlign = 'center';
    iconTd.textContent = entry.type === 'dir' ? '📁' : getFileIcon(entry.name);

    const nameTd = document.createElement('td');
    nameTd.style.wordBreak = 'break-all';
    nameTd.textContent = entry.name;

    const sizeTd = document.createElement('td');
    sizeTd.style.textAlign = 'right';
    sizeTd.style.fontFamily = 'monospace';
    sizeTd.style.color = 'var(--text-muted)';
    sizeTd.textContent = entry.type === 'dir' ? '—' : formatFileSize(entry.size || 0);

    const modTd = document.createElement('td');
    modTd.style.color = 'var(--text-muted)';
    modTd.textContent = entry.modified || '';

    const actionTd = document.createElement('td');

    if (entry.type === 'dir') {
      const enterBtn = document.createElement('button');
      enterBtn.className = 'btn-share-download';
      enterBtn.textContent = 'Open';
      const entryPath = remotePath ? `${remotePath}/${entry.name}` : entry.name;
      enterBtn.addEventListener('click', () => browseShareDir(shareCurrentIp, shareName, entryPath));
      actionTd.appendChild(enterBtn);

      tr.style.cursor = 'pointer';
      tr.addEventListener('dblclick', () => browseShareDir(shareCurrentIp, shareName, entryPath));
    } else {
      const dlBtn = document.createElement('button');
      dlBtn.className = 'btn-share-download';
      dlBtn.textContent = '⬇ Save';
      const filePath = remotePath ? `${remotePath}/${entry.name}` : entry.name;
      dlBtn.addEventListener('click', () => downloadShareEntry(shareCurrentIp, shareName, filePath, dlBtn));
      actionTd.appendChild(dlBtn);
    }

    tr.appendChild(iconTd);
    tr.appendChild(nameTd);
    tr.appendChild(sizeTd);
    tr.appendChild(modTd);
    tr.appendChild(actionTd);
    shareFileTbody.appendChild(tr);
  });

  const dirs  = sorted.filter(e => e.type === 'dir').length;
  const files = sorted.filter(e => e.type === 'file').length;
  if (shareFooterInfo) shareFooterInfo.textContent = `${dirs} folder${dirs !== 1 ? 's' : ''}, ${files} file${files !== 1 ? 's' : ''}`;
}

async function browseShareDir(targetIp, shareName, remotePath) {
  clearShareError();
  setShareStatus(`Browsing \\\\${targetIp}\\${shareName}\\${remotePath || ''}...`, true);

  if (shareFileTbody) {
    shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">Loading...</td></tr>';
  }
  buildBreadcrumb(shareName, remotePath);

  try {
    await api.browseShare({ targetIp, shareName, remotePath, credentials: getShareCredentials() });
    setShareStatus(`Browsing \\\\${targetIp}\\${shareName}\\${remotePath || ''}`, false);
  } catch (err) {
    showShareError(`Browse error: ${err.message}`);
    setShareStatus('Browse failed', false);
  }
}

async function downloadShareEntry(targetIp, shareName, remoteFile, btn) {
  clearShareError();
  const originalText = btn.textContent;
  btn.textContent = '⏳';
  btn.disabled = true;

  try {
    const result = await api.downloadShareFile({ targetIp, shareName, remoteFile, credentials: getShareCredentials() });
    if (result.status === 'downloaded') {
      btn.textContent = '✔️';
      setShareStatus(`Downloaded to: ${result.localPath}`);
      setTimeout(() => {
        btn.textContent = originalText;
        btn.disabled = false;
      }, 3000);
    } else if (result.status === 'cancelled') {
      btn.textContent = originalText;
      btn.disabled = false;
    } else {
      btn.textContent = originalText;
      btn.disabled = false;
      showShareError(result.error || 'Download failed');
    }
  } catch (err) {
    btn.textContent = originalText;
    btn.disabled = false;
    showShareError(`Download error: ${err.message}`);
  }
}

async function runEnumeration() {
  const targetIp = shareTargetIp?.value?.trim();
  if (!targetIp) {
    showShareError('Enter a target IP address');
    shareTargetIp?.focus();
    return;
  }

  if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(targetIp)) {
    showShareError('Invalid IP address format');
    shareTargetIp?.focus();
    return;
  }

  if (shareEnumerating) return;
  shareEnumerating = true;

  clearShareError();
  shareCurrentIp = targetIp;

  if (shareListSmb) shareListSmb.innerHTML = '';
  if (shareListNfs) shareListNfs.innerHTML = '';
  if (shareFileTbody) {
    shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 32px;">Select a share to browse</td></tr>';
  }
  if (shareBreadcrumb) shareBreadcrumb.innerHTML = '<span style="opacity:0.5;">No share selected</span>';
  if (shareFooterInfo) shareFooterInfo.textContent = '—';
  shareCurrentShare = '';

  setShareStatus(`Enumerating shares on ${targetIp}...`, true);
  if (btnShareEnumerate) btnShareEnumerate.disabled = true;

  try {
    await api.enumerateShares({ targetIp, credentials: getShareCredentials() });
  } catch (err) {
    showShareError(`Enumeration error: ${err.message}`);
    setShareStatus('Enumeration failed', false);
  } finally {
    shareEnumerating = false;
    if (btnShareEnumerate) btnShareEnumerate.disabled = false;
  }
}

function initResizer(resizerEl, panelEl) {
  if (!resizerEl || !panelEl) return;
  let activeResize = null;

  resizerEl.addEventListener('mousedown', (e) => {
    const startWidth = parseInt(document.defaultView.getComputedStyle(panelEl).width, 10);
    activeResize = { resizerEl, panelEl, startX: e.clientX, startWidth };
    resizerEl.classList.add('is-resizing');
    document.body.style.cursor = 'col-resize';
    e.preventDefault();
  });

  document.addEventListener('mousemove', (e) => {
    if (!activeResize) return;
    const { startX, startWidth } = activeResize;
    const newWidth = startWidth - (e.clientX - startX);
    if (newWidth > 300 && newWidth < Math.min(800, window.innerWidth - 100)) {
      panelEl.style.width = `${newWidth}px`;
    }
  });

  document.addEventListener('mouseup', () => {
    if (!activeResize) return;
    activeResize.resizerEl.classList.remove('is-resizing');
    document.body.style.cursor = '';
    activeResize = null;
  });
}

export function openPanel(prefilledIp) {
  clearShareError();
  if (prefilledIp && shareTargetIp) shareTargetIp.value = prefilledIp;
  if (shareListSmb) shareListSmb.innerHTML = '<div class="share-empty-state" style="text-align:center;color:var(--text-muted);padding:24px;font-size:12px;">Run enumeration to discover shares</div>';
  if (shareListNfs) shareListNfs.innerHTML = '<div class="share-empty-state" style="text-align:center;color:var(--text-muted);padding:24px;font-size:12px;">Run enumeration to discover NFS exports</div>';
  if (shareFileTbody) shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">Select a share to browse</td></tr>';
  if (shareBreadcrumb) shareBreadcrumb.innerHTML = '<span style="opacity:0.5;">No share selected</span>';
  if (shareFooterInfo) shareFooterInfo.textContent = '—';
  setShareStatus('Enter a target IP and click Enumerate.', false);
  if (sharePanel) openPanelHelper(sharePanel, shareResizer);

  if (prefilledIp) {
    setTimeout(runEnumeration, 150);
  }
}

function closeSharePanel() {
  if (sharePanel) closePanelHelper(sharePanel, shareResizer);
}

export function init() {
  initResizer(shareResizer, sharePanel);

  btnCloseSharePanel?.addEventListener('click', closeSharePanel);

  btnShareEnumOpen?.addEventListener('click', () => {
    if (sharePanel) {
      if (sharePanel.style.display === 'none' || !sharePanel.classList.contains('open')) {
        openPanel('');
      } else {
        closeSharePanel();
      }
    }
  });

  btnShareEnumerate?.addEventListener('click', runEnumeration);
  shareTargetIp?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runEnumeration();
  });

  btnShareClear?.addEventListener('click', () => {
    clearShareError();
    if (shareListSmb) shareListSmb.innerHTML = '<div class="share-empty-state" style="text-align:center;color:var(--text-muted);padding:24px;font-size:12px;">Run enumeration to discover shares</div>';
    if (shareListNfs) shareListNfs.innerHTML = '<div class="share-empty-state" style="text-align:center;color:var(--text-muted);padding:24px;font-size:12px;">Run enumeration to discover NFS exports</div>';
    if (shareFileTbody) shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">Select a share to browse</td></tr>';
    if (shareBreadcrumb) shareBreadcrumb.innerHTML = '<span style="opacity:0.5;">No share selected</span>';
    if (shareFooterInfo) shareFooterInfo.textContent = '—';
    shareCurrentIp = ''; shareCurrentShare = '';
    setShareStatus('Enter a target IP and click Enumerate.', false);
  });

  // Protocol tab switching
  document.querySelectorAll('[data-share-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('[data-share-tab]').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const which = tab.getAttribute('data-share-tab');
      document.getElementById('share-tab-smb').style.display = which === 'smb' ? 'flex' : 'none';
      document.getElementById('share-tab-nfs').style.display = which === 'nfs' ? 'flex' : 'none';
    });
  });

  // Split-pane resizer
  (function initSharePaneResizer() {
    const resizer  = document.getElementById('share-pane-resizer');
    const leftPane = resizer?.previousElementSibling;
    if (!resizer || !leftPane) return;

    let dragging = false;
    let startX = 0;
    let startWidth = 0;

    resizer.addEventListener('mousedown', (e) => {
      dragging = true;
      startX = e.clientX;
      startWidth = leftPane.offsetWidth;
      resizer.classList.add('dragging');
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      const delta = e.clientX - startX;
      const newWidth = Math.max(140, Math.min(400, startWidth + delta));
      leftPane.style.width = `${newWidth}px`;
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      resizer.classList.remove('dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    });
  })();

  // IPC event listeners
  window.electronAPI.onShareResult?.((data) => {
    if (data.type === 'smb') {
      if (!shareListSmb) return;
      shareListSmb.innerHTML = '';

      if (data.shares.length === 0) {
        const msg = data.note || 'No SMB shares found (null session may be blocked)';
        shareListSmb.innerHTML = `<div style="text-align:center;color:var(--text-muted);padding:16px;font-size:12px;">${escapeHtml(msg)}</div>`;
      } else {
        data.shares.forEach(share => renderShareItem(share, shareListSmb));
      }
      setShareStatus(`SMB: ${data.shares.length} share${data.shares.length !== 1 ? 's' : ''} found`, false);

    } else if (data.type === 'nfs') {
      if (!shareListNfs) return;
      shareListNfs.innerHTML = '';

      if (data.shares.length === 0) {
        const msg = data.note || 'No NFS exports found';
        shareListNfs.innerHTML = `<div style="text-align:center;color:var(--text-muted);padding:16px;font-size:12px;">${escapeHtml(msg)}</div>`;
      } else {
        data.shares.forEach(share => renderShareItem(share, shareListNfs));
      }

    } else if (data.type === 'browse') {
      renderFileBrowser(shareCurrentShare, data.path?.replace(/^\//, '') || '', data.entries || []);
      setShareStatus(`${data.entries?.length ?? 0} items in ${data.path || '/'}`, false);
    }
  });

  window.electronAPI.onShareError?.((err) => {
    showShareError(err.message || 'Share enumeration error');
    setShareStatus('Error — see banner above', false);
    if (btnShareEnumerate) btnShareEnumerate.disabled = false;
    shareEnumerating = false;
  });

  return { openPanel };
}
