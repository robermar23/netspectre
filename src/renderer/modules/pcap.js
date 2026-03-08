import { api } from '../api.js';
import { state } from '../state.js';

export function init() {
  const btnStartLivePcap = document.getElementById('btn-start-live-pcap');
  const btnStopLivePcap = document.getElementById('btn-stop-live-pcap');
  const inputLivePcapHost = document.getElementById('live-pcap-host');
  const inputLivePcapDuration = document.getElementById('live-pcap-duration');
  const inputLivePcapBpf = document.getElementById('live-pcap-bpf');
  const livePcapStats = document.getElementById('live-pcap-total-stats');
  const livePcapWarnings = document.getElementById('live-pcap-warnings');
  const livePcapResults = document.getElementById('live-pcap-results');
  const passiveInterfaceSelect = document.getElementById('passive-interface-select');

  btnStartLivePcap?.addEventListener('click', async () => {
    const selectedOption = passiveInterfaceSelect.options[passiveInterfaceSelect.selectedIndex];
    if (!selectedOption || !selectedOption.dataset.name) {
      alert('Please select a valid network interface first.');
      return;
    }
    const ifaceName = selectedOption.dataset.name;

    const hostFilter = inputLivePcapHost.value.trim();
    if (!hostFilter) {
      alert('Please provide a Host Filter (IP address) to capture packets for.');
      return;
    }

    btnStartLivePcap.disabled = true;
    btnStopLivePcap.disabled = false;
    livePcapResults.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:12px;">Capturing packets...</td></tr>';
    livePcapStats.textContent = '0 Packets / 0 Bytes';
    livePcapWarnings.textContent = '';

    state.pcapPackets = [];

    const options = {
      duration: parseInt(inputLivePcapDuration.value, 10) || 60,
      host: hostFilter,
      bpf: inputLivePcapBpf.value.trim() || undefined
    };

    const res = await api.startPassiveCapture('pcap', ifaceName, options);
    if (res.status !== 'started') {
      btnStartLivePcap.disabled = false;
      btnStopLivePcap.disabled = true;
      livePcapWarnings.textContent = res.error || 'Failed to start PCAP capture.';
    }
  });

  btnStopLivePcap?.addEventListener('click', async () => {
    await api.stopPassiveCapture('pcap');
    btnStartLivePcap.disabled = false;
    btnStopLivePcap.disabled = true;
  });

  const btnImportLivePcap = document.getElementById('btn-import-live-pcap');
  btnImportLivePcap?.addEventListener('click', async () => {
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.pcap,.pcapng';
    fileInput.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      livePcapResults.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:12px;">Analyzing imported PCAP...</td></tr>';
      livePcapStats.textContent = '0 Packets / 0 Bytes';
      livePcapWarnings.textContent = '';
      state.pcapPackets = [];

      const res = await api.analyzePcapFile(file.path);
      if (res.status !== 'started') {
         livePcapWarnings.textContent = res.error || 'Failed to analyze PCAP file.';
      }
    };
    fileInput.click();
  });

  // PCAP Export Modal
  const pcapModalOverlay = document.getElementById('pcap-modal-overlay');
  const btnClosePcapModal = document.getElementById('btn-close-pcap-modal');
  const btnCancelPcap = document.getElementById('btn-cancel-pcap');
  const btnStartPcapBtn = document.getElementById('btn-start-pcap');
  const pcapInterfaceSelect = document.getElementById('pcap-interface');
  const pcapHostIpInput = document.getElementById('pcap-host-ip');
  const pcapDurationInput = document.getElementById('pcap-duration');
  const btnExportPcap = document.getElementById('btn-export-pcap');

  btnExportPcap?.addEventListener('click', async () => {
    pcapModalOverlay.classList.remove('hidden');
    pcapInterfaceSelect.innerHTML = '<option value="">Loading...</option>';
    try {
      const interfaces = await api.getInterfaces();
      pcapInterfaceSelect.innerHTML = '';
      interfaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.name;
        opt.textContent = `${iface.name} (${iface.ip})`;
        pcapInterfaceSelect.appendChild(opt);
      });
      if (passiveInterfaceSelect.value) {
        pcapInterfaceSelect.value = passiveInterfaceSelect.value;
      }
    } catch (e) {
      console.error(e);
      pcapInterfaceSelect.innerHTML = '<option value="">Error Loading</option>';
    }
  });

  const closePcapModal = () => pcapModalOverlay.classList.add('hidden');
  btnClosePcapModal?.addEventListener('click', closePcapModal);
  btnCancelPcap?.addEventListener('click', closePcapModal);

  btnStartPcapBtn?.addEventListener('click', async () => {
    const iface = pcapInterfaceSelect.value;
    if (!iface) {
      alert('Select an interface');
      return;
    }

    const host = pcapHostIpInput.value.trim();
    const dur = parseInt(pcapDurationInput.value, 10) || 60;

    btnStartPcapBtn.disabled = true;
    btnStartPcapBtn.textContent = 'Starting...';

    const res = await api.exportPcap({ interfaceId: iface, hostIp: host, duration: dur });
    if (res.success && res.status === 'started') {
      btnStartPcapBtn.textContent = 'Exporting...';
      closePcapModal();
      btnStartPcapBtn.disabled = false;
      btnStartPcapBtn.textContent = 'Start Export';
    } else {
      btnStartPcapBtn.disabled = false;
      btnStartPcapBtn.textContent = 'Start Export';
      if (res.status !== 'cancelled') {
         alert(`Failed to start PCAP export: ${res.error}`);
      } else {
         closePcapModal();
      }
    }
  });

  // IPC: PCAP event listeners
  window.electronAPI.onPcapExportComplete && window.electronAPI.onPcapExportComplete((data) => {
     alert(`PCAP Export Complete!\nSaved ${data.packetCount} packets to:\n${data.filePath}`);
  });

  window.electronAPI.onPcapExportError && window.electronAPI.onPcapExportError((err) => {
     alert(`PCAP Export Error:\n${err}`);
  });

  window.electronAPI.onPcapPacketSummary && window.electronAPI.onPcapPacketSummary((summary) => {
    state.pcapPackets = state.pcapPackets || [];
    state.pcapPackets.push(summary);
    if (state.pcapPackets.length > 500) state.pcapPackets.shift(); // Keep last 500

    const livePcapResultsEl = document.getElementById('live-pcap-results');
    if (!livePcapResultsEl) return;

    const tr = document.createElement('tr');
    const tdTime = document.createElement('td');
    tdTime.style.whiteSpace = 'nowrap';
    tdTime.textContent = new Date(summary.timestamp).toLocaleTimeString();

    const tdSrc = document.createElement('td');
    tdSrc.className = 'selectable-text';
    tdSrc.textContent = summary.srcIp;

    const tdDst = document.createElement('td');
    tdDst.className = 'selectable-text';
    tdDst.textContent = summary.dstIp;

    const tdProto = document.createElement('td');
    const spanProto = document.createElement('span');
    spanProto.className = 'badge ' + (summary.protocol === 'TCP' ? 'info' : (summary.protocol === 'UDP' ? 'success' : 'warning'));
    spanProto.textContent = summary.protocol;
    tdProto.appendChild(spanProto);

    const tdLen = document.createElement('td');
    tdLen.textContent = summary.length;

    const tdInfo = document.createElement('td');
    tdInfo.className = 'selectable-text text-ellipsis';
    tdInfo.title = summary.info;
    tdInfo.textContent = summary.info;

    tr.appendChild(tdTime);
    tr.appendChild(tdSrc);
    tr.appendChild(tdDst);
    tr.appendChild(tdProto);
    tr.appendChild(tdLen);
    tr.appendChild(tdInfo);

    if (livePcapResultsEl.children[0] && livePcapResultsEl.children[0].textContent.includes('Waiting for')) {
      livePcapResultsEl.innerHTML = '';
    } else if (livePcapResultsEl.children[0] && livePcapResultsEl.children[0].textContent.includes('Capturing packets...')) {
      livePcapResultsEl.innerHTML = '';
    }

    livePcapResultsEl.prepend(tr);
    if (livePcapResultsEl.children.length > 500) {
      livePcapResultsEl.lastElementChild.remove();
    }
  });

  window.electronAPI.onPcapStatsUpdate && window.electronAPI.onPcapStatsUpdate((stats) => {
    const livePcapStatsEl = document.getElementById('live-pcap-total-stats');
    const livePcapWarningsEl = document.getElementById('live-pcap-warnings');
    if (livePcapStatsEl) {
      livePcapStatsEl.textContent = `${stats.totalPackets} Packets / ${stats.totalBytes} Bytes`;
    }
    if (livePcapWarningsEl) {
      livePcapWarningsEl.textContent = stats.warnings.join(', ');
    }
  });

  window.electronAPI.onPcapCaptureComplete && window.electronAPI.onPcapCaptureComplete((msg) => {
    const btnStartLivePcapEl = document.getElementById('btn-start-live-pcap');
    const btnStopLivePcapEl = document.getElementById('btn-stop-live-pcap');
    if (btnStartLivePcapEl) btnStartLivePcapEl.disabled = false;
    if (btnStopLivePcapEl) btnStopLivePcapEl.disabled = true;

    const livePcapWarningsEl = document.getElementById('live-pcap-warnings');
    if (livePcapWarningsEl && msg !== 'Capture finished.') {
      livePcapWarningsEl.textContent = msg;
    }
  });
}
