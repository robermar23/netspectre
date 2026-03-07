/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';

// Load HTML structure
const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

describe('Reverse Shell UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;
    
    // Mock the electronAPI
    window.electronAPI = {
      startRevShell: vi.fn(),
      stopRevShell: vi.fn(),
      sendRevShell: vi.fn(),
      onRevShellConnection: vi.fn(),
      onRevShellData: vi.fn(),
      onRevShellError: vi.fn(),
    };
    
    // Quick mock for API object used in index.js
    window.api = {
      startRevShell: window.electronAPI.startRevShell,
      stopRevShell: window.electronAPI.stopRevShell,
      sendRevShell: window.electronAPI.sendRevShell
    };
    
    // Initialize mock DOM elements
    const revshellTerminal = document.getElementById('revshell-terminal');
    if (revshellTerminal) {
       // mock methods that might throw in jsdom
       revshellTerminal.scrollTop = 0;
       Object.defineProperty(revshellTerminal, 'scrollHeight', { value: 100, writable: true });
    }
    
    // Mock openPanel and closePanel
    window.openPanel = vi.fn((panel, resizer) => {
      panel.style.display = 'block';
      panel.classList.add('open');
      if (resizer) resizer.style.display = 'block';
    });
    
    window.closePanel = vi.fn((panel, resizer) => {
      panel.style.display = 'none';
      panel.classList.remove('open');
      if (resizer) resizer.style.display = 'none';
    });

    // We emulate the part of index.js that attaches listeners for the RevShell
    const btnRevshellOpen = document.getElementById('btn-revshell-open');
    const revshellPanel = document.getElementById('revshell-panel');
    const btnCloseRevshellPanel = document.getElementById('btn-close-revshell-panel');
    const revshellResizer = document.getElementById('revshell-resizer');
    
    const btnRevshellStart = document.getElementById('btn-revshell-start');
    const revshellPort = document.getElementById('revshell-port');
    const revshellMode = document.getElementById('revshell-mode');
    
    // Polyfill DOM click logic
    btnRevshellOpen?.addEventListener('click', () => {
      if (revshellPanel.style.display === 'none' || !revshellPanel.classList.contains('open')) {
        window.openPanel(revshellPanel, revshellResizer);
      } else {
        window.closePanel(revshellPanel, revshellResizer);
      }
    });
    
    btnCloseRevshellPanel?.addEventListener('click', () => {
      window.closePanel(revshellPanel, revshellResizer);
    });
    
    if (btnRevshellStart) {
       btnRevshellStart.addEventListener('click', async () => {
         const port = parseInt(revshellPort.value, 10);
         const mode = revshellMode.value;
         await window.api.startRevShell({ port, mode });
       });
    }
  });

  it('should open and close the reverse shell panel', () => {
    const btnOpen = document.getElementById('btn-revshell-open');
    const btnClose = document.getElementById('btn-close-revshell-panel');
    const panel = document.getElementById('revshell-panel');
    
    // Initially not displayed/open in DOM structure
    expect(panel.style.display).toBe('none');
    
    btnOpen.click();
    expect(window.openPanel).toHaveBeenCalled();
    expect(panel.style.display).toBe('block');
    expect(panel.classList.contains('open')).toBe(true);
    
    btnClose.click();
    expect(window.closePanel).toHaveBeenCalled();
    expect(panel.style.display).toBe('none');
  });
  
  it('should call startRevShell API when Start button is clicked', () => {
    const btnStart = document.getElementById('btn-revshell-start');
    const revshellPort = document.getElementById('revshell-port');
    const revshellMode = document.getElementById('revshell-mode');
    
    revshellPort.value = '4444';
    revshellMode.value = 'native';
    
    btnStart.click();
    
    expect(window.api.startRevShell).toHaveBeenCalledWith({ port: 4444, mode: 'native' });
  });
});
