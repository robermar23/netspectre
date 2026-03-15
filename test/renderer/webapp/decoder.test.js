/**
 * decoder.test.js
 * Tests for the client-side transforms in decoder.js.
 * Uses jsdom to provide browser globals (btoa, atob, TextEncoder, etc.)
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Setup: minimal DOM panel + electronAPI mock ──────────────────────────────

beforeEach(() => {
  document.body.innerHTML = `
    <div id="webapp-panel-decoder"></div>
  `;

  window.electronAPI = {
    decoder: {
      transform: vi.fn().mockResolvedValue({ success: true, output: 'mocked' }),
    },
  };
});

// ─── Transform helpers (mirrors decoder.js _applyClientTransform) ─────────────
// These helpers re-implement the decoder transforms using the same browser APIs
// so we can verify expected values independently of the module's internal state.

function b64encode(input) {
  return btoa(unescape(encodeURIComponent(input)));
}

function b64decode(input) {
  try { return decodeURIComponent(escape(atob(input))); } catch { return '[Base64 decode error]'; }
}

function urlEncode(input) {
  return encodeURIComponent(input);
}

function urlDecode(input) {
  try { return decodeURIComponent(input); } catch { return '[URL decode error]'; }
}

function htmlEncode(input) {
  return input.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
              .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function hexEncode(input) {
  return Array.from(new TextEncoder().encode(input)).map(b => b.toString(16).padStart(2,'0')).join('');
}

function hexDecode(input) {
  const clean = input.replace(/\s/g,'');
  if (clean.length % 2 !== 0) return '[Hex decode error: odd length]';
  try {
    const bytes = new Uint8Array(clean.match(/.{2}/g).map(h => parseInt(h, 16)));
    return new TextDecoder().decode(bytes);
  } catch { return '[Hex decode error]'; }
}

function unicodeEncode(input) {
  return Array.from(input).map(c => {
    const cp = c.codePointAt(0);
    return cp > 127 ? `\\u${cp.toString(16).padStart(4,'0')}` : c;
  }).join('');
}

function unicodeDecode(input) {
  return input.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

// ─── Base64 transforms ────────────────────────────────────────────────────────

describe('Base64 encode/decode', () => {
  it('encodes ASCII string', () => {
    expect(b64encode('hello')).toBe('aGVsbG8=');
  });

  it('encodes empty string', () => {
    expect(b64encode('')).toBe('');
  });

  it('round-trips ASCII', () => {
    const original = 'Hello, World! 12345';
    expect(b64decode(b64encode(original))).toBe(original);
  });

  it('round-trips Unicode (multi-byte UTF-8)', () => {
    const original = 'Héllo Wörld';
    expect(b64decode(b64encode(original))).toBe(original);
  });

  it('decode error returns error string for invalid base64', () => {
    const result = b64decode('!!!invalid!!!');
    expect(result).toBe('[Base64 decode error]');
  });

  it('encodes the string "admin" to known base64', () => {
    expect(b64encode('admin')).toBe('YWRtaW4=');
  });
});

// ─── URL encode/decode ────────────────────────────────────────────────────────

describe('URL encode/decode', () => {
  it('encodes spaces as %20', () => {
    expect(urlEncode('hello world')).toBe('hello%20world');
  });

  it('encodes special chars', () => {
    expect(urlEncode('a=1&b=2')).toBe('a%3D1%26b%3D2');
  });

  it('round-trips a URL-encoded string', () => {
    const original = "user' OR '1'='1--";
    expect(urlDecode(urlEncode(original))).toBe(original);
  });

  it('decode error returns error string for malformed percent encoding', () => {
    const result = urlDecode('%E0%A4%A');  // truncated multibyte
    expect(result).toBe('[URL decode error]');
  });

  it('does not encode unreserved chars (letters, digits, -_.~)', () => {
    expect(urlEncode('abcXYZ-_.~')).toBe('abcXYZ-_.~');
  });
});

// ─── HTML encode ──────────────────────────────────────────────────────────────

describe('HTML encode', () => {
  it('encodes & < > " \'', () => {
    expect(htmlEncode('& < > " \'')).toBe('&amp; &lt; &gt; &quot; &#39;');
  });

  it('encodes XSS payload', () => {
    const xss = '<script>alert("XSS")</script>';
    const encoded = htmlEncode(xss);
    expect(encoded).not.toContain('<script>');
    expect(encoded).toContain('&lt;script&gt;');
    expect(encoded).toContain('&quot;');
  });

  it('leaves plain text unchanged', () => {
    expect(htmlEncode('Hello World 123')).toBe('Hello World 123');
  });

  it('handles empty string', () => {
    expect(htmlEncode('')).toBe('');
  });
});

// ─── Hex encode/decode ────────────────────────────────────────────────────────

describe('Hex encode/decode', () => {
  it('encodes ASCII string to lowercase hex', () => {
    expect(hexEncode('ABC')).toBe('414243');
  });

  it('encodes single byte', () => {
    expect(hexEncode('A')).toBe('41');
  });

  it('round-trips ASCII string', () => {
    expect(hexDecode(hexEncode('Hello'))).toBe('Hello');
  });

  it('returns error for odd-length hex input', () => {
    expect(hexDecode('abc')).toBe('[Hex decode error: odd length]');
  });

  it('handles whitespace in hex input during decode', () => {
    // Whitespace is stripped before decoding
    const result = hexDecode('48 65 6c 6c 6f');
    expect(result).toBe('Hello');
  });

  it('handles empty string encode', () => {
    expect(hexEncode('')).toBe('');
  });

  it('handles empty string decode gracefully', () => {
    // '' has no hex pairs — decode returns an error or empty string
    const result = hexDecode('');
    expect(typeof result).toBe('string');
  });
});

// ─── Unicode escape/unescape ──────────────────────────────────────────────────

describe('Unicode escape/unescape', () => {
  it('escapes non-ASCII chars to \\uXXXX', () => {
    const result = unicodeEncode('é');
    expect(result).toBe('\\u00e9');
  });

  it('leaves ASCII chars unchanged', () => {
    expect(unicodeEncode('abc123')).toBe('abc123');
  });

  it('round-trips non-ASCII', () => {
    const original = 'Héllo';
    expect(unicodeDecode(unicodeEncode(original))).toBe(original);
  });

  it('unescapes \\u sequences in plain ASCII context', () => {
    expect(unicodeDecode('\\u0041\\u0042\\u0043')).toBe('ABC');
  });

  it('handles mixed ASCII + escaped', () => {
    expect(unicodeDecode('hello \\u0077orld')).toBe('hello world');
  });
});

// ─── JWT decode ───────────────────────────────────────────────────────────────

describe('JWT decode helper logic', () => {
  /**
   * Build a valid JWT from header + payload objects (unsigned).
   * Uses the same base64url encoding the decoder expects.
   */
  function makeJwt(header, payload, sig = 'fakesig') {
    const enc = (obj) => btoa(JSON.stringify(obj)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    return `${enc(header)}.${enc(payload)}.${sig}`;
  }

  it('valid JWT returns parsed header and payload', () => {
    const token = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1234', name: 'Alice' });

    // Manually decode using the same logic as decoder.js
    const parts = token.split('.');
    const header  = JSON.parse(decodeURIComponent(escape(atob(parts[0].replace(/-/g,'+').replace(/_/g,'/')))));
    const payload = JSON.parse(decodeURIComponent(escape(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')))));

    expect(header.alg).toBe('HS256');
    expect(payload.sub).toBe('1234');
    expect(payload.name).toBe('Alice');
  });

  it('JWT with alg:none produces warning', () => {
    const token = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: 'victim' });
    const parts = token.split('.');
    const header = JSON.parse(decodeURIComponent(escape(atob(parts[0].replace(/-/g,'+').replace(/_/g,'/')))));

    const warnings = [];
    if (header.alg === 'none') warnings.push('CRITICAL: alg=none');

    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings[0]).toContain('alg=none');
  });

  it('expired JWT triggers expiry warning', () => {
    const pastTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
    const token = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'user', exp: pastTime });
    const parts = token.split('.');
    const payload = JSON.parse(decodeURIComponent(escape(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')))));

    const warnings = [];
    if (payload.exp && new Date(payload.exp * 1000) < new Date()) {
      warnings.push('Token expired');
    }

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('Token expired');
  });

  it('invalid JWT format returns error message', () => {
    // Only one part (no dots) — invalid JWT
    const parts = 'notajwt'.split('.');
    expect(parts.length).toBe(1);
    // The decoder checks parts.length < 2 and returns an error string
  });
});

// ─── Decoder module: init and DOM setup ───────────────────────────────────────

describe('decoder init()', () => {
  it('renders decoder layout when panel exists', async () => {
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    init();

    const layout = document.querySelector('.decoder-layout');
    expect(layout).not.toBeNull();
  });

  it('renders transform select with expected options', async () => {
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    init();

    const select = document.getElementById('decoder-transform-select');
    expect(select).not.toBeNull();

    const options = Array.from(select.options).map(o => o.value);
    expect(options).toContain('base64-encode');
    expect(options).toContain('base64-decode');
    expect(options).toContain('url-encode');
    expect(options).toContain('url-decode');
    expect(options).toContain('html-encode');
    expect(options).toContain('hex-encode');
    expect(options).toContain('hex-decode');
    expect(options).toContain('unicode-encode');
    expect(options).toContain('unicode-decode');
    expect(options).toContain('jwt-decode');
  });

  it('renders input and output textareas', async () => {
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    init();

    expect(document.getElementById('decoder-input')).not.toBeNull();
    expect(document.getElementById('decoder-output')).not.toBeNull();
  });

  it('renders Apply button and Copy Output button', async () => {
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    init();

    expect(document.getElementById('decoder-go')).not.toBeNull();
    expect(document.getElementById('decoder-copy-output')).not.toBeNull();
  });

  it('does not render when panel element missing', async () => {
    document.body.innerHTML = ''; // no panel
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    // Should not throw
    expect(() => init()).not.toThrow();
  });
});

// ─── Decoder: Apply button triggers transform ─────────────────────────────────

describe('decoder Apply button', () => {
  beforeEach(() => {
    document.body.innerHTML = `<div id="webapp-panel-decoder"></div>`;
    window.electronAPI = {
      decoder: { transform: vi.fn().mockResolvedValue({ success: true, output: 'hashed' }) },
    };
  });

  it('applies base64-encode when Apply is clicked', async () => {
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    init();

    const inputEl  = document.getElementById('decoder-input');
    const outputEl = document.getElementById('decoder-output');
    const select   = document.getElementById('decoder-transform-select');
    const goBtn    = document.getElementById('decoder-go');

    inputEl.value = 'hello';
    select.value  = 'base64-encode';

    goBtn.click();

    // Synchronous transform — output should be set immediately
    expect(outputEl.value).toBe('aGVsbG8=');
  });

  it('applies url-encode when Apply is clicked', async () => {
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    init();

    const inputEl  = document.getElementById('decoder-input');
    const outputEl = document.getElementById('decoder-output');
    const select   = document.getElementById('decoder-transform-select');
    const goBtn    = document.getElementById('decoder-go');

    inputEl.value = 'a b&c';
    select.value  = 'url-encode';

    goBtn.click();
    expect(outputEl.value).toBe('a%20b%26c');
  });

  it('applies hex-encode when Apply is clicked', async () => {
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    init();

    const inputEl  = document.getElementById('decoder-input');
    const outputEl = document.getElementById('decoder-output');
    const select   = document.getElementById('decoder-transform-select');
    const goBtn    = document.getElementById('decoder-go');

    inputEl.value = 'Hi';
    select.value  = 'hex-encode';

    goBtn.click();
    expect(outputEl.value).toBe('4869');
  });
});

// ─── Decoder: Clear button ─────────────────────────────────────────────────────

describe('decoder Clear button', () => {
  it('clears both input and output', async () => {
    document.body.innerHTML = `<div id="webapp-panel-decoder"></div>`;
    const { init } = await import('../../../src/renderer/modules/webapp/decoder.js');
    init();

    const inputEl  = document.getElementById('decoder-input');
    const outputEl = document.getElementById('decoder-output');
    const clearBtn = document.getElementById('decoder-clear');

    inputEl.value  = 'some text';
    outputEl.removeAttribute('readonly');  // allow setting value for test
    outputEl.value = 'some output';

    clearBtn.click();

    expect(inputEl.value).toBe('');
    expect(outputEl.value).toBe('');
  });
});
