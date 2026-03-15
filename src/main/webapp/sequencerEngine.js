/**
 * sequencerEngine.js — Token Randomness Analyzer (Feature 7D)
 *
 * Analyzes the randomness quality of tokens (session cookies, CSRF tokens,
 * password reset links) using statistical tests.
 *
 * Analysis includes:
 *   - Shannon entropy (bits per byte)
 *   - FIPS 140-2 tests: monobit, frequency block, runs test, longest run
 *   - Chi-squared test on byte frequency distribution
 *   - Effective bit extraction (XOR all tokens to find varying bits)
 *   - Verdict: STRONG / MODERATE / WEAK
 *
 * Exports:
 *   collectTokens(opts, onToken, onComplete, onError)  — replay request N times
 *   stopCollection()
 *   analyzeTokens(tokens, opts)  → AnalysisResult (synchronous)
 */

import { sendProbe } from './scanner/index.js';

// ─── State ────────────────────────────────────────────────────────────────────

let _collectController = null;
let _collecting        = false;

// ─── Token Collection ─────────────────────────────────────────────────────────

/**
 * Replay a request N times and collect token values from the response.
 *
 * @param {{
 *   url:          string,
 *   method?:      string,
 *   headers?:     object,
 *   body?:        string,
 *   count:        number,   // number of tokens to collect
 *   tokenSource:  'cookie'|'header'|'body-regex',
 *   cookieName?:  string,
 *   headerName?:  string,
 *   bodyRegex?:   string,
 *   timeoutMs?:   number,
 *   delayMs?:     number,
 * }} opts
 */
export async function collectTokens(opts, onToken, onComplete, onError) {
  if (_collecting) {
    onError?.(new Error('Collection already running'));
    return;
  }

  const {
    url,
    method     = 'GET',
    headers    = {},
    body       = null,
    count      = 100,
    tokenSource = 'cookie',
    cookieName,
    headerName,
    bodyRegex,
    timeoutMs  = 10_000,
    delayMs    = 100,
  } = opts;

  try { new URL(url); } catch {
    onError?.(new Error(`Invalid URL: ${url}`));
    return;
  }

  _collectController = new AbortController();
  _collecting        = true;
  const signal       = _collectController.signal;
  const tokens       = [];

  let bodyRe = null;
  if (tokenSource === 'body-regex' && bodyRegex) {
    try { bodyRe = new RegExp(bodyRegex); } catch {
      onError?.(new Error(`Invalid bodyRegex: ${bodyRegex}`));
      _collecting = false;
      return;
    }
  }

  try {
    for (let i = 0; i < count; i++) {
      if (signal.aborted) break;

      let resp;
      try {
        resp = await sendProbe({ method, url, headers, body, timeoutMs }, signal);
      } catch (err) {
        if (err.name === 'AbortError') break;
        onError?.(err);
        break;
      }

      const token = _extractToken(resp, tokenSource, cookieName, headerName, bodyRe);
      if (token) {
        tokens.push(token);
        onToken?.({ token, index: i, total: count });
      }

      if (delayMs > 0 && i < count - 1) {
        await new Promise(r => setTimeout(r, delayMs));
      }
    }
  } finally {
    _collecting = false;
  }

  onComplete?.({ tokens, count: tokens.length });
}

export function stopCollection() {
  _collectController?.abort();
  _collecting = false;
}

export function isCollecting() {
  return _collecting;
}

// ─── Token extraction ─────────────────────────────────────────────────────────

function _extractToken(resp, source, cookieName, headerName, bodyRe) {
  if (source === 'cookie') {
    const setCookieHeaders = resp.headers['set-cookie'] ?? [];
    const arr = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const h of arr) {
      const [nameVal] = h.split(';');
      const [name, ...rest] = nameVal.split('=');
      if (!cookieName || name.trim().toLowerCase() === cookieName.toLowerCase()) {
        return rest.join('=').trim() || null;
      }
    }
    return null;
  }

  if (source === 'header') {
    const val = resp.headers[headerName?.toLowerCase()];
    return val ?? null;
  }

  if (source === 'body-regex' && bodyRe) {
    const m = bodyRe.exec(resp.body ?? '');
    return m ? (m[1] ?? m[0]) : null;
  }

  return null;
}

// ─── Statistical Analysis ─────────────────────────────────────────────────────

/**
 * Analyze a list of token strings for randomness quality.
 * This is a synchronous, CPU-bound function — run in worker_thread for large samples.
 *
 * @param {string[]} tokens
 * @param {{ sampleBits?: number }} [opts]  sampleBits: max bits to analyze per test
 * @returns {AnalysisResult}
 */
export function analyzeTokens(tokens, opts = {}) {
  if (!tokens || tokens.length < 2) {
    return { error: 'Need at least 2 tokens for analysis' };
  }

  // Convert tokens to bit arrays (UTF-8 bytes → bits)
  const bitArrays = tokens.map(t => _tokenToBits(t));
  const minLen    = Math.min(...bitArrays.map(a => a.length));
  if (minLen === 0) return { error: 'Tokens appear to be empty' };

  // Find "effective" bits: positions that vary across samples
  const effectiveBits = _findEffectiveBits(bitArrays, minLen);
  const effectiveBitCount = effectiveBits.filter(Boolean).length;

  // Extract just the effective bits from each token
  const effectiveStreams = bitArrays.map(arr =>
    effectiveBits.map((isEffective, i) => isEffective ? arr[i] : null).filter(b => b !== null)
  );
  const flatBits = effectiveStreams.flat();

  // Shannon entropy on raw bytes
  const entropyPerByte = _shannonEntropy(tokens);

  // FIPS 140-2 tests on the flat bit stream
  const monobit       = _testMonobit(flatBits);
  const blockFreq     = _testBlockFrequency(flatBits, 128);
  const runs          = _testRuns(flatBits);
  const longestRun    = _testLongestRun(flatBits);

  // Chi-squared on byte frequency
  const chiSquared    = _testChiSquared(tokens);

  // Verdict
  const fipsPassed    = [monobit.pass, blockFreq.pass, runs.pass, longestRun.pass].filter(Boolean).length;
  let verdict, verdictColor;
  if (entropyPerByte >= 6.5 && fipsPassed >= 3 && chiSquared.pass) {
    verdict = 'STRONG';
    verdictColor = 'green';
  } else if (entropyPerByte >= 4.0 && fipsPassed >= 2) {
    verdict = 'MODERATE';
    verdictColor = 'yellow';
  } else {
    verdict = 'WEAK';
    verdictColor = 'red';
  }

  // Byte frequency histogram (256 buckets → normalized 0–1)
  const histogram = _byteHistogram(tokens);

  return {
    sampleCount:       tokens.length,
    tokenLengthRange:  [Math.min(...tokens.map(t => t.length)), Math.max(...tokens.map(t => t.length))],
    effectiveBitCount,
    totalBitCount:     minLen,
    entropyPerByte:    +entropyPerByte.toFixed(4),
    fipsTests: {
      monobit,
      blockFrequency:  blockFreq,
      runs,
      longestRun,
    },
    chiSquared,
    verdict,
    verdictColor,
    remediation:       _remediation(verdict, entropyPerByte, fipsPassed),
    histogram,
  };
}

// ─── Bit/entropy helpers ──────────────────────────────────────────────────────

function _tokenToBits(token) {
  const bytes = Buffer.from(token, 'utf8');
  const bits  = [];
  for (const byte of bytes) {
    for (let b = 7; b >= 0; b--) {
      bits.push((byte >> b) & 1);
    }
  }
  return bits;
}

function _findEffectiveBits(bitArrays, len) {
  const effective = new Array(len).fill(false);
  const reference = bitArrays[0];
  for (let i = 0; i < len; i++) {
    for (let j = 1; j < bitArrays.length; j++) {
      if ((bitArrays[j][i] ?? 0) !== (reference[i] ?? 0)) {
        effective[i] = true;
        break;
      }
    }
  }
  return effective;
}

/**
 * Shannon entropy in bits-per-byte.
 * H = -Σ p(x) log2 p(x) over byte values.
 */
function _shannonEntropy(tokens) {
  const freq = new Array(256).fill(0);
  let total  = 0;
  for (const token of tokens) {
    const bytes = Buffer.from(token, 'utf8');
    for (const b of bytes) { freq[b]++; total++; }
  }
  if (total === 0) return 0;
  let H = 0;
  for (const f of freq) {
    if (f > 0) {
      const p = f / total;
      H -= p * Math.log2(p);
    }
  }
  return H;
}

/** FIPS 140-2 Monobit Test: count of 1s should be 9,725–10,275 in 20,000 bits */
function _testMonobit(bits) {
  if (bits.length < 100) return { pass: null, note: 'Insufficient bits', ones: 0, total: bits.length };
  const ones = bits.filter(b => b === 1).length;
  // Scale the threshold proportionally (FIPS specifies 20k bits; we scale)
  const total = bits.length;
  const ratio = ones / total;
  const pass  = ratio >= 0.4865 && ratio <= 0.5135;
  return { pass, ones, total, ratio: +ratio.toFixed(4), note: pass ? 'OK' : 'Significant bias toward ' + (ratio > 0.5 ? '1s' : '0s') };
}

/** FIPS 140-2 Frequency Block Test: chi-squared on non-overlapping 128-bit blocks */
function _testBlockFrequency(bits, blockSize = 128) {
  const blocks = Math.floor(bits.length / blockSize);
  if (blocks < 4) return { pass: null, note: 'Insufficient blocks' };
  let chi2 = 0;
  for (let i = 0; i < blocks; i++) {
    const block = bits.slice(i * blockSize, (i + 1) * blockSize);
    const ones  = block.filter(b => b === 1).length;
    const pi    = ones / blockSize;
    chi2 += 4 * blockSize * (pi - 0.5) ** 2;
  }
  const pValue = _chi2pvalue(chi2, blocks);
  const pass   = pValue >= 0.01;
  return { pass, chi2: +chi2.toFixed(4), pValue: +pValue.toFixed(4), blocks, note: pass ? 'OK' : 'Non-uniform block frequency' };
}

/** FIPS 140-2 Runs Test: tests for too many or too few consecutive run lengths */
function _testRuns(bits) {
  if (bits.length < 100) return { pass: null, note: 'Insufficient bits' };
  let runs  = 1;
  let ones  = bits[0] === 1 ? 1 : 0;
  for (let i = 1; i < bits.length; i++) {
    if (bits[i] !== bits[i - 1]) runs++;
    if (bits[i] === 1) ones++;
  }
  const n  = bits.length;
  const pi = ones / n;
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) {
    return { pass: false, runs, note: 'Monobit precondition failed' };
  }
  const expected = 2 * n * pi * (1 - pi);
  const variance = 2 * Math.sqrt(n) * pi * (1 - pi);
  const z        = Math.abs(runs - expected) / variance;
  const pass     = z < 1.96; // 95% confidence
  return { pass, runs, expected: +expected.toFixed(1), z: +z.toFixed(4), note: pass ? 'OK' : 'Unusual run pattern' };
}

/** FIPS 140-2 Longest Run Test: longest run of 1s in each block */
function _testLongestRun(bits) {
  const blockSize = 128;
  const blocks    = Math.floor(bits.length / blockSize);
  if (blocks < 4) return { pass: null, note: 'Insufficient bits' };
  let maxRun = 0;
  for (let i = 0; i < blocks; i++) {
    const block  = bits.slice(i * blockSize, (i + 1) * blockSize);
    let curRun   = 0;
    let blockMax = 0;
    for (const b of block) {
      if (b === 1) { curRun++; blockMax = Math.max(blockMax, curRun); }
      else curRun = 0;
    }
    maxRun = Math.max(maxRun, blockMax);
  }
  // For 128-bit blocks: longest run should be ≤ 5 with high probability for random sequences
  const pass = maxRun <= 6;
  return { pass, maxRun, note: pass ? 'OK' : `Suspiciously long run of 1s: ${maxRun} bits` };
}

/** Chi-squared goodness-of-fit on byte frequency (df=255) */
function _testChiSquared(tokens) {
  const freq = new Array(256).fill(0);
  let total  = 0;
  for (const token of tokens) {
    const bytes = Buffer.from(token, 'utf8');
    for (const b of bytes) { freq[b]++; total++; }
  }
  if (total < 256) return { pass: null, note: 'Too few bytes for chi-squared' };
  const expected = total / 256;
  let chi2 = 0;
  for (const f of freq) {
    chi2 += ((f - expected) ** 2) / expected;
  }
  const pValue = _chi2pvalue(chi2, 255);
  const pass   = pValue >= 0.001;
  return { pass, chi2: +chi2.toFixed(2), pValue: +pValue.toFixed(6), note: pass ? 'OK' : 'Non-uniform byte distribution' };
}

function _byteHistogram(tokens) {
  const freq = new Array(256).fill(0);
  let total  = 0;
  for (const token of tokens) {
    const bytes = Buffer.from(token, 'utf8');
    for (const b of bytes) { freq[b]++; total++; }
  }
  return total > 0 ? freq.map(f => +(f / total).toFixed(6)) : freq;
}

/** Approximate chi-squared p-value using Wilson-Hilferty approximation */
function _chi2pvalue(chi2, df) {
  if (df <= 0) return 0;
  const x  = chi2 / df;
  const wh = 1 - 2 / (9 * df) - Math.pow(x, 1 / 3) / Math.sqrt(2 / (9 * df));
  // Map to 0–1 using normal CDF approximation
  return 1 - _normalCdf(wh);
}

/** Abramowitz & Stegun approximation of the normal CDF */
function _normalCdf(x) {
  const t = 1 / (1 + 0.2316419 * Math.abs(x));
  const poly = t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));
  const pdf  = Math.exp(-0.5 * x * x) / Math.sqrt(2 * Math.PI);
  const cdf  = 1 - pdf * poly;
  return x >= 0 ? cdf : 1 - cdf;
}

function _remediation(verdict, entropy, fipsPassed) {
  if (verdict === 'STRONG') {
    return 'Token appears cryptographically random. No immediate remediation required.';
  }
  const issues = [];
  if (entropy < 4.0) issues.push('Low Shannon entropy — tokens may be predictable or have limited character space.');
  if (fipsPassed < 2) issues.push('Failed multiple FIPS 140-2 randomness tests — significant statistical bias detected.');
  issues.push('Ensure tokens are generated using a CSPRNG (e.g., crypto.randomBytes in Node.js).');
  issues.push('Token length should be at least 16 bytes (128 bits) of entropy.');
  issues.push('Avoid using timestamp, user ID, or sequential values as part of token generation.');
  return issues.join(' ');
}
