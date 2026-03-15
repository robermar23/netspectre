/**
 * Feature 7C — Broken Authentication Scanner Module
 *
 * Checks:
 *   1. Rate limiting on login forms (replay 20 bad-credential requests)
 *   2. Username enumeration (timing/body delta between valid vs invalid username)
 *   3. Weak password probe on detected login forms
 *   4. JWT inspection (alg:none, long expiry, missing claims)
 */

import { sendProbe, extractParams, makeFinding } from './index.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const WEAK_PASSWORDS  = ['password', '123456', 'admin', 'letmein', 'welcome', 'qwerty', 'password123'];
const FAKE_USERNAME   = `netspecter_probe_${Date.now()}`;
const FAKE_PASSWORDS  = ['WRONG_PASS_NS_PROBE', 'invalid_probe'];

// Login-endpoint heuristics
const LOGIN_PATH_PATTERNS  = [/login/i, /signin/i, /auth/i, /session/i, /token/i];
const USERNAME_FIELD_NAMES = ['username', 'user', 'email', 'login', 'userid'];
const PASSWORD_FIELD_NAMES = ['password', 'pass', 'passwd', 'pwd', 'secret'];

// ─── Module runner ────────────────────────────────────────────────────────────

export async function runBrokenAuth(target, opts) {
  const { signal, timeoutMs } = opts;
  const findings = [];

  let parsedUrl;
  try { parsedUrl = new URL(target.url); } catch { return findings; }

  const isLoginEndpoint = LOGIN_PATH_PATTERNS.some(p => p.test(parsedUrl.pathname));

  // ── 1. JWT inspection (passive — uses request/response headers) ───────────
  _inspectJwts(target, findings);

  if (!isLoginEndpoint) return findings;

  // ── 2. Rate-limit detection (replay 20 bad creds) ────────────────────────
  const params  = extractParams(target);
  const usernameParam = params.find(p => USERNAME_FIELD_NAMES.some(n => p.name.toLowerCase().includes(n)));
  const passwordParam = params.find(p => PASSWORD_FIELD_NAMES.some(n => p.name.toLowerCase().includes(n)));

  if (usernameParam && passwordParam) {
    let blockedCount = 0;
    for (let i = 0; i < 20; i++) {
      if (signal?.aborted) break;
      let injected = usernameParam.inject(`ns_probe_${i}`);
      injected = passwordParam.inject(`WRONG_${i}`);
      try {
        const resp = await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
          signal,
        );
        if (resp.statusCode === 429 || /too many/i.test(resp.body) || /rate limit/i.test(resp.body) || /locked/i.test(resp.body)) {
          blockedCount++;
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }

    if (blockedCount === 0) {
      findings.push(makeFinding({
        severity:    'high',
        type:        'brokenAuth',
        title:       'No Rate Limiting on Login Endpoint',
        description: `The login endpoint at ${target.url} does not apply rate limiting. 20 consecutive bad-credential requests were submitted without receiving a 429 or lockout response, enabling brute-force attacks.`,
        url:         target.url,
        evidence:    {
          request:  `POST ${target.url}`,
          response: '20 requests — no 429, no lockout detected',
        },
        remediation: 'Implement account lockout or progressive delay after N failed login attempts. Add CAPTCHA for high-volume sources. Use rate-limiting middleware (e.g., express-rate-limit).',
        references:  ['CWE-307', 'OWASP A07:2021'],
      }));
    }

    // ── 3. Username enumeration ────────────────────────────────────────────
    try {
      const realUserResp  = await sendProbe(
        { method: target.method, url: target.url, headers: target.requestHeaders, body: target.body, timeoutMs },
        signal,
      );
      let fakeInjected = usernameParam.inject(FAKE_USERNAME);
      fakeInjected = passwordParam.inject(FAKE_PASSWORDS[0]);
      const t0 = Date.now();
      const fakeUserResp  = await sendProbe(
        { method: fakeInjected.method || target.method, url: fakeInjected.url, headers: fakeInjected.requestHeaders || target.requestHeaders, body: fakeInjected.body, timeoutMs },
        signal,
      );
      const timingDelta   = Date.now() - t0;
      const lengthDelta   = Math.abs(realUserResp.body.length - fakeUserResp.body.length);

      if (lengthDelta > 50 || timingDelta > 200) {
        findings.push(makeFinding({
          severity:    'medium',
          type:        'brokenAuth',
          title:       'Username Enumeration Possible on Login Endpoint',
          description: `The login endpoint at ${target.url} produces different responses (body delta: ${lengthDelta} bytes, timing delta: ~${timingDelta}ms) for valid vs invalid usernames, allowing attackers to enumerate valid accounts.`,
          url:         target.url,
          evidence:    {
            request:      `POST ${target.url}`,
            lengthDelta,
            timingDelta,
          },
          remediation: 'Return identical responses (body, status code, timing) for both valid and invalid login attempts. Use constant-time comparison.',
          references:  ['CWE-204', 'OWASP A07:2021'],
        }));
      }
    } catch (err) {
      if (err.name === 'AbortError') return findings;
    }

    // ── 4. Weak password probe ────────────────────────────────────────────
    for (const weakPwd of WEAK_PASSWORDS) {
      if (signal?.aborted) break;
      let injected = usernameParam.inject('admin');
      injected = passwordParam.inject(weakPwd);
      try {
        const resp = await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
          signal,
        );
        // Heuristic: 200 + token/redirect = success
        const hasToken = /token|jwt|session|auth/i.test(JSON.stringify(resp.headers));
        if (resp.statusCode === 200 && (hasToken || resp.statusCode < 400)) {
          findings.push(makeFinding({
            severity:    'critical',
            type:        'brokenAuth',
            title:       `Weak/Default Credentials Accepted: admin / ${weakPwd}`,
            description: `The login endpoint at ${target.url} accepted the weak credential combination admin / ${weakPwd}. This allows attackers to gain unauthorized access.`,
            url:         target.url,
            payload:     `username=admin&password=${weakPwd}`,
            evidence:    {
              request:  `POST ${target.url}`,
              response: `HTTP ${resp.statusCode}`,
            },
            remediation: 'Enforce a strong password policy. Change all default credentials immediately. Implement multi-factor authentication.',
            references:  ['CWE-521', 'OWASP A07:2021'],
          }));
          break;
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }
  }

  return findings;
}

// ─── JWT inspection (passive) ─────────────────────────────────────────────────

function _inspectJwts(target, findings) {
  const sources = [
    ...Object.values(target.requestHeaders || {}),
    ...Object.values(target.responseHeaders || {}),
    target.body || '',
  ].join(' ');

  // JWT pattern: base64url.base64url.base64url
  const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  const tokens = sources.match(jwtPattern);
  if (!tokens) return;

  for (const token of [...new Set(tokens)]) {
    try {
      const parts = token.split('.');
      const header  = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

      if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
        findings.push(makeFinding({
          severity:    'critical',
          type:        'brokenAuth',
          title:       'JWT "alg:none" — Signature Bypass Possible',
          description: `A JWT was found with algorithm "none", which means the server may accept unsigned tokens. Attackers can forge arbitrary JWT payloads.`,
          url:         target.url,
          evidence:    { jwtHeader: header, jwtPayload: _sanitizePayload(payload) },
          remediation: 'Reject JWTs with alg:none. Enforce a strict allowlist of accepted algorithms (e.g., RS256 only). Use a well-maintained JWT library.',
          references:  ['CWE-347', 'OWASP A02:2021'],
        }));
      }

      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && (payload.exp - now) > 7 * 24 * 3600) {
        findings.push(makeFinding({
          severity:    'low',
          type:        'brokenAuth',
          title:       'JWT Long Expiry (> 7 days)',
          description: `A JWT was found with an expiry of ${Math.round((payload.exp - now) / 86400)} days. Long-lived tokens increase the window of opportunity if the token is compromised.`,
          url:         target.url,
          evidence:    { jwtHeader: header, exp: new Date(payload.exp * 1000).toISOString() },
          remediation: 'Use short-lived access tokens (15–60 minutes) with refresh tokens. Implement token revocation.',
          references:  ['CWE-613', 'OWASP A02:2021'],
        }));
      }

      if (!payload.aud && !payload.iss) {
        findings.push(makeFinding({
          severity:    'info',
          type:        'brokenAuth',
          title:       'JWT Missing aud/iss Claims',
          description: 'A JWT was found without "aud" (audience) and "iss" (issuer) claims, which weakens token validation and may allow token reuse across different services.',
          url:         target.url,
          evidence:    { jwtPayload: _sanitizePayload(payload) },
          remediation: 'Always include iss, aud, and exp claims. Validate all three on every request.',
          references:  ['CWE-347', 'OWASP A02:2021'],
        }));
      }
    } catch { /* malformed token — skip */ }
  }
}

function _sanitizePayload(payload) {
  // Remove fields that may contain sensitive values
  const { password, secret, key, ...safe } = payload;
  return safe;
}
