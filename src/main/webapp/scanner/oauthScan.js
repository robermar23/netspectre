/**
 * Feature 7E — OAuth/OIDC Misconfiguration Scanner
 *
 * Passively analyses proxied requests for OAuth/OIDC patterns and
 * actively probes detected authorization endpoints for:
 *
 *   1. Open redirect in redirect_uri — wildcard/unvalidated redirect URIs
 *   2. Missing state parameter — CSRF vulnerability in authorization flow
 *   3. Authorization code leakage via Referer header
 *   4. Token delivered in URL fragment or query parameter
 *   5. PKCE absence / bypass on authorization code flows
 *   6. Client secret exposed in URL / request body (not Basic auth)
 *   7. Implicit flow usage (deprecated, token in fragment)
 *   8. Insecure response_type combinations
 */

import { sendProbe, makeFinding } from './index.js';
import { OAUTH_REDIRECT_TEST_DOMAINS } from '#shared/webConstants.js';

// ─── Heuristics ────────────────────────────────────────────────────────────────

/** Detect OAuth/OIDC endpoints by URL path and parameter patterns */
function _isOauthEndpoint(target) {
  const url = target.url.toLowerCase();
  return (
    url.includes('/oauth') ||
    url.includes('/authorize') ||
    url.includes('/auth/') ||
    url.includes('/connect/') ||
    url.includes('/openid') ||
    url.includes('/token') ||
    url.includes('/callback') ||
    url.includes('response_type=') ||
    url.includes('client_id=') ||
    url.includes('redirect_uri=')
  );
}

function _parseQueryParams(url) {
  try {
    return Object.fromEntries(new URL(url).searchParams.entries());
  } catch { return {}; }
}

function _parseFragment(url) {
  try {
    const frag = new URL(url).hash;
    if (!frag) return {};
    return Object.fromEntries(new URLSearchParams(frag.slice(1)).entries());
  } catch { return {}; }
}

// ─── Module runner ─────────────────────────────────────────────────────────────

export async function runOauthScan(target, opts) {
  const { signal, timeoutMs } = opts;
  const findings = [];

  if (!_isOauthEndpoint(target)) return findings;

  const params   = _parseQueryParams(target.url);
  const fragment = _parseFragment(target.url);
  const body     = target.requestBody ? String(target.requestBody) : '';

  // ── 1. Open redirect in redirect_uri ──────────────────────────────────────
  if (params.redirect_uri || body.includes('redirect_uri=')) {
    const redirectUri = params.redirect_uri
      ?? new URLSearchParams(body).get('redirect_uri')
      ?? '';

    for (const evil of OAUTH_REDIRECT_TEST_DOMAINS) {
      if (signal?.aborted) break;
      try {
        const probeUrl = new URL(target.url);
        probeUrl.searchParams.set('redirect_uri', evil);
        const resp = await sendProbe({
          method: 'GET', url: probeUrl.toString(),
          headers: target.requestHeaders || {},
          timeoutMs, followRedirect: false,
        }, signal);

        // A redirect to our evil domain means the server accepted it
        const location = Object.entries(resp.headers || {})
          .find(([k]) => k.toLowerCase() === 'location')?.[1] ?? '';
        if (location.startsWith(evil) || location.includes('evil.com')) {
          findings.push(makeFinding({
            severity:    'high',
            type:        'oauth',
            title:       'OAuth Open Redirect — Unvalidated redirect_uri',
            description: `The OAuth authorization endpoint accepted an external domain "${evil}" as a redirect_uri without validation. An attacker can redirect authorization codes or tokens to a domain they control, leading to account takeover.`,
            url:         target.url,
            parameter:   'redirect_uri',
            payload:     evil,
            evidence:    { location, probeUrl: probeUrl.toString() },
            remediation: 'Validate redirect_uri against a strict server-side allowlist. Never use wildcard or prefix matching. Register valid redirect URIs at client registration time.',
            references:  ['CWE-601', 'OWASP A01:2021', 'RFC 6749 §10.6'],
          }));
          break;
        }
      } catch (err) { if (err.name === 'AbortError') return findings; }
    }
  }

  // ── 2. Missing state parameter ────────────────────────────────────────────
  if ((params.response_type || body.includes('response_type=')) && !params.state) {
    findings.push(makeFinding({
      severity:    'medium',
      type:        'oauth',
      title:       'OAuth Authorization Request Missing "state" Parameter',
      description: 'The OAuth authorization request does not include a "state" parameter. This makes the flow vulnerable to CSRF attacks — an attacker can trick a user into authorizing a malicious client by initiating a flow without a nonce.',
      url:         target.url,
      parameter:   'state',
      evidence:    { queryParams: params },
      remediation: 'Always include a cryptographically random "state" parameter (at least 128 bits) in authorization requests. Validate it on the callback. Consider using PKCE as an additional layer of protection.',
      references:  ['RFC 6749 §10.12', 'CWE-352', 'OWASP A01:2021'],
    }));
  }

  // ── 3. Authorization code leakage via Referer ─────────────────────────────
  const referer = Object.entries(target.requestHeaders || {})
    .find(([k]) => k.toLowerCase() === 'referer')?.[1] ?? '';
  if (params.code && referer && referer !== target.url) {
    findings.push(makeFinding({
      severity:    'medium',
      type:        'oauth',
      title:       'OAuth Authorization Code Leakage via Referer Header',
      description: `The OAuth authorization code is present in the URL (${params.code.substring(0, 8)}...) and the request includes a Referer header pointing to an external resource (${referer.substring(0, 80)}). The code may be sent to third-party servers via the Referer header before it is exchanged.`,
      url:         target.url,
      parameter:   'code',
      evidence:    { codePrefix: params.code.substring(0, 12), referer },
      remediation: 'Use the Referrer-Policy: no-referrer response header on callback pages. Exchange the code immediately and invalidate it. Move the authorization code out of the URL using the POST response mode.',
      references:  ['CWE-200', 'OWASP A02:2021', 'RFC 6749 §10.6'],
    }));
  }

  // ── 4. Token in URL fragment or query parameter ────────────────────────────
  const tokenInQuery    = params.access_token || params.id_token;
  const tokenInFragment = fragment.access_token || fragment.id_token;

  if (tokenInQuery) {
    findings.push(makeFinding({
      severity:    'medium',
      type:        'oauth',
      title:       'OAuth Token Delivered in URL Query Parameter',
      description: `An access_token or id_token was found in the URL query string. Tokens in URL query parameters are logged in server logs, browser history, and can be leaked via Referer headers.`,
      url:         target.url,
      parameter:   'access_token',
      evidence:    { tokenPrefix: (tokenInQuery).substring(0, 20) + '...' },
      remediation: 'Use the authorization code flow with PKCE. Deliver tokens only in POST response bodies or HTTP response headers. Avoid the implicit flow.',
      references:  ['OWASP A02:2021', 'RFC 6749 §10.3'],
    }));
  }

  if (tokenInFragment) {
    findings.push(makeFinding({
      severity:    'low',
      type:        'oauth',
      title:       'OAuth Token Delivered via URL Fragment (Implicit Flow)',
      description: `An access_token or id_token was found in the URL fragment (#). This indicates use of the OAuth implicit flow, which is deprecated in OAuth 2.1. Tokens in fragments can be stolen via JavaScript injections or malicious page content.',`,
      url:         target.url,
      parameter:   'access_token (fragment)',
      evidence:    { tokenPrefix: tokenInFragment.substring(0, 20) + '...' },
      remediation: 'Migrate from the implicit flow to the authorization code flow with PKCE (RFC 7636). Never put tokens in URL fragments.',
      references:  ['OWASP A02:2021', 'RFC 6749 §4.2', 'OAuth 2.1 draft'],
    }));
  }

  // ── 5. PKCE absence on authorization code flow ────────────────────────────
  if (params.response_type === 'code' && !params.code_challenge) {
    findings.push(makeFinding({
      severity:    'low',
      type:        'oauth',
      title:       'OAuth Authorization Code Flow Missing PKCE (code_challenge)',
      description: 'The authorization code flow does not include a "code_challenge" parameter (PKCE — RFC 7636). Without PKCE, authorization code injection attacks and interception attacks are possible, especially for public clients.',
      url:         target.url,
      parameter:   'code_challenge',
      evidence:    { response_type: params.response_type, hasPKCE: false },
      remediation: 'Implement PKCE (code_challenge and code_verifier) for all authorization code flows, especially for public/native clients. Use S256 as the code_challenge_method.',
      references:  ['RFC 7636', 'OWASP A07:2021'],
    }));
  }

  // ── 6. Client secret in URL ────────────────────────────────────────────────
  const clientSecretInUrl = params.client_secret;
  const clientSecretInBody = /client_secret=/.test(body) && !/Authorization:\s*Basic/i.test(
    Object.entries(target.requestHeaders || {}).map(([k, v]) => `${k}: ${v}`).join('\n'),
  );

  if (clientSecretInUrl || clientSecretInBody) {
    findings.push(makeFinding({
      severity:    'high',
      type:        'oauth',
      title:       'OAuth Client Secret Exposed in Request',
      description: `The OAuth client_secret is transmitted ${clientSecretInUrl ? 'in the URL query string' : 'in the request body as plain text'} rather than via HTTP Basic authentication or a secure POST body with TLS. This exposes the secret in server logs, browser history, and network traces.`,
      url:         target.url,
      parameter:   'client_secret',
      evidence:    {
        location: clientSecretInUrl ? 'URL query parameter' : 'Request body (non-Basic)',
      },
      remediation: 'Use HTTP Basic authentication (Authorization: Basic base64(client_id:client_secret)) for client authentication at the token endpoint. Never put client_secret in URLs.',
      references:  ['RFC 6749 §2.3', 'CWE-522', 'OWASP A02:2021'],
    }));
  }

  // ── 7. Implicit flow usage (passive detection) ────────────────────────────
  if (params.response_type === 'token' || params.response_type === 'id_token token') {
    findings.push(makeFinding({
      severity:    'medium',
      type:        'oauth',
      title:       'Deprecated OAuth Implicit Flow in Use',
      description: `The OAuth implicit flow (response_type="${params.response_type}") is deprecated in OAuth 2.1 and the Security BCP (RFC 9700). It delivers tokens via the URL fragment without authentication of the token endpoint, exposing tokens to browser history and JavaScript.`,
      url:         target.url,
      parameter:   'response_type',
      evidence:    { response_type: params.response_type },
      remediation: 'Migrate to the authorization code flow with PKCE (RFC 7636) for all clients, including SPAs and mobile applications.',
      references:  ['RFC 9700 §2.1', 'OWASP A07:2021'],
    }));
  }

  return findings;
}
