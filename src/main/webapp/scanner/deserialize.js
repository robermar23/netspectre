/**
 * Feature 7C — Insecure Deserialization Scanner Module
 *
 * Detection only — no weaponization.
 *
 * Detects serialized data patterns in cookies, POST bodies, JSON fields:
 *   - PHP serialized objects  (O:n:"ClassName":{...})
 *   - Java serialized objects (rO0AB base64 magic bytes aced 0005)
 *   - Python Pickle           (\x80\x02 or \x80\x03/\x04/\x05 prefix)
 *   - .NET __VIEWSTATE        without MAC protection hint
 */

import { makeFinding } from './index.js';

// ─── Detection patterns ────────────────────────────────────────────────────────

const PATTERNS = [
  {
    name:     'PHP Object Serialization',
    pattern:  /O:\d+:"[A-Za-z_\\][A-Za-z0-9_\\]*":\d+:\{/,
    severity: 'info',
    desc:     'PHP serialized object detected. If deserialized without validation, this may allow PHP object injection.',
    remediation: 'Do not pass user-supplied serialized PHP objects to unserialize(). Use JSON or other safe formats. If unavoidable, use a whitelist of allowed classes with __PHP_Incomplete_Class protection.',
    cwe:      'CWE-502',
  },
  {
    name:     'Java Serialized Object',
    pattern:  /rO0AB[A-Za-z0-9+/=]{4,}/,   // Base64 of aced 0005
    severity: 'info',
    desc:     'Java serialized object (Base64-encoded) detected. Deserialization of untrusted Java objects can lead to remote code execution via gadget chains.',
    remediation: 'Use Java serialization filters (ObjectInputFilter). Consider replacing Java serialization with JSON or Protocol Buffers. Apply the OWASP deserialization cheat sheet.',
    cwe:      'CWE-502',
  },
  {
    name:     'Python Pickle Data',
    pattern:  /\\x80[\\x02-\\x05]/,
    severity: 'info',
    desc:     'Python Pickle serialized data detected. Deserializing untrusted pickle data can execute arbitrary Python code.',
    remediation: 'Never deserialize pickle data from untrusted sources. Use JSON or MessagePack instead.',
    cwe:      'CWE-502',
  },
  {
    name:     '.NET ViewState',
    pattern:  /__VIEWSTATE\s*=\s*["'][A-Za-z0-9+/=]{20,}/,
    severity: 'medium',
    desc:     '.NET __VIEWSTATE found. If viewStateMAC is disabled or the MAC key is weak, the ViewState can be tampered with to trigger deserialization attacks.',
    remediation: 'Enable viewStateMAC (enableViewStateMac="true"). Use a strong machine key. Encrypt ViewState (ViewStateEncryptionMode="Always").',
    cwe:      'CWE-502',
  },
];

// Detect raw Java magic bytes in non-base64 context
const JAVA_MAGIC = /\xac\xed\x00\x05/;

// ─── Module runner ─────────────────────────────────────────────────────────────

export async function runDeserialize(target, opts) {
  const { oastCallbackUrl } = opts;
  const findings = [];

  // Collect all string sources from the target
  const sources = _buildSources(target);

  for (const { label, value } of sources) {
    for (const { name, pattern, severity, desc, remediation, cwe } of PATTERNS) {
      if (pattern.test(value)) {
        findings.push(makeFinding({
          severity,
          type:        'deserialize',
          title:       `${name} Detected in ${label}`,
          description: `${desc} Found in: ${label}`,
          url:         target.url,
          evidence:    {
            location: label,
            snippet:  value.slice(0, 200),
          },
          remediation,
          references:  [cwe, 'OWASP A08:2021', 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'],
        }));
      }
    }

    // Raw Java magic bytes
    if (JAVA_MAGIC.test(value)) {
      findings.push(makeFinding({
        severity:    'info',
        type:        'deserialize',
        title:       `Java Serialized Object (raw bytes) in ${label}`,
        description: `Raw Java serialization magic bytes (0xACED0005) were found in ${label}. This indicates the application is transmitting or receiving Java serialized objects.`,
        url:         target.url,
        evidence:    { location: label },
        remediation: 'Replace Java object serialization with a safer format (JSON, Protobuf). Apply Java serialization filters.',
        references:  ['CWE-502', 'OWASP A08:2021'],
      }));
    }
  }

  // OAST-based Java gadget chain probe (DNS-lookup only, no RCE payloads)
  if (oastCallbackUrl && findings.some(f => f.title.includes('Java'))) {
    findings.push(makeFinding({
      severity:    'info',
      type:        'deserialize',
      title:       'Java Deserialization OAST Probe Available',
      description: `Java serialized objects were detected. If you have an OAST callback URL configured, a DNS-lookup gadget chain probe can be sent to confirm exploitability without executing code. Configure the OAST server to enable this check.`,
      url:         target.url,
      evidence:    { oastUrl: oastCallbackUrl },
      remediation: 'Apply Java serialization filters (ObjectInputFilter). Use safer serialization formats.',
      references:  ['CWE-502', 'OWASP A08:2021'],
    }));
  }

  return findings;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _buildSources(target) {
  const sources = [];

  // Request headers
  for (const [k, v] of Object.entries(target.requestHeaders || {})) {
    sources.push({ label: `Request Header: ${k}`, value: String(v) });
  }

  // Request body
  if (target.body) {
    sources.push({ label: 'Request Body', value: target.body });
    // Also check JSON field values
    try {
      const obj = JSON.parse(target.body);
      for (const [k, v] of Object.entries(obj)) {
        if (typeof v === 'string') {
          sources.push({ label: `JSON Field: ${k}`, value: v });
        }
      }
    } catch {}
  }

  // Response body
  if (target.responseBody) {
    sources.push({ label: 'Response Body', value: String(target.responseBody).slice(0, 50_000) });
  }

  return sources;
}
