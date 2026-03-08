import { ipRegex } from './networkConstants.js';

/**
 * Returns true if value is a valid IPv4 address or a valid hostname.
 * @param {string} value
 * @returns {boolean}
 */
export function isValidIpOrHostname(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  return ipRegex.test(value) || /^[a-zA-Z0-9.-]{1,253}$/.test(value);
}

/**
 * Returns true if value is a well-formed http:// or https:// URL.
 * @param {string} value
 * @returns {boolean}
 */
export function isValidHttpUrl(value) {
  if (typeof value !== 'string') return false;
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Returns true if value is a valid absolute filesystem path that stays
 * within the given allowedRoot directory (no path traversal).
 * @param {string} value
 * @param {string} allowedRoot  — absolute path, e.g. '/home/user/downloads'
 * @returns {boolean}
 */
export function isPathWithinRoot(value, allowedRoot) {
  if (typeof value !== 'string' || typeof allowedRoot !== 'string') return false;
  if (value.includes('..')) return false;
  // Normalize separators for cross-platform safety
  const normalised = value.replace(/\\/g, '/');
  const root = allowedRoot.replace(/\\/g, '/');
  return normalised.startsWith(root);
}
