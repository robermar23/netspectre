/**
 * Brute-Force Module — THC-Hydra Wrapper
 *
 * Spawns Hydra as a child process, parses structured stdout,
 * and streams results back to the renderer via callbacks.
 */

import { spawn } from 'child_process';
import fs from 'fs';
import { ipRegex, BRUTEFORCE_PROTOCOLS } from '#shared/networkConstants.js';
import { getSetting } from './store.js';

/** Active brute-force processes keyed by `targetIp:protocol` */
const activeProcesses = new Map();

/** Max safety cap for total attempts (prevents runaway attacks) */
const ABSOLUTE_MAX_ATTEMPTS = 50000;

/**
 * Validate brute-force options before spawning Hydra.
 * @param {object} opts
 * @returns {{ valid: boolean, error?: string }}
 */
function validateOptions(opts) {
  if (!opts.targetIp || !ipRegex.test(opts.targetIp)) {
    return { valid: false, error: 'Invalid IP address format' };
  }

  const port = parseInt(opts.port, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    return { valid: false, error: 'Port must be between 1 and 65535' };
  }

  if (!opts.protocol || !BRUTEFORCE_PROTOCOLS.includes(opts.protocol)) {
    return { valid: false, error: `Unsupported protocol: ${opts.protocol}. Allowed: ${BRUTEFORCE_PROTOCOLS.join(', ')}` };
  }

  if (!opts.username && !opts.userListPath) {
    return { valid: false, error: 'Username or user list path is required' };
  }

  if (!opts.wordlistPath) {
    return { valid: false, error: 'Wordlist path is required' };
  }

  if (opts.wordlistPath && !fs.existsSync(opts.wordlistPath)) {
    return { valid: false, error: `Wordlist file not found: ${opts.wordlistPath}` };
  }

  if (opts.userListPath && !fs.existsSync(opts.userListPath)) {
    return { valid: false, error: `User list file not found: ${opts.userListPath}` };
  }

  const threads = parseInt(opts.threads, 10) || 4;
  if (threads < 1 || threads > 16) {
    return { valid: false, error: 'Thread count must be between 1 and 16' };
  }

  const maxAttempts = parseInt(opts.maxAttempts, 10) || 10000;
  if (maxAttempts < 1 || maxAttempts > ABSOLUTE_MAX_ATTEMPTS) {
    return { valid: false, error: `Max attempts must be between 1 and ${ABSOLUTE_MAX_ATTEMPTS}` };
  }

  return { valid: true };
}

/**
 * Regex to parse Hydra credential hit lines.
 * Example: [22][ssh] host: 10.0.0.1   login: admin   password: admin123
 */
const HYDRA_HIT_REGEX = /^\[(\d+)\]\[(\w[\w-]*)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)$/;

/**
 * Regex to parse Hydra status/progress lines.
 * Example: [STATUS] 64.00 tries/min, 128 tries in 00:02h, 9872 to do in 02:34h
 */
const HYDRA_STATUS_REGEX = /^\[STATUS\]\s+(.+)$/;

/**
 * Build Hydra CLI arguments from validated options.
 * @param {object} opts - Validated options
 * @returns {string[]} Array of CLI arguments
 */
function buildHydraArgs(opts) {
  const args = [];

  // Username: -l for single user, -L for user list file
  if (opts.userListPath) {
    args.push('-L', opts.userListPath);
  } else {
    args.push('-l', opts.username);
  }

  // Wordlist
  args.push('-P', opts.wordlistPath);

  // Port
  args.push('-s', String(opts.port));

  // Threads (capped at 16)
  const threads = Math.min(parseInt(opts.threads, 10) || 4, 16);
  args.push('-t', String(threads));

  // Delay between attempts
  const delay = parseInt(opts.delay, 10) || 0;
  if (delay > 0) {
    args.push('-W', String(delay));
  }

  // Stop after first successful match
  args.push('-f');

  // Verbose mode (shows each attempt)
  args.push('-V');

  // Any custom arguments
  if (Array.isArray(opts.customArgs)) {
    // Sanitize: only allow arguments that start with '-'
    const safe = opts.customArgs.filter(a => typeof a === 'string' && a.startsWith('-'));
    args.push(...safe);
  }

  // Target and protocol (positional args at end)
  args.push(opts.targetIp, opts.protocol);

  return args;
}

/**
 * Start a brute-force attack using Hydra.
 *
 * @param {object} options - Attack configuration
 * @param {Function} onAttempt - Called for each attempt line
 * @param {Function} onResult  - Called when a credential is found
 * @param {Function} onProgress - Called for status/progress updates
 * @param {Function} onError   - Called on error
 * @param {Function} onComplete - Called when the process exits
 */
export function startBruteForce(options, onAttempt, onResult, onProgress, onError, onComplete) {
  const validation = validateOptions(options);
  if (!validation.valid) {
    onError({ message: validation.error });
    return;
  }

  const key = `${options.targetIp}:${options.protocol}`;

  // Prevent duplicate concurrent attacks on the same target:protocol
  if (activeProcesses.has(key)) {
    onError({ message: `Brute-force already running on ${key}` });
    return;
  }

  // Resolve Hydra path from store
  const hydraPath = getSetting('hydra.path') || 'hydra';
  const args = buildHydraArgs(options);

  console.log(`[BruteForce] Spawning: ${hydraPath} ${args.join(' ')}`);

  let proc;
  try {
    proc = spawn(hydraPath, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
  } catch (err) {
    onError({ message: `Failed to spawn Hydra: ${err.message}` });
    return;
  }

  activeProcesses.set(key, proc);

  let attemptCount = 0;
  let foundCredentials = [];
  const maxAttempts = parseInt(options.maxAttempts, 10) || 10000;

  // Parse stdout line-by-line
  let stdoutBuffer = '';
  proc.stdout.on('data', (data) => {
    stdoutBuffer += data.toString();
    const lines = stdoutBuffer.split('\n');
    // Keep incomplete last line in buffer
    stdoutBuffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      // Check for credential hit
      const hitMatch = trimmed.match(HYDRA_HIT_REGEX);
      if (hitMatch) {
        const credential = {
          port: parseInt(hitMatch[1], 10),
          protocol: hitMatch[2],
          host: hitMatch[3],
          user: hitMatch[4],
          password: hitMatch[5].trim(),
          timestamp: new Date().toISOString(),
        };
        foundCredentials.push(credential);
        onResult(credential);
        continue;
      }

      // Check for status/progress update
      const statusMatch = trimmed.match(HYDRA_STATUS_REGEX);
      if (statusMatch) {
        onProgress({
          statusText: statusMatch[1],
          attemptCount,
          foundCount: foundCredentials.length,
        });
        continue;
      }

      // Verbose attempt lines (start with [ATTEMPT])
      if (trimmed.startsWith('[ATTEMPT]') || trimmed.startsWith('[')) {
        attemptCount++;

        // Safety cap enforcement
        if (attemptCount >= maxAttempts) {
          console.log(`[BruteForce] Max attempts (${maxAttempts}) reached. Stopping.`);
          stopBruteForce(key);
          onError({ message: `Max attempts (${maxAttempts}) reached. Attack stopped.` });
          return;
        }

        onAttempt({
          line: trimmed,
          attemptNumber: attemptCount,
          timestamp: new Date().toISOString(),
        });
      }
    }
  });

  // Capture stderr for error reporting
  let stderrBuffer = '';
  proc.stderr.on('data', (data) => {
    stderrBuffer += data.toString();
  });

  proc.on('error', (err) => {
    activeProcesses.delete(key);
    onError({ message: `Hydra process error: ${err.message}` });
  });

  proc.on('close', (code) => {
    activeProcesses.delete(key);

    // Flush remaining stdout buffer
    if (stdoutBuffer.trim()) {
      const hitMatch = stdoutBuffer.trim().match(HYDRA_HIT_REGEX);
      if (hitMatch) {
        const credential = {
          port: parseInt(hitMatch[1], 10),
          protocol: hitMatch[2],
          host: hitMatch[3],
          user: hitMatch[4],
          password: hitMatch[5].trim(),
          timestamp: new Date().toISOString(),
        };
        foundCredentials.push(credential);
        onResult(credential);
      }
    }

    onComplete({
      exitCode: code,
      totalAttempts: attemptCount,
      credentialsFound: foundCredentials,
      stderr: stderrBuffer.trim(),
    });
  });
}

/**
 * Stop an active brute-force attack.
 * @param {string} [key] - Optional specific key (`ip:protocol`). If omitted, stops all.
 */
export function stopBruteForce(key) {
  if (key && activeProcesses.has(key)) {
    const proc = activeProcesses.get(key);
    proc.kill('SIGTERM');
    activeProcesses.delete(key);
    return true;
  }

  // Stop all if no key specified
  if (!key) {
    for (const [k, proc] of activeProcesses.entries()) {
      proc.kill('SIGTERM');
      activeProcesses.delete(k);
    }
    return activeProcesses.size === 0;
  }

  return false;
}

/**
 * Check if any brute-force attack is currently running.
 * @returns {boolean}
 */
export function isBruteForceRunning() {
  return activeProcesses.size > 0;
}

/**
 * Kill all tracked processes (called on app shutdown).
 */
export function cleanupBruteForce() {
  for (const [key, proc] of activeProcesses.entries()) {
    try {
      proc.kill('SIGKILL');
    } catch (_) { /* ignore */ }
    activeProcesses.delete(key);
  }
}
