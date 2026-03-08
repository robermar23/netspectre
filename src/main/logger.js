const isDev = process.env.NODE_ENV === 'development';

/**
 * Minimal structured logger for the main process.
 * In production, info() is suppressed; warn() and error() always emit.
 *
 * Usage:
 *   import { logger } from './logger.js';
 *   logger.info('scanner', 'Scan started', { subnet });
 *   logger.warn('main', 'Nmap not found');
 *   logger.error('bruteForce', 'IPC handler failed', err);
 */
export const logger = {
  info:  (module, msg, ...args) => { if (isDev) console.log(`[${module}] ${msg}`, ...args); },
  warn:  (module, msg, ...args) => console.warn(`[${module}] ${msg}`, ...args),
  error: (module, msg, ...args) => console.error(`[${module}] ${msg}`, ...args),
};
