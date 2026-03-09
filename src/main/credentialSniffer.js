/* LEGAL NOTICE: This module captures cleartext credentials from network traffic.
 * Use this tool only on authorized networks where you have explicit permission
 * to monitor traffic. Unauthorized packet sniffing or credential interception
 * may violate federal, state, and local wiretapping laws. Ensure strict compliance
 * with all relevant laws and organizational policies before activating this feature.
 */

import { startModule, stopModule } from './passiveCapture.js';

const MODULE_ID = 'creds';
const pendingPairs = new Map();

export function startCredentialSniffing(interfaceId, onCredentialFound, onError, onComplete) {
  pendingPairs.clear();

  const tsharkArgs = [
    '-Y', 'ftp.request.command == USER or ftp.request.command == PASS or telnet.data or http.authorization contains "Basic" or pop.request.command == USER or pop.request.command == PASS or imap.request contains "LOGIN"',
    '-T', 'fields',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', 'tcp.dstport',
    '-e', 'ftp.request.command',
    '-e', 'ftp.request.arg',
    '-e', 'http.authorization',
    '-e', 'pop.request.command',
    '-e', 'pop.request.data',
    '-e', 'imap.request'
  ];

  function onLineParsed(line) {
    const parts = line.split('\t').map(p => p.trim());
    if (parts.length < 3) return;

    const srcIp = parts[0].split(',')[0];
    const dstIp = parts[1].split(',')[0];
    const port = parts[2].split(',')[0];
    const ftpCmd = parts[3];
    const ftpArg = parts[4];
    const httpAuth = parts[5];
    const popCmd = parts[6];
    const popArg = parts[7];
    const imapReq = parts[8];

    if (!srcIp) return;

    const parseUserPassSequence = (cmd, arg, protocol) => {
      if (cmd === 'USER') {
        pendingPairs.set(srcIp, { username: arg, protocol, dstIp, port });
      } else if (cmd === 'PASS') {
        const pending = pendingPairs.get(srcIp);
        if (pending && pending.protocol === protocol) {
          const masked = arg.length > 2 ? arg[0] + '*'.repeat(arg.length - 2) + arg[arg.length - 1] : '***';
          onCredentialFound({
            protocol, srcIp, dstIp, port,
            username: pending.username,
            password: arg,
            maskedPassword: masked,
            timestamp: Date.now()
          });
          pendingPairs.delete(srcIp);
        }
      }
    };

    if (ftpCmd) {
      parseUserPassSequence(ftpCmd.toUpperCase(), ftpArg, 'FTP');
    } else if (popCmd) {
      parseUserPassSequence(popCmd.toUpperCase(), popArg, 'POP3');
    } else if (httpAuth && httpAuth.startsWith('Basic ')) {
      try {
        const b64 = httpAuth.substring(6);
        const decoded = Buffer.from(b64, 'base64').toString('utf8');
        const [username, password] = decoded.split(':');
        if (username && password !== undefined) {
          const masked = password.length > 2 ? password[0] + '*'.repeat(password.length - 2) + password[password.length - 1] : '***';
          onCredentialFound({
            protocol: 'HTTP Basic', srcIp, dstIp, port,
            username, password: password, maskedPassword: masked, timestamp: Date.now()
          });
        }
      } catch (e) {}
    } else if (imapReq && imapReq.toUpperCase().includes('LOGIN ')) {
      const match = imapReq.match(/LOGIN\s+([^ ]+)\s+(.+)/i);
      if (match) {
        const username = match[1];
        const password = match[2].replace(/"/g, ''); // strip quotes
        const masked = password.length > 2 ? password[0] + '*'.repeat(password.length - 2) + password[password.length - 1] : '***';
        onCredentialFound({
          protocol: 'IMAP', srcIp, dstIp, port,
          username, password, maskedPassword: masked, timestamp: Date.now()
        });
      }
    }
  }

  return startModule(MODULE_ID, interfaceId, tsharkArgs, onLineParsed, onError, onComplete);
}

export function stopCredentialSniffing() {
  return stopModule(MODULE_ID);
}
