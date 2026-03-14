/**
 * Feature 5C — Container & Cloud Enumeration
 *
 * Probes discovered hosts for signs of Docker daemon, Kubernetes components,
 * etcd, Consul, Vault, cloud metadata endpoints, Prometheus, and Portainer.
 *
 * All probes are pure Node.js http/https/net — zero external dependencies.
 * Cancellation via AbortController; concurrency controlled by a semaphore.
 */

import http  from 'http';
import https from 'https';
import net   from 'net';
import { ipRegex, CLOUD_METADATA_PATHS } from '../shared/networkConstants.js';
import { IPC_CHANNELS } from '../shared/ipc.js';

// ─── Active session ───────────────────────────────────────────────────────────

let activeController = null;

// ─── Semaphore ────────────────────────────────────────────────────────────────

function createSemaphore(maxConcurrent) {
  let running = 0;
  const queue = [];
  return {
    acquire() {
      return new Promise(resolve => {
        const tryRun = () => {
          if (running < maxConcurrent) { running++; resolve(() => { running--; if (queue.length) queue.shift()(); }); }
          else queue.push(tryRun);
        };
        tryRun();
      });
    }
  };
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

/**
 * Make an HTTP/HTTPS GET request. Returns { statusCode, body, headers } or throws.
 * @param {object} opts - { protocol, host, port, path, headers, timeoutMs }
 * @param {AbortSignal} signal
 */
function httpGet(opts, signal) {
  const { protocol = 'http', host, port, path = '/', headers = {}, timeoutMs = 4000 } = opts;
  const lib = protocol === 'https' ? https : http;

  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('Aborted'));

    const reqOpts = {
      hostname: host,
      port,
      path,
      method: 'GET',
      headers,
      timeout: timeoutMs,
      // Accept self-signed certs for container APIs
      rejectUnauthorized: false,
      checkServerIdentity: () => undefined,
    };

    const req = lib.request(reqOpts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       Buffer.concat(chunks).toString('utf8').slice(0, 2000),
        });
      });
      res.on('error', reject);
    });

    req.on('timeout', () => { req.destroy(new Error('Timeout')); });
    req.on('error', reject);

    const abortHandler = () => { req.destroy(new Error('Aborted')); };
    signal?.addEventListener('abort', abortHandler, { once: true });

    req.on('close', () => signal?.removeEventListener('abort', abortHandler));

    req.end();
  });
}

/** TCP connect probe — just checks if a port is open. */
function tcpConnect(host, port, timeoutMs = 2000) {
  return new Promise(resolve => {
    const s = new net.Socket();
    s.setTimeout(timeoutMs);
    s.connect(port, host, () => { s.destroy(); resolve(true); });
    s.on('timeout', () => { s.destroy(); resolve(false); });
    s.on('error',   () => { s.destroy(); resolve(false); });
  });
}

// ─── Finding builder ──────────────────────────────────────────────────────────

function buildFinding(ip, service, port, severity, title, description, evidence, remediation, references = [], rawResponse = '') {
  return {
    ip,
    service,
    port,
    severity,
    title,
    description,
    evidence,
    remediation,
    references,
    rawResponse: String(rawResponse).slice(0, 500),
    timestamp: Date.now(),
  };
}

// ─── Individual probe functions ───────────────────────────────────────────────

export async function probeDockerDaemon(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'http', host: ip, port: 2375, path: '/version', timeoutMs: 4000 }, signal);
    if (res.statusCode === 200 && res.body.includes('ApiVersion')) {
      return buildFinding(
        ip, 'docker-daemon', 2375, 'critical',
        'Unauthenticated Docker Daemon',
        'Docker Remote API is exposed on TCP port 2375 without TLS or authentication. An attacker can run arbitrary containers, mount the host filesystem, and achieve full root code execution on the host.',
        `HTTP ${res.statusCode} — ${res.body.slice(0, 200)}`,
        'Bind Docker socket to unix:///var/run/docker.sock only, or enforce TLS mutual authentication. Remove -H tcp:// from dockerd flags. Apply firewall rules to block port 2375 externally.',
        ['https://docs.docker.com/engine/security/protect-access/'],
        res.body
      );
    }
  } catch { /* port closed or not docker */ }
  return null;
}

export async function probeDockerDaemonTLS(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'https', host: ip, port: 2376, path: '/version', timeoutMs: 4000 }, signal);
    if (res.statusCode === 200 && res.body.includes('ApiVersion')) {
      return buildFinding(
        ip, 'docker-daemon-tls', 2376, 'warning',
        'Docker Daemon Exposed (TLS)',
        'Docker Remote API is exposed on TCP port 2376 with TLS. While TLS provides encryption, mutual certificate authentication should be enforced. An attacker with access to the network can still attempt unauthorized API calls.',
        `HTTPS ${res.statusCode} — ${res.body.slice(0, 200)}`,
        'Enable TLS mutual authentication (--tlsverify) to require client certificates. Restrict port 2376 to known management IPs via firewall.',
        ['https://docs.docker.com/engine/security/protect-access/'],
        res.body
      );
    }
  } catch { /* expected: self-signed, port closed */ }
  return null;
}

export async function probeKubelet(ip, signal) {
  const findings = [];

  // Port 10250 — Kubelet API (unauthenticated, CRITICAL)
  try {
    const res = await httpGet({ protocol: 'https', host: ip, port: 10250, path: '/pods', timeoutMs: 4000 }, signal);
    if (res.statusCode === 200 && (res.body.includes('items') || res.body.includes('Pod'))) {
      findings.push(buildFinding(
        ip, 'kubelet', 10250, 'critical',
        'Unauthenticated Kubelet API',
        'The Kubernetes Kubelet API is exposed on port 10250 without authentication. An attacker can list all running pods, execute commands inside containers, read environment variables (including secrets), and escalate to full cluster compromise.',
        `HTTPS ${res.statusCode} — Pod list accessible without credentials`,
        'Enable Kubelet authentication (--authentication-token-webhook=true) and authorization (--authorization-mode=Webhook). Apply NetworkPolicy to restrict port 10250 access.',
        ['https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/'],
        res.body
      ));
    } else if (res.statusCode === 401 || res.statusCode === 403) {
      findings.push(buildFinding(
        ip, 'kubelet', 10250, 'info',
        'Kubelet API Detected (Auth Required)',
        'The Kubernetes Kubelet API is exposed on port 10250. Authentication is enforced (HTTP ' + res.statusCode + '). Verify that authorization mode is set to Webhook and not AlwaysAllow.',
        `HTTPS ${res.statusCode} — Authentication enforced`,
        'Ensure --authorization-mode=Webhook is set. Confirm NodeRestriction admission plugin is enabled. Restrict network access to port 10250.',
        ['https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/'],
        ''
      ));
    }
  } catch { /* port closed */ }

  // Port 10255 — Kubelet read-only API (deprecated, WARNING)
  try {
    const res = await httpGet({ protocol: 'http', host: ip, port: 10255, path: '/pods', timeoutMs: 3000 }, signal);
    if (res.statusCode === 200) {
      findings.push(buildFinding(
        ip, 'kubelet-ro', 10255, 'warning',
        'Kubelet Read-Only API Exposed',
        'The deprecated Kubelet read-only API is exposed on port 10255. This API provides unauthenticated read access to pod metadata, running containers, and resource usage. It should be disabled in modern clusters.',
        `HTTP ${res.statusCode} — Unauthenticated read access`,
        'Disable the read-only port by setting --read-only-port=0 in the Kubelet configuration.',
        ['https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/'],
        res.body
      ));
    }
  } catch { /* port closed */ }

  return findings;
}

export async function probeKubeAPI(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'https', host: ip, port: 6443, path: '/version', timeoutMs: 4000 }, signal);
    if (res.statusCode === 200 && res.body.includes('gitVersion')) {
      return buildFinding(
        ip, 'kube-api', 6443, 'critical',
        'Unauthenticated Kubernetes API Server',
        'The Kubernetes API server is accessible on port 6443 without authentication. An attacker can enumerate the entire cluster, list secrets, deploy malicious workloads, and achieve full cluster takeover.',
        `HTTPS ${res.statusCode} — ${res.body.slice(0, 200)}`,
        'Ensure the API server has --anonymous-auth=false. Enforce RBAC and enable audit logging. Restrict API server access to management IPs via firewall or cloud security groups.',
        ['https://kubernetes.io/docs/reference/access-authn-authz/authentication/'],
        res.body
      );
    }
    if (res.statusCode === 401 || res.statusCode === 403) {
      return buildFinding(
        ip, 'kube-api', 6443, 'info',
        'Kubernetes API Server Detected (Auth Required)',
        'A Kubernetes API server was detected on port 6443. Authentication is enforced. Verify RBAC rules and ensure no cluster-admin bindings exist for service accounts or anonymous users.',
        `HTTPS ${res.statusCode} — Authentication enforced`,
        'Audit RBAC bindings with: kubectl get clusterrolebindings -o wide. Ensure --anonymous-auth=false.',
        ['https://kubernetes.io/docs/reference/access-authn-authz/rbac/'],
        ''
      );
    }
  } catch { /* port closed or TLS error */ }
  return null;
}

export async function probeEtcd(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'http', host: ip, port: 2379, path: '/version', timeoutMs: 3000 }, signal);
    if (res.statusCode === 200 && (res.body.includes('etcdserver') || res.body.includes('etcdcluster'))) {
      return buildFinding(
        ip, 'etcd', 2379, 'critical',
        'Unauthenticated etcd Cluster',
        'etcd is accessible on port 2379 without authentication. An attacker can read ALL Kubernetes secrets (including service account tokens, certificates, and application secrets), modify cluster state, and gain full control over any Kubernetes cluster backed by this etcd.',
        `HTTP ${res.statusCode} — etcd version endpoint accessible`,
        'Enable TLS mutual authentication on etcd (--cert-file, --key-file, --client-cert-auth). Restrict port 2379 to Kubernetes control plane IPs only. Rotate all secrets immediately if exposed.',
        ['https://etcd.io/docs/v3.5/op-guide/security/'],
        res.body
      );
    }
  } catch { /* port closed */ }
  return null;
}

export async function probeCloudMetadata(ip, signal) {
  // Probe each cloud metadata endpoint
  for (const { path, provider } of CLOUD_METADATA_PATHS) {
    try {
      const res = await httpGet({
        protocol: 'http',
        host: ip,
        port: 80,
        path,
        headers: { 'Metadata-Flavor': 'Google', 'Metadata': 'true' },
        timeoutMs: 3000,
      }, signal);

      if (signal?.aborted) return null;

      // Valid metadata responses: 200 with content, or specific provider headers
      if (res.statusCode === 200 && res.body.length > 10) {
        return buildFinding(
          ip, 'cloud-metadata', 80, 'critical',
          `Cloud Metadata Endpoint Accessible (${provider})`,
          `The cloud instance metadata service (IMDS) endpoint for ${provider} is accessible from this host. This is typically exploited via SSRF vulnerabilities to obtain IAM credentials, API tokens, and instance configuration data that can lead to cloud account compromise.`,
          `HTTP ${res.statusCode} on ${path} — ${res.body.slice(0, 150)}`,
          'Block outbound requests to 169.254.169.254 at the network/firewall layer unless required. Use IMDSv2 (AWS) which requires session-oriented requests. Audit and remove SSRF vulnerabilities in web applications.',
          ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
           'https://cloud.google.com/compute/docs/metadata/overview'],
          res.body
        );
      }
    } catch { /* endpoint not present */ }
  }
  return null;
}

export async function probeConsul(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'http', host: ip, port: 8500, path: '/v1/status/leader', timeoutMs: 3000 }, signal);
    if (res.statusCode === 200) {
      return buildFinding(
        ip, 'consul', 8500, 'warning',
        'Consul HTTP API Exposed',
        'HashiCorp Consul HTTP API is accessible on port 8500. Without ACL tokens, an attacker can read service registry data, key/value store contents, and potentially modify DNS-based service discovery to redirect traffic.',
        `HTTP ${res.statusCode} — Consul leader: ${res.body.slice(0, 100)}`,
        'Enable Consul ACLs (acl.enabled = true) and enforce default-deny policy. Bind Consul HTTP API to localhost or a private interface. Restrict port 8500 via firewall.',
        ['https://developer.hashicorp.com/consul/docs/security/acl'],
        res.body
      );
    }
  } catch { /* port closed */ }
  return null;
}

export async function probeVault(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'http', host: ip, port: 8200, path: '/v1/sys/health', timeoutMs: 3000 }, signal);
    if (res.statusCode === 200 || res.statusCode === 429 || res.statusCode === 472 || res.statusCode === 473) {
      const isSealed = res.body.includes('"sealed":true');
      const severity = isSealed ? 'info' : 'warning';
      return buildFinding(
        ip, 'vault', 8200, severity,
        isSealed ? 'HashiCorp Vault Detected (Sealed)' : 'HashiCorp Vault HTTP API Exposed',
        isSealed
          ? 'HashiCorp Vault is running on port 8200 and is in a sealed state. While sealed vaults cannot decrypt data, the endpoint is network-accessible. Verify this exposure is intentional.'
          : 'HashiCorp Vault HTTP API is accessible on port 8200. Vault manages secrets, encryption keys, and PKI infrastructure. Unauthorized access could lead to secrets disclosure.',
        `HTTP ${res.statusCode} — ${res.body.slice(0, 150)}`,
        'Restrict port 8200 to authorized management hosts via firewall. Enable Vault audit logging. Ensure TLS is configured. Rotate all secrets if unauthorized access is confirmed.',
        ['https://developer.hashicorp.com/vault/docs/configuration/listener/tcp'],
        res.body
      );
    }
  } catch { /* port closed */ }
  return null;
}

export async function probePrometheus(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'http', host: ip, port: 9090, path: '/-/ready', timeoutMs: 3000 }, signal);
    if (res.statusCode === 200) {
      return buildFinding(
        ip, 'prometheus', 9090, 'info',
        'Prometheus Metrics Server Exposed',
        'A Prometheus metrics server was detected on port 9090. Prometheus dashboards can expose sensitive infrastructure metrics, service topology, and internal IP addresses that aid in reconnaissance.',
        `HTTP ${res.statusCode} — Prometheus ready endpoint accessible`,
        'Restrict Prometheus UI to localhost or VPN. Enable authentication via a reverse proxy (nginx basic auth, OAuth2 Proxy). Do not expose Prometheus directly to untrusted networks.',
        ['https://prometheus.io/docs/prometheus/latest/configuration/https/'],
        ''
      );
    }
  } catch { /* port closed */ }
  return null;
}

export async function probePortainer(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'http', host: ip, port: 9000, path: '/api/status', timeoutMs: 3000 }, signal);
    if (res.statusCode === 200 && res.body.includes('Version')) {
      return buildFinding(
        ip, 'portainer', 9000, 'info',
        'Portainer Docker Management UI Exposed',
        'Portainer, a Docker management UI, is accessible on port 9000. If default credentials (admin/admin) or weak passwords are in use, an attacker can manage all Docker containers, images, volumes, and networks on this host.',
        `HTTP ${res.statusCode} — ${res.body.slice(0, 150)}`,
        'Change the default admin password immediately. Enable HTTPS for Portainer. Restrict access to port 9000 via firewall. Enable Portainer RBAC and disable unused features.',
        ['https://docs.portainer.io/admin/settings'],
        res.body
      );
    }
  } catch { /* port closed */ }
  return null;
}

export async function probeGrafana(ip, signal) {
  try {
    const res = await httpGet({ protocol: 'http', host: ip, port: 3000, path: '/api/health', timeoutMs: 3000 }, signal);
    if (res.statusCode === 200 && res.body.includes('database')) {
      return buildFinding(
        ip, 'grafana', 3000, 'info',
        'Grafana Dashboard Exposed',
        'A Grafana dashboard was detected on port 3000. Grafana dashboards can expose monitoring data, datasource credentials, and internal network topology. Default admin credentials (admin/admin) are a common misconfiguration.',
        `HTTP ${res.statusCode} — Grafana health endpoint accessible`,
        'Change the default admin/admin password. Enable HTTPS. Restrict port 3000 to VPN or management network. Disable anonymous access (auth.anonymous.enabled = false).',
        ['https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/'],
        ''
      );
    }
  } catch { /* port closed */ }
  return null;
}

// ─── Full fingerprint (runs all probes for one IP) ────────────────────────────

/**
 * Runs all probes for a single IP address and returns an array of findings.
 * @param {string} ip
 * @param {AbortSignal} signal
 * @param {(finding: object) => void} onFinding
 * @param {string[]} enabledProbes - subset of probe keys to run (or empty for all)
 */
export async function fingerprint(ip, signal, onFinding, enabledProbes = []) {
  const all = enabledProbes.length === 0;
  const enabled = new Set(enabledProbes);
  const findings = [];

  const run = async (key, fn) => {
    if (!all && !enabled.has(key)) return;
    if (signal?.aborted) return;
    try {
      const result = await fn();
      if (Array.isArray(result)) {
        for (const f of result) { if (f) { findings.push(f); onFinding(f); } }
      } else if (result) {
        findings.push(result);
        onFinding(result);
      }
    } catch { /* swallow; individual probe failure should not stop enumeration */ }
  };

  await run('docker',           () => probeDockerDaemon(ip, signal));
  await run('docker-tls',       () => probeDockerDaemonTLS(ip, signal));
  await run('kubernetes',       () => probeKubelet(ip, signal));
  await run('kube-api',         () => probeKubeAPI(ip, signal));
  await run('etcd',             () => probeEtcd(ip, signal));
  await run('cloud-metadata',   () => probeCloudMetadata(ip, signal));
  await run('consul',           () => probeConsul(ip, signal));
  await run('vault',            () => probeVault(ip, signal));
  await run('prometheus',       () => probePrometheus(ip, signal));
  await run('portainer',        () => probePortainer(ip, signal));
  await run('grafana',          () => probeGrafana(ip, signal));

  return findings;
}

// ─── Main enumeration loop ────────────────────────────────────────────────────

/**
 * Start container/cloud enumeration across a list of targets.
 * @param {object} opts
 * @param {string[]} opts.targets
 * @param {string[]} opts.probes       - enabled probe keys (empty = all)
 * @param {number}   opts.concurrency  - max simultaneous hosts (default 10)
 * @param {number}   opts.timeoutMs    - per-probe timeout ms (not used yet; reserved)
 * @param {Function} onFinding
 * @param {Function} onProgress
 * @param {Function} onComplete
 * @param {Function} onError
 */
export async function startCloudEnum(opts, onFinding, onProgress, onComplete, onError) {
  if (activeController) {
    onError(new Error('A cloud enumeration session is already running.'));
    return;
  }

  const targets = (opts?.targets || []).filter(ip => ipRegex.test(ip));
  if (targets.length === 0) {
    onError(new Error('No valid IP targets provided for cloud enumeration.'));
    return;
  }

  const concurrency  = Math.min(Math.max(1, opts?.concurrency  ?? 10), 50);
  const enabledProbes = Array.isArray(opts?.probes) ? opts.probes : [];

  activeController = new AbortController();
  const { signal } = activeController;

  const sem = createSemaphore(concurrency);
  let completed = 0;
  const total = targets.length;
  const allFindings = [];
  const startTime = Date.now();

  try {
    await Promise.all(targets.map(async (ip) => {
      const release = await sem.acquire();
      try {
        if (signal.aborted) return;
        const hostFindings = await fingerprint(ip, signal, (f) => {
          allFindings.push(f);
          onFinding(f);
        }, enabledProbes);
        void hostFindings; // findings already emitted via onFinding
      } finally {
        release();
        completed++;
        onProgress({
          completed,
          total,
          percent: Math.floor((completed / total) * 100),
          currentIp: ip,
        });
      }
    }));
  } catch (err) {
    if (err.message !== 'Aborted') onError(err);
  } finally {
    const wasAborted = signal.aborted;
    activeController = null;
    onComplete({
      findings:  allFindings.length,
      critical:  allFindings.filter(f => f.severity === 'critical').length,
      warning:   allFindings.filter(f => f.severity === 'warning').length,
      info:      allFindings.filter(f => f.severity === 'info').length,
      elapsed:   Date.now() - startTime,
      aborted:   wasAborted,
    });
  }
}

export function stopCloudEnum() {
  if (activeController) {
    activeController.abort();
    activeController = null;
  }
}

export function cleanupCloudEnum() {
  stopCloudEnum();
}

// ─── IPC Handler Registration ─────────────────────────────────────────────────

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.CLOUDENUM_START, async (_event, options) => {
    if (!options || typeof options !== 'object') {
      return { status: 'error', error: 'Invalid options payload' };
    }

    // Validate targets — must be IPs matching ipRegex
    if (!Array.isArray(options.targets) || options.targets.length === 0) {
      return { status: 'error', error: 'No targets specified.' };
    }

    const validTargets = options.targets.filter(ip => typeof ip === 'string' && ipRegex.test(ip));
    if (validTargets.length === 0) {
      return { status: 'error', error: 'No valid IP addresses in targets list.' };
    }

    startCloudEnum(
      { ...options, targets: validTargets },
      (finding)  => getWindow()?.webContents.send(IPC_CHANNELS.CLOUDENUM_FINDING,  finding),
      (progress) => getWindow()?.webContents.send(IPC_CHANNELS.CLOUDENUM_PROGRESS, progress),
      (complete) => getWindow()?.webContents.send(IPC_CHANNELS.CLOUDENUM_COMPLETE, complete),
      (err)      => getWindow()?.webContents.send(IPC_CHANNELS.CLOUDENUM_ERROR,    { message: err.message })
    );

    return { status: 'started', targets: validTargets.length };
  });

  ipcMain.handle(IPC_CHANNELS.CLOUDENUM_STOP, async () => {
    stopCloudEnum();
    return { status: 'stopped' };
  });
}
