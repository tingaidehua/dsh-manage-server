import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

function run(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', shell: process.platform === 'win32' })
  return {
    status: r.status,
    stdout: (r.stdout || '').trim(),
    stderr: (r.stderr || '').trim(),
  }
}

export function summary() {
  const mem = {
    totalMb: Math.round(os.totalmem() / 1024 / 1024),
    freeMb: Math.round(os.freemem() / 1024 / 1024),
  }
  const load = os.loadavg()
  const uptimeSec = Math.round(os.uptime())
  const disk = run('bash', ['-lc', "df -h / | awk 'NR==2{print $2,$3,$4,$5}'"])
  const units = run('bash', ['-lc', 'systemctl is-active dsh-web nginx frps ssh 2>/dev/null; true'])
  const ports = run('bash', ['-lc', "ss -tlnp | awk 'NR>1{print $4}' | sed 's/.*://' | sort -n | uniq | head -40"])
  return {
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    mem,
    load,
    uptimeSec,
    disk: disk.stdout,
    services: units.stdout,
    listeningPorts: ports.stdout.split(/\s+/).filter(Boolean),
    node: process.version,
  }
}

export function alerts() {
  const items = []
  const df = run('bash', ['-lc', "df -P / | awk 'NR==2{gsub(/%/,\"\",$5); print $5}'"])
  const used = Number(df.stdout || '0')
  if (used >= 85) items.push({ level: 'warn', code: 'disk', message: `root disk ${used}% used` })

  for (const svc of ['nginx', 'dsh-web', 'frps']) {
    const st = run('systemctl', ['is-active', svc])
    if (st.stdout !== 'active') {
      items.push({ level: 'crit', code: 'service', message: `${svc} is ${st.stdout || st.stderr || 'unknown'}` })
    }
  }

  const domain = process.env.DSH_DOMAIN || 'tingaidehua.top'
  const cert = `/etc/letsencrypt/live/${domain}/fullchain.pem`
  if (fs.existsSync(cert)) {
    const end = run('openssl', ['x509', '-in', cert, '-noout', '-enddate'])
    const notAfter = (end.stdout || '').replace('notAfter=', '')
    const days = Math.floor((Date.parse(notAfter) - Date.now()) / 86400000)
    if (Number.isFinite(days) && days < 14) {
      items.push({ level: 'warn', code: 'tls', message: `TLS for ${domain} expires in ${days} days (${notAfter})` })
    }
  } else {
    items.push({ level: 'warn', code: 'tls', message: `no cert at ${cert}` })
  }

  const failed = run('bash', ['-lc', 'systemctl --failed --no-legend | head -20'])
  if (failed.stdout) {
    items.push({ level: 'warn', code: 'systemd-failed', message: failed.stdout })
  }

  return { ok: items.filter((i) => i.level === 'crit').length === 0, items }
}

export function securityBaseline() {
  const sshd = run('bash', ['-lc', "grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config 2>/dev/null | head -20"])
  const uau = run('bash', ['-lc', 'systemctl is-enabled unattended-upgrades 2>/dev/null || echo disabled'])
  const world = run('bash', ['-lc', "ss -tlnp | awk 'NR>1 && $4 ~ /0\\.0\\.0\\.0:|:\\*:/ {print $4,$6}' | head -30"])
  const envPerm = (() => {
    const p = path.join(os.homedir(), '.env')
    if (!fs.existsSync(p)) return { path: p, exists: false }
    const mode = (fs.statSync(p).mode & 0o777).toString(8)
    return { path: p, exists: true, mode, ok: mode === '600' || mode === '400' }
  })()
  return {
    note: 'Read-only baseline — not a penetration test.',
    sshd: sshd.stdout,
    unattendedUpgrades: uau.stdout,
    publicListeners: world.stdout,
    envFile: envPerm,
    recommendations: [
      'Keep dsh-web on 127.0.0.1 only; expose via nginx HTTPS',
      'Do not open frps dashboard (7500) to the public internet',
      'Rotate tokens if they ever appear in chat or git history',
      'Prefer PubkeyAuthentication; restrict PasswordAuthentication when possible',
    ],
  }
}
