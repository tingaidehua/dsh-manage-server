import { summary, alerts, securityBaseline } from './lib/server-ops.js'
import { registerJsonTool } from './lib/register-json-tool.js'

export const name = 'dsh-manage-server'
export const inject = ['tools']

export function apply(ctx) {
  registerJsonTool(ctx, {
    name: 'server.summary',
    description: 'CPU/mem/disk, key systemd units, listening ports snapshot',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    execute: async () => summary(),
  })
  registerJsonTool(ctx, {
    name: 'server.alerts',
    description: 'Disk, service, TLS expiry, failed units alerts',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    execute: async () => alerts(),
  })
  registerJsonTool(ctx, {
    name: 'server.security_baseline',
    description: 'Read-only SSH/update/listener baseline checklist (not an attack scanner)',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    execute: async () => securityBaseline(),
  })
  console.log('[dsh-manage-server] tools registered')
}
