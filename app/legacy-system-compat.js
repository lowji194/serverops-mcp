import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);

export function registerLegacySystemCompat(server, { registeredTools, authInfo, z, result, fail, requireToolScope, oauthScheme }) {
  for (const [alias, original] of [['system_service', 'system_service_manage'], ['system_environment', 'system_environment_inspect']]) {
    const tool = registeredTools.get(original);
    if (!tool) throw new Error(`Missing native tool: ${original}`);
    server.registerTool(alias, tool.definition, tool.handler);
  }
  const definition = {
    title: 'Read bounded system journal',
    description: 'Reads bounded system journal entries. Sensitive host logs require system:admin.',
    inputSchema: {
      unit: z.string().regex(/^[A-Za-z0-9@_.:-]{1,200}$/).optional(),
      lines: z.number().int().min(1).max(5000).default(200),
      priority: z.enum(['emerg','alert','crit','err','warning','notice','info','debug']).optional(),
      since: z.string().min(1).max(120).regex(/^[^\x00-\x1f\x7f]+$/).optional()
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  };
  const handler = requireToolScope(authInfo, 'system:admin', async ({ unit, lines = 200, priority, since }) => {
    try {
      const args = ['--no-pager', '--output=short-iso', '--lines', String(lines)];
      if (unit) args.push('--unit', unit);
      if (priority) args.push('--priority', priority);
      if (since) args.push('--since', since);
      const { stdout, stderr } = await execFileAsync('/usr/bin/journalctl', args, { timeout: 15000, maxBuffer: 4 * 1024 * 1024, env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' } });
      return result({ stdout, stderr, unit: unit || null, lines });
    } catch (error) { return fail(error); }
  });
  server.registerTool('system_logs', definition, handler);
  server.registerTool('system_logs_read', definition, handler);
}