import test from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { registerLegacySystemCompat } from '../app/legacy-system-compat.js';

test('legacy system aliases reuse native protected handlers and logs require admin', async () => {
  const tools = new Map();
  const originalService = { definition: { inputSchema: { action: z.string() } }, handler: () => 'native-service' };
  const originalEnvironment = { definition: { inputSchema: {} }, handler: () => 'native-environment' };
  const server = { registerTool(name, definition, handler) { tools.set(name, { definition, handler }); } };
  registerLegacySystemCompat(server, {
    registeredTools: new Map([['system_service_manage', originalService], ['system_environment_inspect', originalEnvironment]]),
    authInfo: { scopes: ['system:read'] }, z,
    result: value => value, fail: error => ({ isError: true, error: String(error) }),
    oauthScheme: scopes => [{ type: 'oauth2', scopes }],
    requireToolScope: (auth, scope, handler) => async (...args) => auth.scopes.includes(scope) ? handler(...args) : { isError: true, error: `Missing OAuth scope: ${scope}` }
  });
  assert.equal(tools.get('system_service').handler, originalService.handler);
  assert.equal(tools.get('system_service').definition, originalService.definition);
  assert.equal(tools.get('system_environment').handler, originalEnvironment.handler);
  for (const name of ['system_logs', 'system_logs_read']) {
    const tool = tools.get(name);
    assert.deepEqual(tool.definition._meta.securitySchemes[0].scopes, ['system:admin']);
    assert.equal((await tool.handler({ lines: 1 })).isError, true);
    const schema = z.object(tool.definition.inputSchema);
    assert.equal(schema.safeParse({ lines: 5001 }).success, false);
    assert.equal(schema.safeParse({ unit: 'service; rm -rf /' }).success, false);
    assert.equal(schema.safeParse({ since: 'today\n' }).success, false);
    assert.equal(schema.safeParse({ unit: 'serverops.service', lines: 10, priority: 'err', since: '1 hour ago' }).success, true);
  }
});