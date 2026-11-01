import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-full-admin-'));
process.env.NODE_ENV = 'test';
process.env.SERVEROPS_DATA_DIR = path.join(dir, 'data');
process.env.SERVEROPS_BACKUP_DIR = path.join(dir, 'backup');
process.env.SERVEROPS_ENABLE_LEGACY_INTEGRATIONS = '0';
const full = await import('../app/full-admin.js');
const { SCOPES } = await import('../app/oauth.js');
const { app } = await import('../app/main.js');
const admin = await import('../app/admin.js');
const store = await import('../app/storage.js');
const { runWithRequestContext } = await import('../app/request-context.js');
const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
const { StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');
const oauth = await import('../app/oauth.js');
const { config } = await import('../app/config.js');
const crypto = await import('node:crypto');

test('permanent token supports MCP mutations, audit, immediate session revocation and default denial', async () => {
  const issued = full.createToken('isolated-test');
  assert.equal(issued.expires_at, null);
  assert.ok(!JSON.stringify(full.listTokens()).includes(issued.token));
  assert.throws(() => full.verifyToken(issued.token.slice(0,-1) + '!', SCOPES));
  assert.throws(() => admin.write(path.join(dir,'denied'), 'x'));
  const auth = full.verifyToken(issued.token, SCOPES);
  assert.equal(full.hasFullAdmin({...auth, scopes:['system:read']}), false);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const client = new Client({ name:'full-admin-test', version:'1' });
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), { requestInit: { headers:{ Authorization:`Bearer ${issued.token}` } } });
  try {
    await client.connect(transport);
    const file = path.join(dir,'authorized.txt');
    const write = await client.callTool({name:'root_write', arguments:{path:file,content:'permanent admin'}});
    assert.ok(!write.isError, JSON.stringify(write));
    assert.equal(fs.readFileSync(file,'utf8'), 'permanent admin');
    const command = await client.callTool({name:'system_execute',arguments:{command:'printf full-admin-ok', cwd:dir, max_output_bytes:4096}});
    assert.ok(!command.isError, JSON.stringify(command));
    assert.ok(JSON.stringify(command).includes('full-admin-ok'));
    const audits = store.db.prepare("SELECT detail FROM audit WHERE action='full_admin_operation_authorized'").all();
    assert.ok(audits.length >= 2);
    assert.ok(!JSON.stringify(audits).includes(issued.token));
    assert.equal(full.revokeToken(issued.id), 1);
    assert.throws(() => full.verifyToken(issued.token,SCOPES));
    assert.equal(full.hasFullAdmin(auth),false);
    runWithRequestContext({ authInfo:auth }, () => assert.throws(() => admin.write(file,'denied')));
    await assert.rejects(() => client.callTool({name:'root_write',arguments:{path:file,content:'denied'}}));
    assert.equal(fs.readFileSync(file,'utf8'),'permanent admin');
  } finally { await client.close().catch(()=>{}); await new Promise(resolve=>server.close(resolve)); }
});

test('explicit OAuth grant persists, works in MCP, revokes live and retains default denial for other clients', async () => {
  const clientId = 'https://chatgpt.com/oauth/client.json';
  const refresh = crypto.randomBytes(48).toString('base64url');
  const digest = crypto.createHash('sha256').update(refresh).digest('hex');
  store.db.prepare('INSERT INTO oauth_refresh_tokens VALUES(?,?,?,?,?,?,NULL)').run(digest,clientId,SCOPES.join(' '),oauth.RESOURCE,config.ownerSubject,store.now()+3600);
  assert.throws(()=>full.grantOAuthClient('untrusted-client'),/authenticated_admin_client_required/);
  assert.throws(()=>full.grantOAuthClient(clientId,'another-owner'),/owner_subject_required/);
  const grant=full.grantOAuthClient(clientId);
  assert.equal(grant.expires_at,null);
  const t=store.now();
  const access=oauth.jwt({iss:config.oauthIssuer,aud:oauth.RESOURCE,sub:config.ownerSubject,client_id:clientId,scope:SCOPES.join(' '),iat:t,nbf:t,exp:t+3600,jti:crypto.randomUUID()});
  assert.equal(full.hasFullAdmin(oauth.verifyAccessToken(access)),true);
  assert.equal(full.hasFullAdmin({...oauth.verifyAccessToken(access),clientId:'other-client'}),false);
  assert.equal(full.hasFullAdmin({...oauth.verifyAccessToken(access),scopes:['system:read']}),false);
  store.db.prepare('UPDATE oauth_refresh_tokens SET expires_at=? WHERE token_hash=?').run(t-10,digest);
  assert.throws(()=>oauth.refreshTokens({refreshToken:refresh,clientId:'other-client'}),/invalid_grant/);
  const renewed=oauth.refreshTokens({refreshToken:refresh,clientId});
  assert.ok(renewed.access_token);
  assert.throws(()=>oauth.refreshTokens({refreshToken:refresh,clientId}),/invalid_grant/);
  const server=app.listen(0,'127.0.0.1');
  await new Promise(resolve=>server.once('listening',resolve));
  const c=new Client({name:'oauth-full-admin-test',version:'1'});
  try {
    await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`),{requestInit:{headers:{Authorization:'Bearer '+access}}}));
    const file=path.join(dir,'oauth-authorized.txt');
    const first=await c.callTool({name:'root_write',arguments:{path:file,content:'oauth-full-admin'}});
    assert.ok(!first.isError,JSON.stringify(first));
    assert.equal(full.revokeOAuthClient(clientId).revoked,1);
    assert.equal(full.hasFullAdmin(oauth.verifyAccessToken(access)),false);
    const denied=await c.callTool({name:'root_write',arguments:{path:file,content:'denied'}});
    assert.equal(denied.isError,true);
    assert.equal(fs.readFileSync(file,'utf8'),'oauth-full-admin');
    const renewedHash=crypto.createHash('sha256').update(renewed.refresh_token).digest('hex');
    store.db.prepare('UPDATE oauth_refresh_tokens SET expires_at=? WHERE token_hash=?').run(t-10,renewedHash);
    assert.throws(()=>oauth.refreshTokens({refreshToken:renewed.refresh_token,clientId}),/invalid_grant/);
    assert.throws(()=>oauth.verifyAccessToken(oauth.jwt({iss:config.oauthIssuer,aud:oauth.RESOURCE,sub:config.ownerSubject,client_id:clientId,scope:SCOPES.join(' '),iat:t-3600,exp:t-1})),/token_expired/);
  } finally { full.revokeOAuthClient(clientId); await c.close().catch(()=>{}); await new Promise(resolve=>server.close(resolve)); }
});

test('password recovery revokes permanent credentials and persistent OAuth grants', async () => {
  const { resetPasswordLocally } = await import('../app/bootstrap.js');
  const issued = full.createToken('recovery-regression');
  const id = 'recovery-client';
  store.db.prepare('INSERT INTO full_admin_oauth_grants VALUES (?,?,?,NULL)').run(id, config.ownerSubject, store.now());
  assert.ok(full.hasOAuthFullAdmin(id, config.ownerSubject));
  resetPasswordLocally('RecoveryRegressionPassword123!');
  assert.throws(() => full.verifyToken(issued.token, SCOPES));
  assert.equal(full.hasOAuthFullAdmin(id, config.ownerSubject), false);
});

test('Full Admin does not bypass OAuth session revocation', () => {
  const clientId = 'session-bound-admin';
  const refresh = crypto.randomBytes(48).toString('base64url');
  const digest = crypto.createHash('sha256').update(refresh).digest('hex');
  store.db.prepare('INSERT INTO oauth_refresh_tokens VALUES(?,?,?,?,?,?,NULL)').run(digest, clientId, SCOPES.join(' '), oauth.RESOURCE, config.ownerSubject, store.now() + 3600);
  full.grantOAuthClient(clientId);
  const renewed = oauth.refreshTokens({ refreshToken: refresh, clientId });
  const auth = oauth.verifyAccessToken(renewed.access_token);
  assert.ok(auth.token.sid);
  assert.ok(full.hasFullAdmin(auth));
  oauth.revokeToken(renewed.refresh_token);
  assert.throws(() => oauth.verifyAccessToken(renewed.access_token), /invalid_session/);
  full.revokeOAuthClient(clientId);
});
