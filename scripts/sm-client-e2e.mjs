// Opt-in real-client check: npm run test:e2e:sm-clients (Node, Go, tar and unzip required).
// Downloads pinned official clients into the OS temp directory; all accounts/data are local fixtures.
import assert from 'node:assert/strict';
import { createHash, hkdfSync, pbkdf2Sync, randomBytes, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const scriptRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(process.env.SM_E2E_REPO_ROOT || scriptRoot);
const tools = join(tmpdir(), 'nodewarden-sm-client-tools');
const run = mkdtempSync(join(tmpdir(), 'nodewarden-sm-client-run-'));
const env = { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: 'true' };
for (const key of Object.keys(env)) if (/proxy/i.test(key)) delete env[key];
mkdirSync(tools, { recursive: true });
const exec = (command, args, options = {}) => {
  const result = spawnSync(command, args, { cwd: repo, env, encoding: 'utf8', ...options });
  assert.equal(result.status, 0, `${command} ${args.slice(0, 2).join(' ')} failed: ${result.stderr || result.error || result.stdout}`);
  return result.stdout.trim();
};
const download = async (url, path) => {
  const response = await fetch(url);
  assert.equal(response.status, 200, `Download ${url}: ${response.status}`);
  writeFileSync(path, Buffer.from(await response.arrayBuffer()));
};

console.log(exec(process.execPath, ['--import', join(repo, 'node_modules/tsx/dist/loader.mjs'),
  join(scriptRoot, 'scripts/support/sm-d1-batch.ts')], { env: { ...env, SM_E2E_REPO_ROOT: repo } }));
let bws = process.env.BWS_BIN;
if (!bws) {
  assert(process.platform === 'linux' && process.arch === 'x64', 'Set BWS_BIN to bws 2.1.0 on this platform');
  bws = join(tools, 'bws');
  if (!existsSync(bws)) {
    const archive = join(tools, 'bws-2.1.0.zip');
    await download('https://github.com/bitwarden/sdk-sm/releases/download/bws-v2.1.0/bws-x86_64-unknown-linux-gnu-2.1.0.zip', archive);
    assert.equal(createHash('sha256').update(readFileSync(archive)).digest('hex'), 'ba8233c3a4aee5d43e3c73bbd04d99e9bc5aba13bbbfd06d89b073abe732b860');
    exec('unzip', ['-o', archive, '-d', tools]);
  }
}
assert.equal(exec(bws, ['--version']), 'bws 2.1.0');
const sdkVersion = '0.2.0-main.1013';
const sdkDir = join(tools, `sdk-internal-${sdkVersion}`);
if (!existsSync(join(sdkDir, 'package/node/bitwarden_wasm_internal.js'))) {
  mkdirSync(sdkDir, { recursive: true });
  const archive = exec('npm', ['pack', `@bitwarden/sdk-internal@${sdkVersion}`, '--pack-destination', sdkDir, '--silent']);
  exec('tar', ['xzf', join(sdkDir, archive), '-C', sdkDir]);
}
const { default: { PureCrypto } } = await import(pathToFileURL(join(sdkDir, 'package/node/bitwarden_wasm_internal.js')));
const goSync = join(run, 'sm-client-sync');
exec('go', ['build', '-o', goSync, '.'], { cwd: join(scriptRoot, 'scripts/support/sm-client-sync') });

const config = join(run, 'wrangler.json');
const state = join(run, 'state');
const log = join(run, 'worker.log');
const classes = ['NotificationsHub', 'BackupTransferRunner', 'OrganizationHub', 'DirectorySyncActor'];
writeFileSync(config, JSON.stringify({
  name: 'nodewarden-sm-client-e2e', main: join(repo, 'src/index.ts'),
  compatibility_date: '2024-09-23', compatibility_flags: ['nodejs_compat'],
  vars: { ALLOW_OPEN_REGISTRATION: '1', JWT_SECRET: randomBytes(48).toString('base64') },
  d1_databases: [{ binding: 'DB', database_name: 'sm-client-e2e', database_id: randomUUID() }],
  durable_objects: { bindings: classes.map((class_name, i) => ({
    name: ['NOTIFICATIONS_HUB', 'BACKUP_TRANSFER_RUNNER', 'ORGANIZATION_HUB', 'DIRECTORY_SYNC'][i], class_name,
  })) },
  migrations: [{ tag: 'v1', new_sqlite_classes: classes }],
}));
// Avoid registering a real Bitwarden push installation during local database bootstrap.
const sql = join(run, 'seed.sql');
writeFileSync(sql, "CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO config VALUES ('push.installation.id', 'local-e2e'), ('push.installation.key', 'local-e2e');");
const wrangler = join(repo, 'node_modules/.bin/wrangler');
exec(wrangler, ['d1', 'execute', 'sm-client-e2e', '--local', '--config', config, '--persist-to', state, '--file', sql]);
const port = await new Promise((resolvePort, reject) => {
  const probe = createServer().once('error', reject);
  probe.listen(0, '127.0.0.1', () => {
    const { port } = probe.address();
    probe.close(() => resolvePort(port));
  });
});
const origin = `http://127.0.0.1:${port}`;
const worker = spawn(wrangler, ['dev', '--local', '--config', config, '--persist-to', state,
  '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', '0'], {
  cwd: repo, env, stdio: ['ignore', openSync(log, 'a'), openSync(log, 'a')],
});
try {
  let ready = false;
  for (let i = 0; i < 120 && worker.exitCode === null; i++) {
    ready = await fetch(`${origin}/api/alive`, { signal: AbortSignal.timeout(5000) }).then(r => r.ok).catch(() => false);
    if (ready) break;
    await delay(500);
  }
  assert(ready, `Worker failed to start: ${readFileSync(log, 'utf8')}`);
  const request = async (path, body, bearer, method = body === undefined ? 'GET' : 'POST', expected = 200) => {
    const response = await fetch(origin + path, {
      method, signal: AbortSignal.timeout(30000), headers: { ...(bearer && { Authorization: `Bearer ${bearer}` }),
        ...(body !== undefined && !(body instanceof URLSearchParams) && { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : body instanceof URLSearchParams ? body : JSON.stringify(body),
    });
    const text = await response.text();
    assert.equal(response.status, expected, `${method} ${path}: ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const email = `sm-e2e-${randomUUID()}@example.com`;
  const password = `Local-Fixture-${randomUUID()}`;
  const kdf = { pBKDF2: { iterations: 600000 } };
  const userKey = PureCrypto.make_user_key_aes256_cbc_hmac();
  const privateKey = PureCrypto.rsa_generate_keypair();
  const publicKey = PureCrypto.rsa_extract_public_key(privateKey);
  const b64 = bytes => Buffer.from(bytes).toString('base64');
  const masterKey = PureCrypto.derive_kdf_material(Buffer.from(password), Buffer.from(email), kdf);
  const hash = pbkdf2Sync(masterKey, password, 1, 32, 'sha256').toString('base64');
  const wireKdf = { kdfType: 0, iterations: 600000 };
  await request('/identity/accounts/register/finish', {
    email, masterPasswordHint: null,
    userAsymmetricKeys: { publicKey: b64(publicKey), encryptedPrivateKey: PureCrypto.wrap_decapsulation_key(privateKey, userKey) },
    masterPasswordAuthentication: { kdf: wireKdf, masterPasswordAuthenticationHash: hash, salt: email },
    masterPasswordUnlock: { kdf: wireKdf, masterKeyWrappedUserKey: PureCrypto.encrypt_user_key_with_master_password(userKey, password, email, kdf), salt: email },
  });
  const owner = await request('/identity/connect/token', new URLSearchParams({ grant_type: 'password',
    username: email, password: hash, scope: 'api offline_access', client_id: 'cli', deviceType: '8',
    deviceIdentifier: randomUUID(), deviceName: 'sm-client-e2e' }));
  const api = (path, body, method, expected) => request(`/api${path}`, body, owner.access_token, method, expected);
  const orgKey = PureCrypto.make_user_key_aes256_cbc_hmac();
  const enc = value => PureCrypto.symmetric_encrypt_string(value, orgKey);
  const orgPrivateKey = PureCrypto.rsa_generate_keypair();
  const org = await api('/organizations', { name: 'Local SM client E2E', billingEmail: email, planType: 0,
    key: PureCrypto.encapsulate_key_unsigned(orgKey, publicKey),
    keys: { publicKey: b64(PureCrypto.rsa_extract_public_key(orgPrivateKey)), encryptedPrivateKey: PureCrypto.wrap_decapsulation_key(orgPrivateKey, orgKey) },
    collectionName: enc('Default collection') });
  const project = await api(`/organizations/${org.id}/projects`, { name: enc('SDK project') });
  const secret = await api(`/organizations/${org.id}/secrets`, { key: enc('SDK_SECRET'), value: enc('synthetic-value-雪'), note: enc('SDK note'), projectIds: [project.id] });
  const machine = await api(`/organizations/${org.id}/service-accounts`, { name: enc('SDK machine') });
  const seed = randomBytes(16);
  const tokenKey = new Uint8Array(hkdfSync('sha256', seed, 'bitwarden-accesstoken', 'sm-access-token', 64));
  const token = await api(`/service-accounts/${machine.id}/access-tokens`, {
    name: enc('SDK token'), key: enc(b64(tokenKey)),
    encryptedPayload: PureCrypto.symmetric_encrypt_string(JSON.stringify({ encryptionKey: b64(orgKey) }), tokenKey),
  });
  assert.match(token.clientSecret, /^[A-Za-z0-9]{30}$/);
  const accessToken = `0.${token.id}.${token.clientSecret}:${b64(seed)}`;
  const loginBody = () => new URLSearchParams({ grant_type: 'client_credentials', scope: 'api.secrets', client_id: token.id, client_secret: token.clientSecret });
  const login = await request('/identity/connect/token', loginBody());
  assert.deepEqual(Object.keys(login).sort(), ['access_token', 'encrypted_payload', 'expires_in', 'scope', 'token_type']);
  assert.equal(login.expires_in, 3600);
  const clientEnv = { ...env, BWS_ACCESS_TOKEN: accessToken, BWS_SERVER_URL: origin, BWS_CONFIG_FILE: join(run, 'bws-config') };
  exec(bws, ['config', 'state-dir', join(run, 'bws-state')], { env: clientEnv });
  const cli = (...args) => JSON.parse(exec(bws, args, { env: clientEnv }));
  const sync = (lastSyncedDate = null) => JSON.parse(exec(goSync, [], { input: JSON.stringify({ Origin: origin,
    Token: accessToken, OrganizationID: org.id, StateFile: join(run, 'go-state'), LastSyncedDate: lastSyncedDate }) }));
  assert.deepEqual(cli('secret', 'list'), []);
  const grant = enabled => api(`/projects/${project.id}/access-policies/service-accounts`, {
    serviceAccountAccessPolicyRequests: enabled ? [{ granteeId: machine.id, read: true, write: true }] : [],
  }, 'PUT');
  await grant(true);
  assert.equal(cli('project', 'get', project.id).name, 'SDK project');
  assert.equal(cli('project', 'list').length, 1);
  assert.equal(cli('secret', 'list')[0].value, 'synthetic-value-雪');
  assert.equal(cli('secret', 'get', secret.id).note, 'SDK note');
  assert.equal(sync().secrets[0].value, 'synthetic-value-雪');
  const envCheck = join(run, 'check-env.cjs');
  writeFileSync(envCheck, "require('node:assert/strict').equal(process.env.SDK_SECRET, 'synthetic-value-雪');");
  exec(bws, ['run', '--', process.execPath, envCheck], { env: clientEnv });
  const machineProject = cli('project', 'create', 'BWS project');
  assert.equal(cli('project', 'edit', machineProject.id, '--name', 'BWS edited project').name, 'BWS edited project');
  exec(bws, ['project', 'delete', machineProject.id], { env: clientEnv });
  const created = cli('secret', 'create', 'BWS_CREATED', 'synthetic-created', project.id);
  assert.equal(created.note, '');
  assert.equal(cli('secret', 'edit', created.id, '--value', 'synthetic-edited').value, 'synthetic-edited');
  exec(bws, ['secret', 'delete', created.id], { env: clientEnv });
  assert.equal(cli('secret', 'list').length, 1);
  await delay(10);
  const lastSync = new Date().toISOString();
  assert.equal(sync(lastSync).hasChanges, false);
  await grant(false);
  const revoked = sync(lastSync);
  assert.equal(revoked.hasChanges, true);
  assert.equal(revoked.secrets?.length ?? 0, 0);
  assert.deepEqual(cli('secret', 'list'), []);
  assert.notEqual(spawnSync(bws, ['secret', 'get', secret.id], { env: clientEnv, encoding: 'utf8' }).status, 0);
  await request(`/api/secrets/${secret.id}`, undefined, login.access_token, 'GET', 404);
  await api(`/service-accounts/${machine.id}/access-tokens/revoke`, { ids: [token.id] });
  await request(`/api/organizations/${org.id}/secrets/sync`, undefined, login.access_token, 'GET', 401);
  assert.notEqual(spawnSync(bws, ['secret', 'list'], { env: clientEnv, encoding: 'utf8' }).status, 0);
  await request('/identity/connect/token', loginBody(), undefined, 'POST', 400);
  console.log('PASS: real bws 2.1.0 encrypted project/secret CRUD and run; official operator Go SDK v2.1.0 login/sync; policy removal; immediate token revocation.');
} finally {
  worker.kill('SIGTERM');
  console.log(`Local artifacts: ${run}`);
}
