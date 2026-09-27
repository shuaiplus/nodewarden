// Opt-in, isolated Wrangler + real EMAIL simulator + real encrypted webapp fixtures.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, openSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { bytesToBase64, encryptBw, hkdfExpand, pbkdf2 } from '../webapp/src/lib/crypto';
import { readLocalEmailCode } from './support/local-email';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const run = mkdtempSync(join(tmpdir(), 'nodewarden-live-mail-'));
const temporaryFiles = join(run, 'tmp');
mkdirSync(temporaryFiles);
const env: NodeJS.ProcessEnv = { ...process.env, TMPDIR: temporaryFiles, WRANGLER_SEND_METRICS: 'false', CI: 'true' };
for (const key of Object.keys(env)) if (/proxy/i.test(key) || /^CLOUDFLARE_/.test(key)) delete env[key];
const execute = (command: string, args: string[]) => {
  const result = spawnSync(command, args, { cwd: repo, env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
};
writeFileSync(join(run, 'build.log'), execute('npm', ['run', 'build']));
const port = await new Promise<number>((resolvePort, reject) => {
  const server = createServer().once('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address() as { port: number };
    server.close(() => resolvePort(port));
  });
});
const origin = `http://localhost:${port}`;
const config = join(run, 'wrangler.json');
const state = join(run, 'state');
const log = join(run, 'worker.log');
const classes = ['NotificationsHub', 'BackupTransferRunner'];
writeFileSync(config, JSON.stringify({
  name: 'nodewarden-live-mail-test', main: join(repo, 'src/index.ts'), compatibility_date: '2024-09-23', compatibility_flags: ['nodejs_compat'],
  vars: { ALLOW_OPEN_REGISTRATION: '1', JWT_SECRET: randomBytes(48).toString('base64'), ENABLE_NEW_DEVICE_VERIFICATION: '1',
    EMAIL_FROM: 'noreply@local.nodewarden.io', EMAIL_FROM_NAME: 'NodeWarden local browser test', WEB_VAULT_ORIGINS: origin },
  assets: { directory: join(repo, 'dist'), binding: 'ASSETS', html_handling: 'none', not_found_handling: 'single-page-application', run_worker_first: true },
  send_email: [{ name: 'EMAIL' }],
  d1_databases: [{ binding: 'DB', database_name: 'isolated-live-mail', database_id: randomUUID() }],
  durable_objects: { bindings: classes.map((class_name, i) => ({ name: ['NOTIFICATIONS_HUB', 'BACKUP_TRANSFER_RUNNER'][i], class_name })) },
  migrations: [{ tag: 'v1', new_sqlite_classes: classes }],
}), { mode: 0o600 });
writeFileSync(join(run, '.dev.vars'), '');
const seed = join(run, 'bootstrap.sql');
writeFileSync(seed, "CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO config VALUES ('push.installation.id', 'local-e2e'), ('push.installation.key', 'local-e2e');");
const wrangler = join(repo, 'node_modules/.bin/wrangler');
execute(wrangler, ['d1', 'execute', 'isolated-live-mail', '--local', '--config', config, '--persist-to', state, '--file', seed]);
const worker = spawn(wrangler, ['dev', '--local', '--config', config, '--persist-to', state, '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', '0'], {
  cwd: run, env, stdio: ['ignore', openSync(log, 'a'), openSync(log, 'a')],
});
const stop = () => worker.kill('SIGTERM');
process.once('SIGINT', stop);
process.once('SIGTERM', stop);
try {
  let ready = false;
  for (let attempt = 0; attempt < 40 && worker.exitCode === null; attempt++) {
    ready = await fetch(`${origin}/api/alive`, { signal: AbortSignal.timeout(1000) }).then(response => response.ok).catch(() => false);
    if (ready) break;
    await delay(300);
  }
  assert.ok(ready, `Wrangler startup failed; see ${log}`);
  const request = async (path: string, body?: unknown, bearer?: string, method = body === undefined ? 'GET' : 'POST') => {
    const response = await fetch(origin + path, {
      method, signal: AbortSignal.timeout(15000), headers: { ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}), ...(body instanceof URLSearchParams || body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : body instanceof URLSearchParams ? body : JSON.stringify(body),
    });
    const text = await response.text();
    assert.equal(response.status, 200, `${method} ${path}: ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const accounts = [];
  for (const kind of ['email-2fa', 'new-device']) {
    const email = `${kind}@local.nodewarden.io`;
    const password = `Local-browser-only-${randomUUID()}!`;
    const masterKey = await pbkdf2(password, email, 600000, 32);
    const masterPasswordHash = bytesToBase64(await pbkdf2(masterKey, password, 1, 32));
    const sym = crypto.getRandomValues(new Uint8Array(64));
    const encrypt = (text: string) => encryptBw(new TextEncoder().encode(text), sym.slice(0, 32), sym.slice(32));
    const keyPair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt']);
    const publicKey = bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey)));
    const encryptedPrivateKey = await encryptBw(new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)), sym.slice(0, 32), sym.slice(32));
    await request('/identity/accounts/register/finish', {
      email, name: `Local ${kind}`, masterPasswordHash, key: await encryptBw(sym, await hkdfExpand(masterKey, 'enc', 32), await hkdfExpand(masterKey, 'mac', 32)),
      encryptedPrivateKey, publicKey, kdf: 0, kdfIterations: 600000,
    });
    const knownDevice = `fixture-known-${kind}`;
    const token = await request('/identity/connect/token', new URLSearchParams({ grant_type: 'password', username: email, password: masterPasswordHash,
      client_id: 'web', scope: 'api offline_access', deviceType: '10', deviceIdentifier: knownDevice, deviceName: 'Local fixture setup' }));
    const id = JSON.parse(Buffer.from(token.access_token.split('.')[1], 'base64url').toString()).sub;
    const itemName = `Decrypted ${kind} fixture`;
    const cipher = await request('/api/ciphers', { type: 1, name: await encrypt(itemName), login: { username: await encrypt('local-fixture-user'), password: await encrypt('local-fixture-secret') } }, token.access_token);
    const sync = await request('/api/sync', undefined, token.access_token);
    assert.ok(sync.ciphers.some((item: { id: string }) => item.id === cipher.id));
    assert.ok(!JSON.stringify(sync).includes(itemName), 'The fixture name must be encrypted on the wire');
    const factorEmail = `factor@local.nodewarden.io`;
    if (kind === 'email-2fa') {
      const { UserVerificationToken: userVerificationToken } = await request('/api/two-factor/get-email', { masterPasswordHash }, token.access_token);
      const started = Date.now();
      await request('/api/two-factor/send-email', { email: factorEmail, userVerificationToken }, token.access_token);
      let mail = null;
      for (let attempt = 0; attempt < 40 && !mail; attempt++) {
        mail = readLocalEmailCode(log, factorEmail, started, true);
        if (!mail) await delay(100);
      }
      assert.ok(mail, 'No local setup email captured');
      await request('/api/two-factor/email', { email: factorEmail, token: mail.code, userVerificationToken }, token.access_token, 'PUT');
    } else {
      // A young account/first device intentionally skips NDV. Age only this disposable local row.
      execute(wrangler, ['d1', 'execute', 'isolated-live-mail', '--local', '--config', config, '--persist-to', state, '--command',
        `UPDATE users SET created_at='2020-01-01T00:00:00.000Z', verify_devices=1, email_verified=0 WHERE id='${id}';`]);
    }
    accounts.push({ kind, email, password, factorEmail: kind === 'email-2fa' ? factorEmail : email, knownDevice, itemName, cipherId: cipher.id });
  }
  const fixtures = join(run, 'fixtures.json');
  writeFileSync(fixtures, JSON.stringify({ origin, log, accounts }), { mode: 0o600 });
  console.log(`Isolated live-mail browser artifacts: ${run}`);
  const result = spawnSync(join(repo, 'node_modules/.bin/playwright'), ['test', 'e2e/webapp-live-mail.spec.ts', '--reporter=list',
    ...(process.env.LIVE_MAIL_HEADLESS === '1' ? [] : ['--headed']), '--output', join(run, 'browser-results'),
    ...(process.env.LIVE_MAIL_GREP ? ['--grep', process.env.LIVE_MAIL_GREP] : [])], {
    cwd: repo, env: { ...env, E2E_ORIGIN: origin, E2E_LIVE_MAIL_FIXTURES: fixtures }, encoding: 'utf8',
  });
  writeFileSync(join(run, 'playwright.log'), result.stdout + result.stderr);
  console.log(result.stdout + result.stderr);
  assert.equal(result.status, 0, 'Live browser tests failed');
} finally {
  stop();
  await new Promise<void>(resolveStopped => { if (worker.exitCode !== null) resolveStopped(); else worker.once('exit', () => resolveStopped()); });
  console.log(`Local Worker stopped. Artifacts retained at ${run}`);
}
