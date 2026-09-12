// /api/sync handler 的行为测试
//
// 为什么这个 handler 值得单独测：它是**客户端每次启动都会走**的端点，而且是**全量返回**——
// Bitwarden 官方客户端拿到 sync 响应后会**整体替换本地状态**。这带来两个方向的风险：
//
//   1. 响应里**少**了东西 → 客户端把本地数据删掉（数据丢失）
//   2. 响应里**多了非法**的东西 → 客户端解析失败，整个 sync 挂掉（用户彻底进不去）
//
// 所以本文件重点不在"字段对不对"，而在**缓存键的隔离性**和**污染行不能扩散**：
//
//   - sync 的响应会被 `caches.default` 缓存，缓存键由 用户/修订号/凭据标签/三个标志位 拼成。
//     **任一维度漏进键里**都会造成跨请求串答案：先请求 `?excludeSends=1` 的响应
//     （`sends: []`）被缓存后，下一个不带参数的请求会直接命中它，于是客户端认为
//     "我没有 Sends"，进而清空本地 Sends。
//   - `account-passkeys.ts` **完全不碰 revisionDate**（实测确认），所以缓存键里的凭据标签
//     是"新增 passkey 后客户端能否立刻看到"的**唯一**保障 —— 见下方对应的用例。
//   - 存储层若存在 `name` 不是合法 EncString 的行（历史脏数据 / 早期 bug 写入），
//     `isCipherResponseSyncCompatible` 会把它**丢掉而不是让整个同步失败**。
//
// 运行方式：npm run test:sync-handler
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import test from 'node:test';

import { handleCreateCipher } from '../src/handlers/ciphers';
import { handleSync } from '../src/handlers/sync';
import type { Env, SyncResponse } from '../src/types';
import { createD1SqliteDatabase } from './lib/d1-sqlite';

const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const SCHEMA_SQL = readFileSync(path.join(REPO_ROOT, 'migrations', '0001_init.sql'), 'utf8');
const NOW = '2026-01-01T00:00:00.000Z';
const USER = 'sync-user';

function enc(label: string): string {
  return `2.${label}-iv|${label}-data|${label}-mac`;
}

/** 记录被问过的缓存键，用来断言"键有没有正确隔离" */
interface CacheRecorder {
  /** 每次 match() 收到的键，按顺序 */
  matchedKeys: string[];
  /** put() 被调用的次数 —— 命中缓存时不应增加 */
  puts: number;
}

/**
 * 安装一个内存版 CacheStorage。
 * Node 里没有 `caches` 全局，而 `sync.ts` 直接用 `caches.default`，
 * 不装这个会直接 `ReferenceError`。
 */
function installCacheStub(): CacheRecorder {
  const store = new Map<string, string>();
  const recorder: CacheRecorder = { matchedKeys: [], puts: 0 };

  (globalThis as unknown as { caches: unknown }).caches = {
    default: {
      async match(request: Request): Promise<Response | undefined> {
        recorder.matchedKeys.push(request.url);
        const body = store.get(request.url);
        // 每次都返回全新的 Response：缓存命中路径会包一层
        // `new Response(hit.body, hit)`，复用同一个 body 流会被判定为已消费。
        return body === undefined
          ? undefined
          : new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } });
      },
      async put(request: Request, response: Response): Promise<void> {
        recorder.puts += 1;
        store.set(request.url, await response.text());
      },
    },
  };

  return recorder;
}

interface Harness {
  handle: ReturnType<typeof createD1SqliteDatabase>;
  connection: DatabaseSync;
  env: Env;
  cache: CacheRecorder;
}

function createHarness(): Harness {
  const handle = createD1SqliteDatabase();
  handle.connection.exec(SCHEMA_SQL);
  handle.connection
    .prepare(
      'INSERT INTO users (id, email, name, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, status, verify_devices, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run(USER, 'sync@example.test', 'sync', 'master-hash', 'wrapped-key', 0, 600000, 'stamp', 'user', 'active', 0, NOW, NOW);

  return {
    handle,
    connection: handle.connection,
    // 桩掉 NOTIFICATIONS_HUB：本文件通过 handleCreateCipher 造数据，缺绑定会被吞掉
    // 但每次往 stderr 打一行错误，容易淹没真正的失败信息。
    env: {
      DB: handle.db,
      NOTIFICATIONS_HUB: {
        idFromName: (name: string) => ({ toString: () => name }),
        get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
      },
    } as unknown as Env,
    cache: installCacheStub(),
  };
}

function syncRequest(options: { params?: Record<string, string>; web?: boolean } = {}): Request {
  const url = new URL('https://vault.example.test/api/sync');
  for (const [key, value] of Object.entries(options.params ?? {})) {
    url.searchParams.set(key, value);
  }
  const headers: Record<string, string> = {};
  if (options.web) headers['X-NodeWarden-Web'] = '1';
  return new Request(url.toString(), { method: 'GET', headers });
}

async function runSync(
  h: Harness,
  options: { params?: Record<string, string>; web?: boolean } = {}
): Promise<{ status: number; body: SyncResponse & Record<string, unknown> }> {
  const response = await handleSync(syncRequest(options), h.env, USER);
  return { status: response.status, body: (await response.json()) as SyncResponse & Record<string, unknown> };
}

function revisionDate(h: Harness): string | undefined {
  const row = h.connection.prepare('SELECT revision_date FROM user_revisions WHERE user_id = ?').get(USER) as
    | { revision_date: string }
    | undefined;
  return row?.revision_date;
}

/** 取出响应里的 PRF 解密选项（UserDecryption 在类型上是可选的） */
function prfOptions(body: SyncResponse & Record<string, unknown>): unknown[] {
  const { UserDecryption } = body;
  assert.ok(UserDecryption, 'sync 响应应包含 UserDecryption 分区');
  return UserDecryption.WebAuthnPrfOptions ?? [];
}

/** 存一条 Sends（够 sendToResponse 映射即可） */
function seedSend(h: Harness, id: string): void {
  h.connection
    .prepare(
      'INSERT INTO sends (id, user_id, type, name, data, key, auth_type, access_count, disabled, created_at, updated_at, deletion_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run(id, USER, 0, enc('send-name'), JSON.stringify({ text: enc('text') }), enc('send-key'), 2, 0, 0, NOW, NOW, '2027-01-01T00:00:00.000Z');
}

/**
 * 存一条 passkey 凭据。
 * `supports_prf=1` + 三把加密密钥齐全 → `accountPasskeyPrfStatus()` 返回 0
 * → `buildWebAuthnPrfOption()` 才会产出条目进入响应。
 */
function seedPasskey(h: Harness, id: string): void {
  h.connection
    .prepare(
      'INSERT INTO webauthn_credentials (id, user_id, purpose, name, public_key, credential_id, counter, transports, encrypted_user_key, encrypted_public_key, encrypted_private_key, supports_prf, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run(id, USER, 'login', 'my-passkey', 'pub', `cred-${id}`, 0, '["internal"]', enc('uk'), enc('pk'), enc('sk'), 1, NOW, NOW);
}

async function seedCipher(h: Harness, name: string): Promise<string> {
  const response = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: enc(name), login: { username: enc('u') } }),
    }),
    h.env,
    USER
  );
  const body = (await response.json()) as { id: string };
  return body.id;
}

// ---------------------------------------------------------------- 基础契约

test('用户不存在时返回 404', async () => {
  const h = createHarness();
  const response = await handleSync(syncRequest(), h.env, 'no-such-user');
  assert.equal(response.status, 404);

  h.handle.close();
});

test('正常返回 200，且包含 ciphers / folders / sends / domains 等关键分区', async () => {
  const h = createHarness();
  await seedCipher(h, 'a');

  const { status, body } = await runSync(h);
  assert.equal(status, 200);
  assert.equal(body.object, 'sync');
  assert.equal(body.ciphers.length, 1);
  assert.deepStrictEqual(body.folders, []);
  assert.deepStrictEqual(body.collections, [], '团队/集合功能未实现，应恒为空数组');
  assert.deepStrictEqual(body.policies, []);

  h.handle.close();
});

// ---------------------------------------------------------------- 排除开关

test('excludeSends=1 返回空 sends；不带参数返回真实 sends', async () => {
  const h = createHarness();
  seedSend(h, 'send-1');

  const plain = await runSync(h);
  assert.equal(plain.body.sends.length, 1, '不带 excludeSends 时应返回真实 sends');

  const excluded = await runSync(h, { params: { excludeSends: '1' } });
  assert.deepStrictEqual(excluded.body.sends, []);

  h.handle.close();
});

test('excludeDomains=1 把 domains 置为 null；不带参数返回真实 domains', async () => {
  const h = createHarness();
  h.connection
    .prepare('INSERT INTO domain_settings (user_id, equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at) VALUES (?,?,?,?,?)')
    .run(USER, JSON.stringify(['a.test', 'b.test']), '[]', '[]', NOW);

  const plain = await runSync(h);
  assert.ok(plain.body.domains, '不带 excludeDomains 时 domains 不应为 null');

  const excluded = await runSync(h, { params: { excludeDomains: '1' } });
  assert.equal(excluded.body.domains, null);

  h.handle.close();
});

// ---------------------------------------------------------------- 缓存键隔离（核心）

test('未勾选排除时，绝不能命中「勾选了排除」留下的缓存（客户端会据此清空本地数据）', async () => {
  const h = createHarness();
  seedSend(h, 'send-1');

  // 危险顺序：先让"瘦身版"响应占住缓存，再请求完整版
  const thin = await runSync(h, { params: { excludeSends: '1' } });
  assert.deepStrictEqual(thin.body.sends, [], '前置条件：excludeSends=1 应为空');

  const full = await runSync(h);
  assert.equal(
    full.body.sends.length,
    1,
    '缓存键若漏掉 excludeSends，这里会命中上面的空 sends；客户端会认为没有 Sends 并清空本地数据'
  );

  h.handle.close();
});

test('三个标志位与 Web 请求头各自独立影响缓存键', async () => {
  const h = createHarness();

  await runSync(h);
  await runSync(h, { params: { excludeDomains: '1' } });
  await runSync(h, { params: { excludeSends: '1' } });
  await runSync(h, { web: true });

  const keys = new Set(h.cache.matchedKeys);
  assert.equal(keys.size, 4, `四次请求应落在 4 个不同的缓存键上，实际 ${keys.size} 个：\n${[...keys].join('\n')}`);

  h.handle.close();
});

test('新增 passkey 必须使缓存失效（revisionDate 不会变，凭据标签是唯一保障）', async () => {
  const h = createHarness();

  const before = await runSync(h);
  assert.deepStrictEqual(prfOptions(before.body), [], '前置条件：初始没有 passkey');
  const revisionBefore = revisionDate(h);
  assert.ok(revisionBefore, '前置条件：首次 sync 应建立 user_revisions 记录');

  seedPasskey(h, 'passkey-1');

  // 这一条是"为什么缓存键里必须带凭据标签"的证明：新增 passkey **不会**改动修订号。
  assert.equal(
    revisionDate(h),
    revisionBefore,
    '插入 passkey 不改 revisionDate —— 若这里开始变了，说明实现变了，本用例的前提需重新审视'
  );

  const after = await runSync(h);
  assert.notEqual(h.cache.matchedKeys.at(-1), h.cache.matchedKeys[0], '第二次请求必须落在不同的缓存键上');
  assert.equal(
    prfOptions(after.body).length,
    1,
    '新增的 passkey 必须立刻出现在 sync 响应里，否则客户端在缓存过期前看不到它、表现为"passkey 注册了但没用"'
  );

  h.handle.close();
});

test('相同参数重复请求命中缓存：不再写入缓存，且响应一致', async () => {
  const h = createHarness();
  await seedCipher(h, 'a');

  const first = await runSync(h);
  assert.equal(h.cache.puts, 1, '首次请求应写缓存');

  const second = await runSync(h);
  assert.equal(h.cache.puts, 1, '第二次应命中缓存，不应再写缓存');
  assert.deepStrictEqual(second.body, first.body, '命中缓存返回的内容应与首次一致');

  h.handle.close();
});

// ---------------------------------------------------------------- 脏数据不扩散

test('name 不是合法 EncString 的脏行被丢弃，但其余条目照常返回（不能让整次同步失败）', async () => {
  const h = createHarness();
  const goodId = await seedCipher(h, 'good');
  const poisonedId = await seedCipher(h, 'to-be-poisoned');

  // 模拟历史脏数据 / 早期版本写入的明文 name，绕过 handler 的校验
  h.connection.prepare('UPDATE ciphers SET name = ? WHERE id = ?').run('plaintext-not-an-encstring', poisonedId);

  const { status, body } = await runSync(h);
  assert.equal(status, 200, '一条坏数据不应让整个 sync 返回非 200');
  assert.equal(body.ciphers.length, 1, '脏行应被丢弃');
  assert.equal(body.ciphers[0].id, goodId, '保留的应是那条合法数据');

  h.handle.close();
});
