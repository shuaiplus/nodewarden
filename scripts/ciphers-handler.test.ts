// ciphers handler 的行为测试
//
// 为什么需要它：`ciphers.ts` 是核心数据面（约 1500 行），却**没有任何测试** ——
// 第 1-10 轮的后端审计只覆盖了安全面（注入 / 越权 / 并发 / 限流），§3.4 的统计显示
// 20 个 handler 中只有 2 个被测试引用。
//
// 本文件用**真实 SQL**（node:sqlite 适配器 + migrations/0001_init.sql）驱动真实 handler，
// 重点是三件最要紧的事：
//   1. **跨用户隔离** —— 越权读写必须 404，且数据分毫不变
//   2. **陈旧写入** —— 过期的 lastKnownRevisionDate 必须被拒绝
//   3. **未知字段保留** —— CONTRIBUTING 的硬性要求（Bitwarden 兼容面）
//
// 运行方式（必须带模块解析钩子）：
//   npm run test:ciphers-handler
//
// 原因：`ciphers.ts` 间接 import `src/durable/notifications-hub.ts`，后者从 Workers 虚拟
// 模块 `cloudflare:workers` 导入，而 Node 无法解析该协议
// （ERR_UNSUPPORTED_ESM_URL_SCHEME）。钩子把该模块重定向到本地桩。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import test from 'node:test';

import {
  handleCreateCipher,
  handleDeleteCipherCompat,
  handleGetCipher,
  handleRestoreCipher,
  handleUpdateCipher,
} from '../src/handlers/ciphers';
import type { Env } from '../src/types';
import { createD1SqliteDatabase } from './lib/d1-sqlite';

const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const SCHEMA_SQL = readFileSync(path.join(REPO_ROOT, 'migrations', '0001_init.sql'), 'utf8');
const NOW = '2026-01-01T00:00:00.000Z';

const USER_A = 'user-a';
const USER_B = 'user-b';

/** 远早于任何 updated_at，用于触发 stale 检查（判定阈值是差值 >1000ms） */
const STALE_REVISION = '2020-01-01T00:00:00.000Z';

/**
 * 生成合法的 Bitwarden EncString。
 * 服务端会校验"加密串"格式（`validateCipherEncryptedFieldsForCompatibility`）：
 * type 2 = AES-CBC-HMAC，需 `2.<iv>|<data>|<mac>` 三段。传明文会被 400 拒绝。
 */
function enc(label: string): string {
  return `2.${label}-iv|${label}-data|${label}-mac`;
}

interface Harness {
  handle: ReturnType<typeof createD1SqliteDatabase>;
  env: Env;
  connection: DatabaseSync;
}

function createHarness(): Harness {
  const handle = createD1SqliteDatabase();
  handle.connection.exec(SCHEMA_SQL);
  for (const [id, email] of [
    [USER_A, 'a@example.test'],
    [USER_B, 'b@example.test'],
  ] as const) {
    handle.connection
      .prepare(
        'INSERT INTO users (id, email, name, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, status, verify_devices, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
      )
      .run(id, email, id, 'master-hash', 'wrapped-key', 0, 600000, `stamp-${id}`, 'user', 'active', 0, NOW, NOW);
  }

  // 桩掉 NOTIFICATIONS_HUB：handler 在写操作后会发通知，缺绑定虽被 try/catch 吞掉，
  // 但会往 stderr 打一堆堆栈、淹没有用信息。给它一个空实现更接近生产形态。
  const notificationsHub = {
    idFromName: (name: string) => ({ toString: () => name }),
    get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
  };

  return {
    handle,
    env: { DB: handle.db, NOTIFICATIONS_HUB: notificationsHub } as unknown as Env,
    connection: handle.connection,
  };
}

function jsonRequest(body: unknown, method = 'POST'): Request {
  return new Request('https://vault.example.test/api/ciphers', {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === null ? undefined : JSON.stringify(body),
  });
}

async function callCreate(env: Env, userId: string, body: Record<string, unknown>) {
  const response = await handleCreateCipher(jsonRequest(body), env, userId);
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

async function callUpdate(env: Env, userId: string, id: string, body: Record<string, unknown>) {
  const response = await handleUpdateCipher(jsonRequest(body, 'PUT'), env, userId, id);
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

function cipherRow(connection: DatabaseSync, id: string): Record<string, unknown> | undefined {
  return connection.prepare('SELECT * FROM ciphers WHERE id = ?').get(id) as Record<string, unknown> | undefined;
}

function cipherData(connection: DatabaseSync, id: string): Record<string, unknown> {
  const row = cipherRow(connection, id);
  assert.ok(row, `ciphers 表中缺少 ${id}`);
  return JSON.parse(String(row.data)) as Record<string, unknown>;
}

/** 建一个属于 USER_A 的 login 类型条目，返回其 id */
async function seedCipher(h: Harness, extra: Record<string, unknown> = {}): Promise<string> {
  const created = await callCreate(h.env, USER_A, {
    type: 1,
    name: enc('name'),
    notes: enc('notes'),
    login: { username: enc('username'), password: enc('password') },
    ...extra,
  });
  assert.equal(created.status, 200, `创建应成功，实际 ${created.status}：${JSON.stringify(created.body)}`);
  return String(created.body.id);
}

// ---------------------------------------------------------------- 创建与读取

test('创建：服务端接管 id/userId/时间戳，且保留客户端未知字段', async () => {
  const h = createHarness();
  const created = await callCreate(h.env, USER_A, {
    type: 1,
    name: enc('name'),
    login: { username: enc('u') },
    futureClientField: 'keep-me',
    nested: { deep: [1, 2] },
  });

  assert.equal(created.status, 200);
  const id = String(created.body.id);
  assert.ok(id, '响应应含服务端生成的 id');

  const row = cipherRow(h.connection, id);
  assert.ok(row, '应写入 ciphers 表');
  assert.equal(row.user_id, USER_A, 'userId 必须取自会话参数，而不是客户端');
  assert.equal(row.type, 1);
  assert.equal(row.deleted_at, null, '新建条目不应是已删除状态');

  const data = cipherData(h.connection, id);
  assert.equal(data.futureClientField, 'keep-me', '客户端未知字段必须保留（CONTRIBUTING 硬性要求）');
  assert.deepStrictEqual(data.nested, { deep: [1, 2] });

  h.handle.close();
});

test('创建：客户端伪造的 userId 必须被服务端覆盖', async () => {
  const h = createHarness();
  const forged = await callCreate(h.env, USER_A, {
    type: 1,
    name: enc('forged'),
    userId: USER_B,
  });

  assert.equal(forged.status, 200);
  assert.equal(
    cipherRow(h.connection, String(forged.body.id))?.user_id,
    USER_A,
    '客户端传入的 userId 必须被覆盖，否则可写入他人数据'
  );

  h.handle.close();
});

test('读取：所有者能读到，非所有者 404', async () => {
  const h = createHarness();
  const id = await seedCipher(h);

  const owner = await handleGetCipher(jsonRequest(null, 'GET'), h.env, USER_A, id);
  assert.equal(owner.status, 200);

  const stranger = await handleGetCipher(jsonRequest(null, 'GET'), h.env, USER_B, id);
  assert.equal(stranger.status, 404, '非所有者读取必须 404（而不是 200 或 500）');

  h.handle.close();
});

// ---------------------------------------------------------------- 跨用户隔离

test('跨用户写入必须 404，且目标数据分毫不变', async () => {
  const h = createHarness();
  const id = await seedCipher(h);
  const before = { ...cipherRow(h.connection, id)! };

  const attempt = await callUpdate(h.env, USER_B, id, { type: 1, name: enc('hijacked') });
  assert.equal(attempt.status, 404, '非所有者更新必须 404');

  assert.deepStrictEqual({ ...cipherRow(h.connection, id)! }, before, '被拒绝的写入不得改动任何数据');
  h.handle.close();
});

test('跨用户删除必须 404，且数据仍在', async () => {
  const h = createHarness();
  const id = await seedCipher(h);

  const attempt = await handleDeleteCipherCompat(jsonRequest(null, 'DELETE'), h.env, USER_B, id);
  assert.equal(attempt.status, 404, '非所有者删除必须 404');

  const row = cipherRow(h.connection, id);
  assert.ok(row, '数据不应被删除');
  assert.equal(row.deleted_at, null, '也不应被软删除');

  h.handle.close();
});

test('跨用户恢复必须 404，且数据仍是已删除状态', async () => {
  const h = createHarness();
  const id = await seedCipher(h);
  await handleDeleteCipherCompat(jsonRequest(null, 'DELETE'), h.env, USER_A, id);

  const attempt = await handleRestoreCipher(jsonRequest(null, 'PUT'), h.env, USER_B, id);
  assert.equal(attempt.status, 404, '非所有者恢复必须 404');
  assert.ok(cipherRow(h.connection, id)?.deleted_at, '数据应仍是已删除状态');

  h.handle.close();
});

// ---------------------------------------------------------------- 陈旧写入

test('陈旧的 lastKnownRevisionDate 必须被拒绝，且数据不变', async () => {
  const h = createHarness();
  const id = await seedCipher(h);
  const before = { ...cipherRow(h.connection, id)! };

  const stale = await callUpdate(h.env, USER_A, id, {
    type: 1,
    name: enc('overwritten-by-stale-client'),
    lastKnownRevisionDate: STALE_REVISION,
  });
  assert.equal(stale.status, 400, `陈旧写入应被拒绝，实际 ${stale.status}`);
  assert.match(String(stale.body.error), /out of date/i, '应提示客户端重新同步');

  assert.deepStrictEqual({ ...cipherRow(h.connection, id)! }, before, '被拒绝的陈旧写入不得改动数据');
  h.handle.close();
});

test('revisionDate 足够新时应被接受', async () => {
  const h = createHarness();
  const id = await seedCipher(h);
  const current = String(cipherRow(h.connection, id)?.updated_at);

  const ok = await callUpdate(h.env, USER_A, id, {
    type: 1,
    name: enc('updated-name'),
    lastKnownRevisionDate: current,
  });
  assert.equal(ok.status, 200, `revisionDate 足够新时应接受，实际 ${ok.status}：${JSON.stringify(ok.body)}`);

  h.handle.close();
});

test('不传 revisionDate 时不做陈旧判定（客户端可省略该字段）', async () => {
  const h = createHarness();
  const id = await seedCipher(h);

  const ok = await callUpdate(h.env, USER_A, id, { type: 1, name: enc('without-revision') });
  assert.equal(ok.status, 200, '省略 lastKnownRevisionDate 不应被当作陈旧');

  h.handle.close();
});

// ---------------------------------------------------------------- 未知字段与字段语义

test('更新时同时保留「既有未知字段」与「本次新增未知字段」', async () => {
  const h = createHarness();
  const id = await seedCipher(h, { originalUnknown: 'from-create' });

  const updated = await callUpdate(h.env, USER_A, id, {
    type: 1,
    name: enc('updated-name'),
    newlyAddedUnknown: 'from-update',
  });
  assert.equal(updated.status, 200);

  const data = cipherData(h.connection, id);
  assert.equal(data.originalUnknown, 'from-create', '既有未知字段必须保留');
  assert.equal(data.newlyAddedUnknown, 'from-update', '本次新增的未知字段也必须保留');

  h.handle.close();
});

test('全量更新中省略 notes 表示清空（replacement 语义，而非"保持原值"）', async () => {
  const h = createHarness();
  const id = await seedCipher(h); // seedCipher 带了 notes
  assert.ok(cipherRow(h.connection, id)?.notes, '前置条件：创建时应写入 notes');

  const updated = await callUpdate(h.env, USER_A, id, { type: 1, name: enc('no-notes') });
  assert.equal(updated.status, 200);

  assert.equal(
    cipherRow(h.connection, id)?.notes,
    null,
    '该端点对可空字段使用替换语义：客户端省略即视为清空（否则"清空备注"永远无法生效）'
  );

  h.handle.close();
});

// ---------------------------------------------------------------- 软删除与恢复

test('软删除与恢复：只改 deleted_at，不物理删除', async () => {
  const h = createHarness();
  const id = await seedCipher(h);

  const deleted = await handleDeleteCipherCompat(jsonRequest(null, 'DELETE'), h.env, USER_A, id);
  assert.equal(deleted.status, 200);
  assert.ok(cipherRow(h.connection, id)?.deleted_at, '软删除应写入 deleted_at');
  assert.ok(cipherRow(h.connection, id), '不应物理删除行');

  const restored = await handleRestoreCipher(jsonRequest(null, 'PUT'), h.env, USER_A, id);
  assert.equal(restored.status, 200);
  assert.equal(cipherRow(h.connection, id)?.deleted_at, null, '恢复应清空 deleted_at');

  h.handle.close();
});
