// `sends` 相关 handler 与工具函数的行为测试
//
// 为什么这一组必须单独测：Send（"分享"）是**未认证用户也能访问**的功能面 ——
// 其他 handler 都躲在登录后面，只有这里可以被任何人用 URL 打到。它要同时守三件事：
//
//   ① **不可泄露**：拿不到 accessId 的人不能猜到内容；"不存在"与"无权访问"必须同一种回答
//   ② **一次性语义**：达到 `maxAccessCount` 后必须真的失效，且**并发下也不能超发**
//   ③ **密码爆破要有代价**：错了要计数、要能锁
//
// 另一部分覆盖 `sends-shared.ts` 里的**纯函数**（解析、可用性判定、accessId 编解码、
// JWT 密钥校验）。它们的性价比最高：不需要数据库、用例密度大、且改动风险集中在这些门控上。
//
// 运行方式：npm run test:sends-handler
import assert from 'node:assert/strict';
import type { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { handleAccessSend } from '../src/handlers/sends-public';
import { handleGetSend } from '../src/handlers/sends-private';
import {
  SEND_INACCESSIBLE_MSG,
  base64UrlEncode,
  extractBearerToken,
  fromAccessId,
  getSafeJwtSecret,
  isSendAvailable,
  setSendPassword,
  validateDeletionDate,
  validatePublicSendAccess,
  verifySendPassword,
} from '../src/handlers/sends-shared';
import { LIMITS } from '../src/config/limits';
import { SendAuthType, type Env, type Send } from '../src/types';
import { createSchemaDatabase, enc, FIXED_NOW, insertUser, TEST_JWT_SECRET } from './lib/test-harness';

const OWNER_ID = 'owner-1';
const OWNER_EMAIL = 'owner-1@example.test';
const STRANGER_ID = 'stranger-1';
const CLIENT_IP = '203.0.113.9';

/** 把一个 UUID 编码成 accessId（与 `toAccessId` 同算法：16 字节 → base64url） */
function accessIdFor(sendId: string): string {
  const hex = sendId.replace(/-/g, '').toLowerCase();
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return base64UrlEncode(bytes);
}

// ---------------------------------------------------------------- 构造 Send 对象

/** 造一个字段齐备的 `Send`（只给纯函数用，不落库） */
function buildSend(overrides: Partial<Send> = {}): Send {
  return {
    id: '11111111-2222-3333-4444-555555555555',
    userId: OWNER_ID,
    type: 0,
    name: enc('send-name'),
    notes: null,
    data: JSON.stringify({ text: enc('text') }),
    key: enc('send-key'),
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    authType: SendAuthType.None,
    emails: null,
    maxAccessCount: null,
    accessCount: 0,
    disabled: false,
    hideEmail: null,
    createdAt: FIXED_NOW,
    updatedAt: FIXED_NOW,
    expirationDate: null,
    deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------- accessId 编解码

test('accessId 编解码：UUID 往返一致，非法输入一律返回 null', () => {
  const sendId = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
  const accessId = accessIdFor(sendId);

  assert.equal(fromAccessId(accessId), sendId, 'accessId 应能解回原始 UUID');
  assert.match(accessId, /^[A-Za-z0-9_-]+$/, 'accessId 应是 URL 安全字符（不能含 + / =）');
  assert.ok(!accessId.includes('='), '不应带 base64 填充');
  assert.equal(accessId.length, 22, '16 字节的 base64url 固定 22 字符');

  for (const bad of ['', 'not-base64!!!', 'AAAA', accessId.slice(0, 21)]) {
    assert.equal(fromAccessId(bad), null, `非法 accessId ${JSON.stringify(bad)} 应返回 null`);
  }
});

test('extractBearerToken：仅接受 Bearer 前缀，大小写不敏感', () => {
  const withHeader = (value: string | null) =>
    new Request('https://x/', { headers: value === null ? {} : { Authorization: value } });

  assert.equal(extractBearerToken(withHeader(null)), null, '没有 Authorization 头时为 null');
  assert.equal(extractBearerToken(withHeader('Bearer abc123')), 'abc123');
  assert.equal(extractBearerToken(withHeader('bearer abc123')), 'abc123', '前缀大小写不敏感');
  assert.equal(extractBearerToken(withHeader('  Bearer   abc123  ')), 'abc123', '应去掉两侧空白');
  assert.equal(extractBearerToken(withHeader('Basic abc123')), null, '其他 scheme 不认');
  assert.equal(extractBearerToken(withHeader('Bearer')), null, '缺少 token 时为 null');
});

// ---------------------------------------------------------------- JWT 密钥校验（安全门控）

test('getSafeJwtSecret：缺失/空白/过短一律拒绝，且不回显密钥内容', async () => {
  const secretOf = (value: unknown) => getSafeJwtSecret({ JWT_SECRET: value } as unknown as Env);

  for (const [value, why] of [
    [undefined, '未配置'],
    ['', '空串'],
    ['   ', '纯空白'],
    ['short-secret', '短于最小长度'],
    ['x'.repeat(LIMITS.auth.jwtSecretMinLength - 1), '刚好短一个字符'],
  ] as const) {
    const result = secretOf(value);
    assert.equal(result.ok, false, `${why} 必须被拒绝`);
    if (result.ok) continue;
    assert.equal(result.response.status, 500);
    const body = (await result.response.json()) as { error?: string; error_description?: string };
    const text = `${body.error ?? ''} ${body.error_description ?? ''}`;
    assert.ok(!text.includes('short-secret'), '错误信息不得回显密钥内容');
    assert.notEqual(text.trim(), '', '仍应给出一个人能看懂的说明');
  }

  const ok = secretOf('x'.repeat(LIMITS.auth.jwtSecretMinLength));
  assert.equal(ok.ok, true, '达到最小长度即通过');
  assert.equal(ok.ok ? ok.secret : null, 'x'.repeat(LIMITS.auth.jwtSecretMinLength));
});

// ---------------------------------------------------------------- 可用性判定（一次性语义的核心）

test('isSendAvailable：四种失效条件各自独立生效', () => {
  const future = new Date(Date.now() + 86_400_000).toISOString();
  const past = new Date(Date.now() - 86_400_000).toISOString();

  assert.equal(isSendAvailable(buildSend()), true, '默认状态应可用');
  assert.equal(isSendAvailable(buildSend({ disabled: true })), false, '手动禁用应不可用');
  assert.equal(isSendAvailable(buildSend({ expirationDate: past })), false, '已过期应不可用');
  assert.equal(isSendAvailable(buildSend({ expirationDate: future })), true, '未过期仍可用');
  assert.equal(isSendAvailable(buildSend({ deletionDate: past })), false, '已到删除期应不可用');

  // 限量：达到上限即不可用
  assert.equal(isSendAvailable(buildSend({ maxAccessCount: 3, accessCount: 2 })), true, '未达上限仍可用');
  assert.equal(isSendAvailable(buildSend({ maxAccessCount: 3, accessCount: 3 })), false, '达到上限即不可用');
  assert.equal(isSendAvailable(buildSend({ maxAccessCount: 3, accessCount: 4 })), false, '超过上限仍不可用');
  assert.equal(isSendAvailable(buildSend({ maxAccessCount: null, accessCount: 999 })), true, '不限量时次数不影响');

  // 边界：maxAccessCount = 0 表示"一次都不给"
  assert.equal(
    isSendAvailable(buildSend({ maxAccessCount: 0, accessCount: 0 })),
    false,
    'maxAccessCount=0 应为"永不可用"（0 >= 0）'
  );
});

test('validateDeletionDate：超过配置的最大天数返回 400，未超则放行', () => {
  const withinLimit = new Date(Date.now() + (LIMITS.send.maxDeletionDays - 1) * 86_400_000);
  const beyondLimit = new Date(Date.now() + (LIMITS.send.maxDeletionDays + 1) * 86_400_000);

  assert.equal(validateDeletionDate(withinLimit), null, '未超上限应放行');
  assert.equal(validateDeletionDate(beyondLimit)?.status, 400, '超上限应 400');
});

// ---------------------------------------------------------------- 密码校验

test('verifySendPassword：服务端加盐哈希的正确/错误密码判定', async () => {
  const send = buildSend();
  await setSendPassword(send, 'correct horse battery staple');

  assert.equal(send.authType, 1, '设置密码后 authType 应变为 Password');
  assert.ok(send.passwordHash && send.passwordSalt && send.passwordIterations, '应写入盐与迭代次数');

  assert.equal(await verifySendPassword(send, 'correct horse battery staple'), true, '正确密码应通过');
  assert.equal(await verifySendPassword(send, 'wrong password'), false, '错误密码应失败');
  assert.equal(await verifySendPassword(send, ''), false, '空密码应失败');

  // 每次设置都应用新的随机盐，即两条相同密码的哈希不应一致
  const other = buildSend();
  await setSendPassword(other, 'correct horse battery staple');
  assert.notEqual(other.passwordSalt, send.passwordSalt, '盐必须是随机的');
  assert.notEqual(other.passwordHash, send.passwordHash, '同密码不同盐应产生不同哈希');
});

test('verifySendPassword：清除密码后任何输入都不通过', async () => {
  const send = buildSend();
  await setSendPassword(send, 'pw');
  assert.equal(send.authType, SendAuthType.Password, '前置条件：设置密码后应是 Password 方式');

  await setSendPassword(send, null);

  assert.equal(send.passwordHash, null);
  assert.equal(send.authType, SendAuthType.None, '清除密码应回到 None 方式');
  assert.equal(await verifySendPassword(send, 'pw'), false, '没有密码哈希时不能通过');
});

// ---------------------------------------------------------------- 公开访问校验

test('validatePublicSendAccess：无密码的 Send 直接放行', async () => {
  const result = await validatePublicSendAccess(buildSend(), {});
  assert.equal(result.ok, true);
});

test('validatePublicSendAccess：邮件认证方式本服务不支持，返回 501', async () => {
  const result = await validatePublicSendAccess(buildSend({ authType: SendAuthType.Email }), {});
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, 'email_auth_unsupported');
    assert.equal(result.response.status, 501);
  }
});

test('validatePublicSendAccess：受密码保护时，缺密码 401、错密码 400、对密码放行', async () => {
  const send = buildSend();
  await setSendPassword(send, 'letmein');

  const missing = await validatePublicSendAccess(send, {});
  assert.equal(missing.ok, false);
  if (!missing.ok) {
    assert.equal(missing.reason, 'password_missing');
    assert.equal(missing.response.status, 401);
  }

  const wrong = await validatePublicSendAccess(send, { password: 'nope' });
  assert.equal(wrong.ok, false);
  if (!wrong.ok) {
    assert.equal(wrong.reason, 'invalid_password');
    assert.equal(wrong.response.status, 400);
  }

  const right = await validatePublicSendAccess(send, { password: 'letmein' });
  assert.equal(right.ok, true, '正确密码应放行');

  // 官方客户端会发大写别名 Password
  const aliased = await validatePublicSendAccess(send, { Password: 'letmein' });
  assert.equal(aliased.ok, true, '应接受 PascalCase 别名');
});

// ---------------------------------------------------------------- 端到端：公开访问面

interface Harness {
  handle: Awaited<ReturnType<typeof createSchemaDatabase>>;
  env: Env;
  connection: DatabaseSync;
}

async function createHarness(): Promise<Harness> {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, OWNER_ID, { email: OWNER_EMAIL });
  insertUser(handle.connection, STRANGER_ID);
  const env = {
    DB: handle.db,
    JWT_SECRET: TEST_JWT_SECRET,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
    },
  } as unknown as Env;
  return { handle, env, connection: handle.connection };
}

/** 存一条 Send，返回其 id 与 accessId */
function seedSend(
  h: Harness,
  overrides: {
    id?: string;
    passwordHash?: string | null;
    passwordSalt?: string | null;
    passwordIterations?: number | null;
    maxAccessCount?: number | null;
    accessCount?: number;
    disabled?: number;
    expirationDate?: string | null;
    deletionDate?: string | null;
  } = {}
): { id: string; accessId: string } {
  const id = overrides.id ?? 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  h.connection
    .prepare(
      'INSERT INTO sends (id, user_id, type, name, data, key, password_hash, password_salt, password_iterations, auth_type, max_access_count, access_count, disabled, created_at, updated_at, expiration_date, deletion_date) ' +
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run(
      id,
      OWNER_ID,
      0,
      enc('send-name'),
      JSON.stringify({ text: enc('text') }),
      enc('send-key'),
      overrides.passwordHash ?? null,
      overrides.passwordSalt ?? null,
      overrides.passwordIterations ?? null,
      overrides.passwordHash ? 1 : 2,
      overrides.maxAccessCount ?? null,
      overrides.accessCount ?? 0,
      overrides.disabled ?? 0,
      FIXED_NOW,
      FIXED_NOW,
      overrides.expirationDate ?? null,
      overrides.deletionDate ?? new Date(Date.now() + 86_400_000).toISOString()
    );
  return { id, accessId: accessIdFor(id) };
}

function accessRequest(body: unknown = {}): Request {
  return new Request('https://vault.example.test/api/sends/access', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': CLIENT_IP },
    body: JSON.stringify(body),
  });
}

function accessCountOf(h: Harness, id: string): number {
  const row = h.connection.prepare('SELECT access_count FROM sends WHERE id = ?').get(id) as {
    access_count: number;
  };
  return row.access_count;
}

test('公开访问：非法 accessId 与不存在的 Send 返回同一种 404（不泄露存在性）', async () => {
  const h = await createHarness();

  const malformed = await handleAccessSend(accessRequest(), h.env, 'not-a-valid-access-id');
  assert.equal(malformed.status, 404);

  const validButAbsent = await handleAccessSend(accessRequest(), h.env, accessIdFor('99999999-9999-4999-8999-999999999999'));
  assert.equal(validButAbsent.status, 404);

  const [a, b] = await Promise.all([
    malformed.json() as Promise<{ error?: string }>,
    validButAbsent.json() as Promise<{ error?: string }>,
  ]);
  assert.equal(a.error, b.error, '"格式非法"与"不存在"必须给出同样的回答');
  assert.equal(a.error, SEND_INACCESSIBLE_MSG);

  h.handle.close();
});

test('公开访问：已禁用的 Send 一律 404（即使 accessId 正确）', async () => {
  const h = await createHarness();
  const { accessId } = seedSend(h, { disabled: 1 });

  const response = await handleAccessSend(accessRequest(), h.env, accessId);
  assert.equal(response.status, 404);

  h.handle.close();
});

test('公开访问：受密码保护时，缺密码 401、错密码 400、对密码 200', async () => {
  const h = await createHarness();
  const password = 'letmein';
  const send = buildSend();
  await setSendPassword(send, password);
  const { id, accessId } = seedSend(h, {
    passwordHash: send.passwordHash,
    passwordSalt: send.passwordSalt,
    passwordIterations: send.passwordIterations,
  });

  const missing = await handleAccessSend(accessRequest(), h.env, accessId);
  assert.equal(missing.status, 401, '缺密码应 401');
  assert.equal(accessCountOf(h, id), 0, '未通过校验时不得计入访问次数');

  const wrong = await handleAccessSend(accessRequest({ password: 'nope' }), h.env, accessId);
  assert.equal(wrong.status, 400, '错密码应 400');
  assert.equal(accessCountOf(h, id), 0, '错密码不得计入访问次数');

  const right = await handleAccessSend(accessRequest({ password }), h.env, accessId);
  assert.equal(right.status, 200, `正确密码应放行，实际 ${right.status}`);
  assert.equal(accessCountOf(h, id), 1, '成功访问应计入一次');

  h.handle.close();
});

test('一次性语义：maxAccessCount=1 时第二次访问必须 404，且计数不再增长', async () => {
  const h = await createHarness();
  const { id, accessId } = seedSend(h, { maxAccessCount: 1 });

  const first = await handleAccessSend(accessRequest(), h.env, accessId);
  assert.equal(first.status, 200, '第一次应成功');
  assert.equal(accessCountOf(h, id), 1);

  const second = await handleAccessSend(accessRequest(), h.env, accessId);
  assert.equal(second.status, 404, '达到上限后必须失效');
  assert.equal(accessCountOf(h, id), 1, '失效后的访问不得再计数');

  h.handle.close();
});

test('一次性语义：并发访问同一限量 Send 时不会超发', async () => {
  const h = await createHarness();
  // 条件是原子 UPDATE（`access_count < max_access_count` 与自增在同一条语句里），
  // 所以并发请求里只应有 max 个成功，其余都拿不到内容。
  const max = 2;
  const { id, accessId } = seedSend(h, { maxAccessCount: max });

  const responses = await Promise.all(
    Array.from({ length: 6 }, () => handleAccessSend(accessRequest(), h.env, accessId))
  );
  const succeeded = responses.filter((response) => response.status === 200).length;

  assert.equal(succeeded, max, `并发下成功次数应恰好等于上限 ${max}，实际 ${succeeded}`);
  assert.equal(accessCountOf(h, id), max, '访问计数不得超过上限');

  h.handle.close();
});

test('跨用户隔离：非所有者读取 Send 详情返回 404', async () => {
  const h = await createHarness();
  const { id } = seedSend(h);

  const owner = await handleGetSend(new Request(`https://x/api/sends/${id}`), h.env, OWNER_ID, id);
  assert.equal(owner.status, 200, '所有者应能读到');

  const stranger = await handleGetSend(new Request(`https://x/api/sends/${id}`), h.env, STRANGER_ID, id);
  assert.equal(stranger.status, 404, '非所有者必须 404');

  h.handle.close();
});
