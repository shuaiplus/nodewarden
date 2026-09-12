// `src/handlers/identity.ts` 的行为测试 —— 认证入口
//
// 为什么这个 handler 最该测：它是**唯一签发凭据的地方**。这里出错的后果与其他 handler
// 不同量级 —— 不是"某个列表少一条"，而是"凭据发给了不该发的人"或"合法用户进不来"。
//
// 覆盖重点（按 NEXT.md §3.4 的规划）：
//   ① 密码校验的**失败路径**：每种失败都必须**不签发任何凭据**
//   ② 防用户枚举：prelogin 对不存在的用户必须返回**与真实用户相同的响应形状**
//   ③ **凭据用途隔离**：access token 不能被当成 refresh token 用
//   ④ `checkClientCredentialsParam` 这个安全门控的边界
//
// 运行方式：npm run test:identity-handler
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  checkClientCredentialsParam,
  handlePrelogin,
  handleRevocation,
  handleToken,
} from '../src/handlers/identity';
import { AuthService } from '../src/services/auth';
import type { Env } from '../src/types';
import { createSchemaDatabase, insertUser, TEST_JWT_SECRET } from './lib/test-harness';

const USER_ID = 'user-1';
const USER_EMAIL = 'user-1@example.test';
/** 客户端先对主密码做一次哈希后发上来的值（服务端再叠一层，见 AuthService） */
const CLIENT_HASH = 'client-side-hash-of-master-password';
/** 客户端 IP 缺失时 handleToken 会直接 503，所以每个请求都要带上 */
const CLIENT_IP = '203.0.113.7';

interface Harness {
  handle: Awaited<ReturnType<typeof createSchemaDatabase>>;
  env: Env;
  auth: AuthService;
}

async function createHarness(): Promise<Harness> {
  const handle = await createSchemaDatabase();
  const env = buildEnv(handle.db);
  return { handle, env, auth: new AuthService(env) };
}

function buildEnv(db: Env['DB']): Env {
  return {
    DB: db,
    // 签发 JWT 需要密钥；不在测试里给就会以零长度密钥 importKey，
    // 报 `DataError: Zero-length key is not supported`
    JWT_SECRET: TEST_JWT_SECRET,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
    },
  } as unknown as Env;
}

/** 存一个"密码就是 CLIENT_HASH"的用户。哈希用真实实现生成，不手写。 */
async function seedUserWithPassword(
  h: Harness,
  options: { id?: string; email?: string; status?: string; yubikeyKey1?: string } = {}
): Promise<string> {
  const id = options.id ?? USER_ID;
  const email = options.email ?? USER_EMAIL;
  const masterPasswordHash = await h.auth.hashPasswordServer(CLIENT_HASH, email);
  insertUser(h.handle.connection, id, {
    email,
    status: options.status,
    masterPasswordHash,
    yubikeyKey1: options.yubikeyKey1,
  });
  return email;
}

function tokenRequest(payload: Record<string, string>, options: { form?: boolean; ip?: string | null } = {}): Request {
  const headers: Record<string, string> = {};
  if (options.ip !== null) headers['CF-Connecting-IP'] = options.ip ?? CLIENT_IP;

  if (options.form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    return new Request('https://vault.example.test/identity/connect/token', {
      method: 'POST',
      headers,
      body: new URLSearchParams(payload).toString(),
    });
  }

  headers['Content-Type'] = 'application/json';
  return new Request('https://vault.example.test/identity/connect/token', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
}

async function callToken(
  h: Harness,
  payload: Record<string, string>,
  options: { form?: boolean; ip?: string | null } = {}
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await handleToken(tokenRequest(payload, options), h.env);
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

// ---------------------------------------------------------------- 纯函数：client_credentials 门控

test('checkClientCredentialsParam：只放行「user. 前缀的 clientId + 非空 secret + scope=api」', () => {
  // 这是 client_credentials 授权的唯一门控，四条规则都必须成立
  const cases: Array<[string, string, string, boolean, string]> = [
    ['user.abc', 'secret', 'api', true, '三个条件齐备才放行'],
    ['user.abc', 'secret', 'offline_access', false, 'scope 必须是 api'],
    ['user.abc', 'secret', '', false, 'scope 不能为空'],
    ['abc', 'secret', 'api', false, 'clientId 必须带 user. 前缀'],
    ['User.abc', 'secret', 'api', false, '前缀区分大小写'],
    ['organization.abc', 'secret', 'api', false, 'organization. 前缀不放行'],
    ['user.', '', 'api', false, 'secret 不能为空'],
    ['user.', '   ', 'api', true, '空白 secret 当前视为非空（记录既有行为，非缺陷判定）'],
    ['', 'secret', 'api', false, '空 clientId 不放行'],
  ];

  for (const [clientId, clientSecret, scope, expected, why] of cases) {
    assert.equal(
      checkClientCredentialsParam(clientId, clientSecret, scope),
      expected,
      `clientId="${clientId}" secret="${clientSecret}" scope="${scope}" —— ${why}`
    );
  }
});

// ---------------------------------------------------------------- 防用户枚举

test('prelogin：不存在的用户返回与真实用户相同的响应形状（防用户枚举）', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const prelogin = (email: string) =>
    handlePrelogin(
      new Request('https://vault.example.test/identity/accounts/prelogin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      }),
      h.env
    );

  const existing = (await (await prelogin(USER_EMAIL)).json()) as Record<string, unknown>;
  const missing = (await (await prelogin('nobody@example.test')).json()) as Record<string, unknown>;

  assert.deepStrictEqual(
    Object.keys(missing).sort(),
    Object.keys(existing).sort(),
    '键集合必须一致 —— 少一个字段就是一个用户枚举信号'
  );
  // 这些字段对不存在的用户应为 null，而不是 undefined 或被省略
  for (const key of ['kdfMemory', 'kdfParallelism']) {
    assert.ok(key in missing, `${key} 必须显式存在`);
    assert.equal(missing[key], null, `${key} 对不存在的用户应为 null`);
    assert.equal(missing[key], existing[key], `${key} 与真实用户应取同一个值（此处都为 null）`);
  }

  h.handle.close();
});

test('prelogin：缺 email 返回 400，非法 JSON 也返回 400', async () => {
  const h = await createHarness();
  const build = (body: string) =>
    new Request('https://vault.example.test/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

  assert.equal((await handlePrelogin(build(JSON.stringify({})), h.env)).status, 400, '缺 email 应 400');
  assert.equal((await handlePrelogin(build('{not json'), h.env)).status, 400, '非法 JSON 应 400');

  h.handle.close();
});

// ---------------------------------------------------------------- 签发路径的失败分支

test('token：缺少客户端 IP 时返回 503，而不是继续往下走', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const result = await callToken(h, { grant_type: 'password', username: USER_EMAIL, password: CLIENT_HASH }, { ip: null });
  assert.equal(result.status, 503, '拿不到客户端 IP 时无法做限流，应拒服务');
  assert.equal(result.body.error, 'temporarily_unavailable');
  assert.ok(result.body.access_token === undefined, '绝不能在缺少限流依据时签发凭据');

  h.handle.close();
});

test('token：password 授权缺 username 或 password 时 400 invalid_request', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const noPassword = await callToken(h, { grant_type: 'password', username: USER_EMAIL });
  assert.equal(noPassword.status, 400);
  assert.equal(noPassword.body.error, 'invalid_request');

  const noUsername = await callToken(h, { grant_type: 'password', password: CLIENT_HASH });
  assert.equal(noUsername.status, 400);
  assert.equal(noUsername.body.error, 'invalid_request');

  h.handle.close();
});

test('token：用户不存在时 400 invalid_grant，且不签发凭据', async () => {
  const h = await createHarness();

  const result = await callToken(h, {
    grant_type: 'password',
    username: 'nobody@example.test',
    password: CLIENT_HASH,
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.error, 'invalid_grant');
  assert.ok(result.body.access_token === undefined);
  assert.ok(result.body.refresh_token === undefined);
  assert.equal(
    h.handle.connection.prepare('SELECT COUNT(*) AS count FROM refresh_tokens').get()?.count,
    0,
    '失败的登录不得写入任何 refresh token'
  );

  h.handle.close();
});

test('token：密码错误时 400 invalid_grant，且不签发凭据、不落库', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const result = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL,
    password: 'wrong-password',
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.error, 'invalid_grant');
  assert.ok(result.body.access_token === undefined, '密码错误绝不能签发 access token');
  assert.ok(result.body.refresh_token === undefined, '密码错误绝不能签发 refresh token');
  assert.equal(
    h.handle.connection.prepare('SELECT COUNT(*) AS count FROM refresh_tokens').get()?.count,
    0,
    '密码错误的登录不得写入 refresh token'
  );

  h.handle.close();
});

test('token：被封禁（banned）的账号无法登录，且不签发凭据', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h, { status: 'banned' });

  const result = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL,
    password: CLIENT_HASH,
  });

  assert.equal(result.status, 400, `被封禁的账号必须登不进来，实际 ${result.status}`);
  assert.match(String(result.body.error_description ?? ''), /disabled/i);
  assert.ok(result.body.access_token === undefined, '封禁账号绝不能签发 access token');
  assert.ok(result.body.refresh_token === undefined);

  h.handle.close();
});

// 下面这条**记录既有行为，不是缺陷判定**，请勿当成"期望行为"照抄。
//
// 背景：`mapUserRow`（storage-user-repo.ts）只有一行
//     status: row.status === 'banned' ? 'banned' : 'active'
// 即**只认 'banned'，其余一切值都归为 'active'** —— 而 `handleToken` 的门是
// `user.status !== 'active'`，所以只有 'banned' 能拦住登录。
//
// 为什么现在不算缺陷：`users.status` 的**唯一**非 active 写入方是管理端的
// `handleAdminUpdateUserStatus`，它做了白名单（`status must be active or banned`，其余 400）。
// 也就是说系统自己永远不会产生第三个值。
//
// 但这是个"宽容映射"（fail-open）：手工执行
// `UPDATE users SET status = 'suspended'` 之类会被**静默当作正常账号**。
// 本用例把这一点固定下来，将来若有人把映射改成 fail-closed，这里会红，
// 从而强制做一次有意识的决策（而不是无声漂移）。
test('记录既有行为：状态映射只认 banned，其余值一律当作 active（fail-open）', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h, { status: 'suspended' });

  const result = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL,
    password: CLIENT_HASH,
  });

  assert.equal(
    result.status,
    200,
    '当前实现下未被识别为 banned 的值不会拦截登录 —— 这是既有行为，不是期望行为'
  );

  h.handle.close();
});

// ---------------------------------------------------------------- 签发路径的成功分支

test('token：密码正确时签发 access_token 与 refresh_token，并把 refresh token 落库', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const result = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL,
    password: CLIENT_HASH,
  });

  assert.equal(result.status, 200, `正确密码应登录成功，实际 ${result.status}：${JSON.stringify(result.body)}`);
  assert.ok(typeof result.body.access_token === 'string' && result.body.access_token.length > 0);
  assert.ok(typeof result.body.refresh_token === 'string' && result.body.refresh_token.length > 0);
  assert.equal(result.body.token_type, 'Bearer');
  assert.equal(result.body.scope, 'api offline_access');

  const stored = h.handle.connection
    .prepare('SELECT COUNT(*) AS count FROM refresh_tokens WHERE user_id = ?')
    .get(USER_ID) as { count: number };
  assert.equal(stored.count, 1, 'refresh token 应落库一条');

  h.handle.close();
});

test('token：form-urlencoded 请求体也能登录（官方客户端就是这么发的）', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const result = await callToken(
    h,
    { grant_type: 'password', username: USER_EMAIL, password: CLIENT_HASH },
    { form: true }
  );

  assert.equal(result.status, 200, `form 形式应同样可用，实际 ${result.status}`);
  assert.ok(result.body.access_token);

  h.handle.close();
});

test('token：邮箱大小写不敏感（客户端可能发大写）', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const result = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL.toUpperCase(),
    password: CLIENT_HASH,
  });

  assert.equal(result.status, 200, '大写邮箱应能登录');
  h.handle.close();
});

// ---------------------------------------------------------------- 2FA 分支

// 这两条守的是一个**关键性质**：光有正确密码，在开启 2FA 时**不能**换到凭据。
// 这是整个认证链上最容易被改坏、也最贵的一处。
const TWO_FACTOR_PROVIDER_YUBIKEY = '3';
const TWO_FACTOR_PROVIDER_REMEMBER = '5';

test('token：开启 2FA 后，只有密码正确也必须走挑战流程，不得签发凭据', async () => {
  const h = await createHarness();
  // YubiKey 的"公钥 ID"当前只做非空判断，任意非空值即可让用户进入 2FA 分支
  await seedUserWithPassword(h, { yubikeyKey1: 'ccccccbcgujh' });

  const result = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL,
    password: CLIENT_HASH,
  });

  assert.equal(result.status, 400, '开了 2FA 就不该直接返回 200');
  assert.equal(result.body.error, 'invalid_grant');
  assert.ok(result.body.access_token === undefined, '2FA 未完成前绝不能签发 access token');
  assert.ok(result.body.refresh_token === undefined, '2FA 未完成前绝不能签发 refresh token');
  assert.ok(
    Array.isArray(result.body.TwoFactorProviders) &&
      (result.body.TwoFactorProviders as string[]).includes(TWO_FACTOR_PROVIDER_YUBIKEY),
    `挑战响应应列出已启用的 2FA 提供方，实际：${JSON.stringify(result.body.TwoFactorProviders)}`
  );
  assert.equal(
    h.handle.connection.prepare('SELECT COUNT(*) AS count FROM refresh_tokens').get()?.count,
    0,
    '2FA 挑战阶段不得写入 refresh token'
  );

  h.handle.close();
});

test('token：提供无效的「记住此设备」令牌时回到挑战流程，而不是放行', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h, { yubikeyKey1: 'ccccccbcgujh' });

  const result = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL,
    password: CLIENT_HASH,
    twoFactorProvider: TWO_FACTOR_PROVIDER_REMEMBER,
    twoFactorToken: 'not-a-real-remember-token',
  });

  assert.equal(result.status, 400, '无效的记住令牌必须回到挑战流程');
  assert.ok(result.body.access_token === undefined);
  assert.ok(Array.isArray(result.body.TwoFactorProviders), '应重新给出 2FA 挑战载荷');

  h.handle.close();
});

// ---------------------------------------------------------------- 凭据用途隔离

test('凭据用途隔离：access token 不能当 refresh token 用', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const login = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL,
    password: CLIENT_HASH,
  });
  assert.equal(login.status, 200);
  const accessToken = String(login.body.access_token);

  const abuse = await callToken(h, { grant_type: 'refresh_token', refresh_token: accessToken });

  assert.notEqual(abuse.status, 200, 'access token 不该能换出新凭据');
  assert.ok(abuse.body.access_token === undefined, '被拒绝的刷新绝不能签发新 access token');

  h.handle.close();
});

test('凭据用途隔离：不存在的 refresh token 换不出凭据', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const result = await callToken(h, { grant_type: 'refresh_token', refresh_token: 'not-a-real-token' });

  assert.notEqual(result.status, 200);
  assert.ok(result.body.access_token === undefined);

  h.handle.close();
});

// ---------------------------------------------------------------- 撤销

test('撤销：未知 token 也返回 200（RFC 7009），已知 token 会被删除', async () => {
  const h = await createHarness();
  await seedUserWithPassword(h);

  const login = await callToken(h, {
    grant_type: 'password',
    username: USER_EMAIL,
    password: CLIENT_HASH,
  });
  assert.equal(login.status, 200);
  const refreshToken = String(login.body.refresh_token);

  const revoke = (token: string) =>
    handleRevocation(
      new Request('https://vault.example.test/identity/connect/revocation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': CLIENT_IP },
        body: JSON.stringify({ token }),
      }),
      h.env
    );

  assert.equal((await revoke('unknown-token')).status, 200, '未知 token 也应是 200，避免泄露存在性');
  assert.equal((await revoke(refreshToken)).status, 200);

  const remaining = h.handle.connection
    .prepare('SELECT COUNT(*) AS count FROM refresh_tokens WHERE user_id = ?')
    .get(USER_ID) as { count: number };
  assert.equal(remaining.count, 0, '撤销后 refresh token 应已删除');

  h.handle.close();
});

test('撤销：请求体无法解析时仍返回 200（best-effort，不报错）', async () => {
  const h = await createHarness();

  const response = await handleRevocation(
    new Request('https://vault.example.test/identity/connect/revocation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{not json',
    }),
    h.env
  );

  assert.equal(response.status, 200);
  h.handle.close();
});
