// 查询数不随返回行数增长（防 N+1 回归）
//
// 为什么需要它：第 5 轮用"按缩进找 `for (...) { await ... }`"的方式扫过全仓库，
// 结论是"11 处批量分块（正确）+ 7 处逐条串行"。但那个扫法**看不见**
// `Promise.all(x.map(async …))` —— 它没有 for 循环，却是实打实的 N+1：
// N 次 await 往返，只是没有 await 写在循环里。
//
// 所以本文件不用"数源码里有几个 await"，而是**数运行时的数据库往返次数**，
// 并断言：**行数变了、查询数不变**。这个断言与实现完全无关 ——
// 无论用 `Promise.all`、`for` 还是将来别的写法，只要是 N+1 就会失败。
//
// 运行方式：npm run test:query-count
import assert from 'node:assert/strict';
import test from 'node:test';

import { handleAdminListUsers } from '../src/handlers/admin';
import { handleListPendingAuthRequests } from '../src/handlers/auth-requests';
import { handleUntrustDevices, handleUpdateDeviceTrust } from '../src/handlers/devices';
import { LIMITS } from '../src/config/limits';
import { StorageService } from '../src/services/storage';
import type { Env, User } from '../src/types';
import { createSchemaDatabase, enc, FIXED_NOW, insertUser } from './lib/test-harness';
import { recordQueries } from './lib/sql-recorder';

const REQUEST_URL = 'https://vault.example.test/api/admin/users';

/**
 * 在**随机数被钉住**的前提下跑一段测量。
 *
 * 为什么必须这么做：仓库里有几处**概率门控**的低频清理挂在普通操作上，例如
 * `writeAuditEvent` → `maybePruneAuditLogs()`（`Math.random() > 概率` 才跑，
 * 一跑就多出约 2 条查询）。不清掉这个随机性，同一个用例的查询数会时多时少 ——
 * 实测就出现过"2 台时 5 次、8 台时 3 次"这种方向都反了的比较。
 *
 * 钉成 1 表示**门永远不开**（`1 > 概率` 恒真），于是计数得到的是确定的下界 ——
 * 这正是本文件要断言的东西："查询数不随行数增长"。
 */
async function withDeterministicRandom<T>(run: () => Promise<T>): Promise<T> {
  const original = Math.random;
  Math.random = () => 1;
  try {
    return await run();
  } finally {
    Math.random = original;
  }
}

function buildEnv(db: Env['DB']): Env {
  return {
    DB: db,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
    },
  } as unknown as Env;
}

// ---------------------------------------------------------------- 管理员用户列表

/**
 * 造一个管理员 + `userCount` 个普通用户，跑一次 `handleAdminListUsers`，
 * 返回响应条数与**数据库往返次数**。
 */
async function measureAdminListUsers(userCount: number): Promise<{ items: number; queries: number }> {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'admin-1', { role: 'admin' });
  for (let i = 0; i < userCount; i += 1) {
    insertUser(handle.connection, `member-${i}`);
  }

  // 每个用户都配一把 twoFactor passkey —— 这正是原实现逐用户去 count 的东西
  for (let i = 0; i < userCount; i += 1) {
    handle.connection
      .prepare(
        'INSERT INTO webauthn_credentials (id, user_id, purpose, name, public_key, credential_id, counter, transports, supports_prf, created_at, updated_at) ' +
          'VALUES (?,?,?,?,?,?,?,?,?,?,?)'
      )
      .run(`pk-${i}`, `member-${i}`, 'twoFactor', 'passkey', 'pub', `cred-${i}`, 0, '[]', 0, FIXED_NOW, FIXED_NOW);
  }

  const recorder = recordQueries(handle.db);
  const env = buildEnv(recorder.db);
  const actor = { id: 'admin-1', email: 'admin-1@example.test', role: 'admin', status: 'active' } as unknown as User;

  const response = await handleAdminListUsers(new Request(REQUEST_URL, { method: 'GET' }), env, actor);
  assert.equal(response.status, 200, '管理员列用户应返回 200');
  const body = (await response.json()) as { data: unknown[] };

  handle.close();
  return { items: body.data.length, queries: recorder.roundTrips };
}

test('管理员列用户：查询数不随用户数增长（防逐用户 count 的 N+1）', async () => {
  const small = await withDeterministicRandom(() => measureAdminListUsers(3));
  const large = await withDeterministicRandom(() => measureAdminListUsers(8));

  // 修改前是 `2 + N`：3 个用户 5 次往返、8 个用户 10 次。
  console.log(`  [实测] 管理员列用户：3 个用户 → ${small.queries} 次往返；8 个用户 → ${large.queries} 次（修改前为 5 / 10）`);

  assert.equal(small.items, 4, '前置条件：3 个成员 + 1 个管理员');
  assert.equal(large.items, 9, '前置条件：8 个成员 + 1 个管理员');
  assert.equal(
    large.queries,
    small.queries,
    `往返数随用户数增长了（3 个用户时 ${small.queries} 次，8 个用户时 ${large.queries} 次）—— 说明存在逐用户的 N+1 查询`
  );
});

test('管理员列用户：响应里能正确标出「哪些用户启用了双因素 passkey」', async () => {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'admin-1', { role: 'admin' });
  insertUser(handle.connection, 'with-passkey');
  insertUser(handle.connection, 'without-passkey');

  handle.connection
    .prepare(
      'INSERT INTO webauthn_credentials (id, user_id, purpose, name, public_key, credential_id, counter, transports, supports_prf, created_at, updated_at) ' +
        'VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run('pk-1', 'with-passkey', 'twoFactor', 'passkey', 'pub', 'cred-1', 0, '[]', 0, FIXED_NOW, FIXED_NOW);

  const env = buildEnv(handle.db);
  const actor = { id: 'admin-1', email: 'admin-1@example.test', role: 'admin', status: 'active' } as unknown as User;
  const response = await handleAdminListUsers(new Request(REQUEST_URL, { method: 'GET' }), env, actor);
  const body = (await response.json()) as { data: Array<{ id: string; twoFactorEnabled: boolean }> };

  const byId = new Map(body.data.map((user) => [user.id, user.twoFactorEnabled]));
  assert.equal(byId.get('with-passkey'), true, '配了 twoFactor passkey 的用户应标记为已启用');
  assert.equal(byId.get('without-passkey'), false, '没配的用户不应被标记');
  assert.equal(byId.get('admin-1'), false);

  handle.close();
});

// ---------------------------------------------------------------- 待处理的登录请求

/**
 * 造 `requestCount` 条来自**不同设备**的待处理登录请求，跑一次
 * `handleListPendingAuthRequests`，返回响应条数与查询条数。
 *
 * 用不同设备是必需的：原实现是「每个请求去查一次该设备」，若请求都来自同一个设备，
 * N+1 就会被去重逻辑掩盖，测不出来。
 */
async function measurePendingAuthRequests(requestCount: number): Promise<{ items: number; queries: number }> {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'user-1');

  for (let i = 0; i < requestCount; i += 1) {
    // 先登记设备，这样 getDevice 才能查到 —— 否则原实现查不到也会走同样的次数，
    // 但为了让"行为等价"的断言有意义，还是把设备造出来
    handle.connection
      .prepare(
        'INSERT INTO devices (user_id, device_identifier, name, type, last_seen_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?)'
      )
      .run('user-1', `device-${i}`, `device-${i}`, 1, FIXED_NOW, FIXED_NOW, FIXED_NOW);

    handle.connection
      .prepare(
        'INSERT INTO auth_requests (id, user_id, type, request_device_identifier, request_device_type, access_code, public_key, approved, creation_date) ' +
          'VALUES (?,?,?,?,?,?,?,?,?)'
      )
      .run(`ar-${i}`, 'user-1', 0, `device-${i}`, 1, `code-${i}`, enc(`pub-${i}`), null, new Date().toISOString());
  }

  const recorder = recordQueries(handle.db);
  const env = buildEnv(recorder.db);
  const response = await handleListPendingAuthRequests(
    new Request('https://vault.example.test/api/auth-requests/pending', { method: 'GET' }),
    env,
    'user-1'
  );
  assert.equal(response.status, 200);
  const body = (await response.json()) as { data: unknown[] };

  handle.close();
  return { items: body.data.length, queries: recorder.roundTrips };
}

test('待处理登录请求：查询数不随请求条数增长（防逐请求查设备的 N+1）', async () => {
  const small = await withDeterministicRandom(() => measurePendingAuthRequests(2));
  const large = await withDeterministicRandom(() => measurePendingAuthRequests(6));

  // 修改前是 `2 + N`：2 条请求 4 次往返、6 条请求 8 次。
  console.log(`  [实测] 待处理登录请求：2 条 → ${small.queries} 次往返；6 条 → ${large.queries} 次（修改前为 4 / 8）`);

  assert.equal(small.items, 2, '前置条件：2 条待处理请求');
  assert.equal(large.items, 6, '前置条件：6 条待处理请求');
  assert.equal(
    large.queries,
    small.queries,
    `往返数随请求条数增长了（2 条时 ${small.queries} 次，6 条时 ${large.queries} 次）—— 这是登录审批轮询路径上的 N+1`
  );
});

test('待处理登录请求：设备标识原样回显，未登记的设备也不会导致字段缺失', async () => {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'user-1');

  // 一台已登记（设备表里的 name 故意与标识不同）＋一台未登记 ——
  // 用来证明返回值**与设备表无关**（原本这里会去查设备，现已删除那次查询）
  handle.connection
    .prepare(
      'INSERT INTO devices (user_id, device_identifier, name, type, last_seen_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?)'
    )
    .run('user-1', 'device-known', 'My Laptop', 1, FIXED_NOW, FIXED_NOW, FIXED_NOW);

  for (const identifier of ['device-known', 'device-unknown']) {
    handle.connection
      .prepare(
        'INSERT INTO auth_requests (id, user_id, type, request_device_identifier, request_device_type, access_code, public_key, approved, creation_date) ' +
          'VALUES (?,?,?,?,?,?,?,?,?)'
      )
      .run(`ar-${identifier}`, 'user-1', 0, identifier, 1, `code-${identifier}`, enc('pub'), null, new Date().toISOString());
  }

  const env = buildEnv(handle.db);
  const response = await handleListPendingAuthRequests(
    new Request('https://vault.example.test/api/auth-requests/pending', { method: 'GET' }),
    env,
    'user-1'
  );
  const body = (await response.json()) as {
    data: Array<{ requestDeviceIdentifier?: string; requestDeviceId?: string | null }>;
  };
  assert.equal(body.data.length, 2);

  // 本用例原本的名字是「能查到设备时用设备上记录的名字」，但那是**错的**：
  // `toAuthRequestResponse` 把入参原样写进 requestDeviceId，根本不查设备表，
  // 而且它回显的是**标识**而不是设备表里的 `name`。所以断言改成落在"原样回显"上 ——
  // 这也正是删掉那 N 次设备查询后必须保持的行为。
  const returned = body.data.map((item) => item.requestDeviceIdentifier).sort();
  const expected = ['device-known', 'device-unknown'].sort();
  assert.deepStrictEqual(
    returned,
    expected,
    '两个标识都必须原样出现在响应里（已登记的那台不得被替换成设备名）'
  );
  for (const item of body.data) {
    assert.equal(
      item.requestDeviceId,
      item.requestDeviceIdentifier,
      'requestDeviceId 应与标识同值：回退逻辑删除后这就是唯一正确的取值'
    );
  }

  handle.close();
});

// ---------------------------------------------------------------- 前置：采样器本身可靠

test('采样器可靠：查询条数确实随 SQL 次数变化（避免断言恒真的假绿）', async () => {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'user-1');
  const recorder = recordQueries(handle.db);
  const storage = new StorageService(recorder.db);

  const before = recorder.roundTrips;
  await storage.getUserById('user-1');
  const afterOne = recorder.roundTrips;
  await storage.getUserById('user-1');
  const afterTwo = recorder.roundTrips;

  assert.equal(afterOne - before, 1, '一次 getUserById 应产生 1 次往返');
  assert.equal(afterTwo - afterOne, 1, '再来一次应再产生 1 次');

  handle.close();
});

// ---------------------------------------------------------------- 设备批量接口（客户端可控列表）

/** 往库里塞 `count` 台设备，返回它们的标识 */
function seedDevices(handle: Awaited<ReturnType<typeof createSchemaDatabase>>, count: number): string[] {
  const identifiers: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const identifier = `device-${i}`;
    identifiers.push(identifier);
    handle.connection
      .prepare(
        'INSERT INTO devices (user_id, device_identifier, name, type, last_seen_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?)'
      )
      .run('user-1', identifier, identifier, 1, FIXED_NOW, FIXED_NOW, FIXED_NOW);
    handle.connection
      .prepare('INSERT INTO trusted_two_factor_device_tokens (token, user_id, device_identifier, expires_at) VALUES (?,?,?,?)')
      .run(`tt-${identifier}`, 'user-1', identifier, Date.now() + 86_400_000);
  }
  return identifiers;
}

function postJson(url: string, payload: unknown): Request {
  return new Request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

async function measureUpdateDeviceTrust(deviceCount: number): Promise<{ queries: number; updated: number }> {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'user-1');
  const identifiers = seedDevices(handle, deviceCount);

  const recorder = recordQueries(handle.db);
  const env = buildEnv(recorder.db);
  const response = await handleUpdateDeviceTrust(
    postJson('https://vault.example.test/api/devices/update-trust', {
      otherDevices: identifiers.map((deviceId, index) => ({ deviceId, encryptedPublicKey: enc(`pk-${index}`) })),
    }),
    env,
    'user-1'
  );
  assert.equal(response.status, 200, `批量更新设备密钥应返回 200，实际 ${response.status}`);
  const body = (await response.json()) as { updated: number };

  handle.close();
  return { queries: recorder.roundTrips, updated: body.updated };
}

test('批量更新设备密钥：查询数不随请求体里的设备数增长（列表来自客户端，无天然上界）', async () => {
  const small = await withDeterministicRandom(() => measureUpdateDeviceTrust(2));
  const large = await withDeterministicRandom(() => measureUpdateDeviceTrust(8));

  console.log(`  [实测] 批量更新设备密钥：2 台 → ${small.queries} 次往返；8 台 → ${large.queries} 次（修改前为 4 / 16）`);

  assert.equal(small.updated, 2, '前置条件：应报告 2 台已更新');
  assert.equal(large.updated, 8, '前置条件：应报告 8 台已更新');
  assert.equal(
    large.queries,
    small.queries,
    `往返数随设备数增长了（2 台时 ${small.queries} 次，8 台时 ${large.queries} 次）—— 这是由请求体驱动的串行 IO`
  );
});

test('批量更新设备密钥：超出上限的请求被拒绝（400），而不是静默截断', async () => {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'user-1');

  const env = buildEnv(handle.db);
  const tooMany = Array.from({ length: LIMITS.device.maxBulkIdentifiers + 1 }, (_, index) => ({
    deviceId: `device-${index}`,
  }));
  const response = await handleUpdateDeviceTrust(
    postJson('https://vault.example.test/api/devices/update-trust', { otherDevices: tooMany }),
    env,
    'user-1'
  );
  assert.equal(response.status, 400, '超限应 400');

  handle.close();
});

test('批量更新设备密钥：写进去的确实是各设备自己的密钥（没串到一起）', async () => {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'user-1');
  seedDevices(handle, 3);

  const env = buildEnv(handle.db);
  const response = await handleUpdateDeviceTrust(
    postJson('https://vault.example.test/api/devices/update-trust', {
      otherDevices: [
        { deviceId: 'device-1', encryptedPublicKey: enc('one') },
        { deviceId: 'device-2', encryptedPublicKey: enc('two') },
      ],
    }),
    env,
    'user-1'
  );
  assert.equal(response.status, 200);

  const read = (identifier: string) =>
    (
      handle.connection
        .prepare('SELECT encrypted_public_key FROM devices WHERE user_id = ? AND device_identifier = ?')
        .get('user-1', identifier) as { encrypted_public_key: string | null } | undefined
    )?.encrypted_public_key;
  assert.equal(read('device-1'), enc('one'), 'device-1 应拿到自己的密钥');
  assert.equal(read('device-2'), enc('two'), 'device-2 应拿到自己的密钥');
  assert.equal(read('device-0'), null, '未提及的设备不应被改动');

  handle.close();
});

async function measureUntrustDevices(deviceCount: number): Promise<{ queries: number }> {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'user-1');
  const identifiers = seedDevices(handle, deviceCount);

  const recorder = recordQueries(handle.db);
  const env = buildEnv(recorder.db);
  const response = await handleUntrustDevices(
    postJson('https://vault.example.test/api/devices/untrust', { devices: identifiers }),
    env,
    'user-1'
  );
  assert.equal(response.status, 200, `解除信任应返回 200，实际 ${response.status}`);

  handle.close();
  return { queries: recorder.roundTrips };
}

test('解除设备信任：查询数不随请求体里的设备数增长', async () => {
  const small = await withDeterministicRandom(() => measureUntrustDevices(2));
  const large = await withDeterministicRandom(() => measureUntrustDevices(8));

  console.log(`  [实测] 解除设备信任：2 台 → ${small.queries} 次往返；8 台 → ${large.queries} 次（修改前为 4 / 16）`);

  assert.equal(
    large.queries,
    small.queries,
    `往返数随设备数增长了（2 台时 ${small.queries} 次，8 台时 ${large.queries} 次）`
  );
});

test('解除设备信任：超限 400，且「记住此设备」令牌确实被删干净', async () => {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, 'user-1');
  const identifiers = seedDevices(handle, 3);
  const env = buildEnv(handle.db);

  const rejected = await handleUntrustDevices(
    postJson('https://vault.example.test/api/devices/untrust', {
      devices: Array.from({ length: LIMITS.device.maxBulkIdentifiers + 1 }, (_, index) => `d-${index}`),
    }),
    env,
    'user-1'
  );
  assert.equal(rejected.status, 400, '超限应 400');

  const accepted = await handleUntrustDevices(
    postJson('https://vault.example.test/api/devices/untrust', { devices: identifiers }),
    env,
    'user-1'
  );
  assert.equal(accepted.status, 200);

  const remaining = handle.connection
    .prepare('SELECT COUNT(*) AS count FROM trusted_two_factor_device_tokens WHERE user_id = ?')
    .get('user-1') as { count: number };
  assert.equal(remaining.count, 0, '所有选定设备的令牌都应被删除');

  handle.close();
});
