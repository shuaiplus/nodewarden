// `src/handlers/import.ts` 的行为测试（Bitwarden 客户端的导入端点）
//
// 为什么值得测：导入是**批量写入**路径 —— 客户端会把整个 vault（最多 5000 条）一次性推上来。
// 这里出错的形态与单条 CRUD 不同：
//   · 写错了 → 一次污染几千条，且用户很难分辨哪些是导入的
//   · 失败时留下了半截数据 → 用户看到"导入失败"，库里却多了东西，重试后越积越多
//
// 本文件把下面这条当作**期望行为**来断言：**导入要么整体成功，要么什么都不留下**。
// （首次运行时它应当失败 —— 那正是要修的东西。）
//
// 运行方式：npm run test:import-handler
import assert from 'node:assert/strict';
import type { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { handleCiphersImport } from '../src/handlers/import';
import { LIMITS } from '../src/config/limits';
import type { Env } from '../src/types';
import { createSchemaDatabase, enc, insertUser } from './lib/test-harness';

const OWNER = 'owner-1';
const STRANGER = 'stranger-1';

interface Harness {
  handle: Awaited<ReturnType<typeof createSchemaDatabase>>;
  connection: DatabaseSync;
  env: Env;
}

async function createHarness(): Promise<Harness> {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, OWNER);
  insertUser(handle.connection, STRANGER);
  const env = {
    DB: handle.db,
    JWT_SECRET: 'test-jwt-secret-at-least-32-characters-long',
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
    },
  } as unknown as Env;
  return { handle, connection: handle.connection, env };
}

function importRequest(payload: unknown, query = ''): Request {
  return new Request(`https://vault.example.test/api/ciphers/import${query}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

function counts(h: Harness, user = OWNER): { folders: number; ciphers: number } {
  const folders = h.connection.prepare('SELECT COUNT(*) AS count FROM folders WHERE user_id = ?').get(user) as {
    count: number;
  };
  const ciphers = h.connection.prepare('SELECT COUNT(*) AS count FROM ciphers WHERE user_id = ?').get(user) as {
    count: number;
  };
  return { folders: folders.count, ciphers: ciphers.count };
}

/** 一条合法的导入条目（name 必须是合法 EncString，否则校验会拒） */
function validCipher(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 1,
    name: enc('name'),
    notes: null,
    login: { username: enc('u'), password: enc('p') },
    ...overrides,
  };
}

// ---------------------------------------------------------------- 入参校验

test('导入：非法 JSON 返回 400', async () => {
  const h = await createHarness();

  const response = await handleCiphersImport(
    new Request('https://vault.example.test/api/ciphers/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{not json',
    }),
    h.env,
    OWNER
  );
  assert.equal(response.status, 400);
  assert.deepStrictEqual(counts(h), { folders: 0, ciphers: 0 });

  h.handle.close();
});

test('导入：文件夹与条目合计超过上限时 400，且不写入任何数据', async () => {
  const h = await createHarness();
  const payload = {
    folders: Array.from({ length: 10 }, (_, i) => ({ name: enc(`f${i}`) })),
    ciphers: Array.from({ length: LIMITS.performance.importItemLimit }, () => validCipher()),
  };

  const response = await handleCiphersImport(importRequest(payload), h.env, OWNER);
  assert.equal(response.status, 400);
  assert.match(String(((await response.json()) as { error?: string }).error ?? ''), /maximum/i);
  assert.deepStrictEqual(counts(h), { folders: 0, ciphers: 0 }, '超限必须在写入之前就被拦下');

  h.handle.close();
});

test('导入：空载荷也能成功（0 文件夹 + 0 条目）', async () => {
  const h = await createHarness();

  const response = await handleCiphersImport(importRequest({}), h.env, OWNER);
  assert.equal(response.status, 200);
  assert.deepStrictEqual(counts(h), { folders: 0, ciphers: 0 });

  h.handle.close();
});

// ---------------------------------------------------------------- 成功路径

test('导入：文件夹与条目都落库，归属取自会话身份', async () => {
  const h = await createHarness();
  const response = await handleCiphersImport(
    importRequest({ folders: [{ name: enc('f') }], ciphers: [validCipher(), validCipher()] }),
    h.env,
    OWNER
  );

  assert.equal(response.status, 200);
  assert.deepStrictEqual(counts(h), { folders: 1, ciphers: 2 });
  assert.deepStrictEqual(counts(h, STRANGER), { folders: 0, ciphers: 0 }, '不得写进别人账户');

  h.handle.close();
});

test('导入：缺少 name 的条目会回退为 Untitled，而 Untitled 过不了加密校验 → 整次导入被拒', async () => {
  const h = await createHarness();
  // 这条固化的是一个**容易误以为能用的组合**：代码里确实有 `name: c.name ?? 'Untitled'` 的回退，
  // 但 `Untitled` 不是合法 EncString，会被 `validateCipherEncryptedFieldsForCompatibility` 拦下。
  // 净效果：**没有 name 的条目无法导入**。报错里会带上条目序号，便于用户定位。
  const response = await handleCiphersImport(
    importRequest({ ciphers: [validCipher(), { type: 1 }] }),
    h.env,
    OWNER
  );

  assert.equal(response.status, 400, '缺 name 的条目应使整次导入失败');
  const body = (await response.json()) as { error?: string };
  assert.match(String(body.error ?? ''), /Cipher 2/, '错误信息应指明是第几条出的问题');
  assert.deepStrictEqual(counts(h), { folders: 0, ciphers: 0 }, '被拒的导入不得留下数据');

  h.handle.close();
});

test('导入：返回 CIPHER MAP 时给出 index / sourceId / 新 id 的对应关系', async () => {
  const h = await createHarness();
  const response = await handleCiphersImport(
    importRequest(
      {
        ciphers: [validCipher({ id: 'old-1' }), validCipher(), validCipher({ id: 'old-3' })],
      },
      '?returnCipherMap=1'
    ),
    h.env,
    OWNER
  );

  assert.equal(response.status, 200);
  const body = (await response.json()) as {
    object: string;
    cipherMap: Array<{ index: number; sourceId: string | null; id: string }>;
  };
  assert.equal(body.object, 'import-result');
  assert.equal(body.cipherMap.length, 3);
  assert.deepStrictEqual(
    body.cipherMap.map((entry) => entry.index),
    [0, 1, 2],
    'index 必须与请求体里的顺序一致，客户端靠它把旧 id 换成新 id'
  );
  assert.deepStrictEqual(
    body.cipherMap.map((entry) => entry.sourceId),
    ['old-1', null, 'old-3'],
    '缺 id 的条目 sourceId 应为 null'
  );
  for (const entry of body.cipherMap) {
    assert.ok(entry.id && entry.id !== entry.sourceId, '新 id 必须是服务端生成的，不能沿用客户端传的');
  }

  h.handle.close();
});

// ---------------------------------------------------------------- 文件夹关联

test('导入：folderRelationships 把条目挂到同一批新建的文件夹上', async () => {
  const h = await createHarness();
  // rel.key = 条目下标，rel.value = 文件夹下标
  const response = await handleCiphersImport(
    importRequest({
      folders: [{ name: enc('work') }, { name: enc('home') }],
      ciphers: [validCipher(), validCipher(), validCipher()],
      folderRelationships: [
        { key: 0, value: 1 },
        { key: 1, value: 0 },
      ],
    }),
    h.env,
    OWNER
  );
  assert.equal(response.status, 200);

  const folders = h.connection.prepare('SELECT id, name FROM folders WHERE user_id = ?').all(OWNER) as Array<{
    id: string;
    name: string;
  }>;
  const folderIdByName = new Map(folders.map((row) => [row.name, row.id]));

  const rows = h.connection
    .prepare('SELECT name, folder_id FROM ciphers WHERE user_id = ? ORDER BY rowid')
    .all(OWNER) as Array<{ name: string; folder_id: string | null }>;

  assert.equal(rows[0].folder_id, folderIdByName.get(enc('home')), '第 0 条应挂到 folders[1]');
  assert.equal(rows[1].folder_id, folderIdByName.get(enc('work')), '第 1 条应挂到 folders[0]');
  assert.equal(rows[2].folder_id, null, '没有关系记录的条目应为"未分类"');

  h.handle.close();
});

test('导入：引用不存在的外部 folderId 时归为未分类，而不是写入一个悬空引用', async () => {
  const h = await createHarness();
  const response = await handleCiphersImport(
    importRequest({ ciphers: [validCipher({ folderId: 'no-such-folder' })] }),
    h.env,
    OWNER
  );
  assert.equal(response.status, 200);

  const row = h.connection.prepare('SELECT folder_id FROM ciphers WHERE user_id = ?').get(OWNER) as {
    folder_id: string | null;
  };
  assert.equal(row.folder_id, null, '悬空引用必须被丢弃，否则客户端会指向不存在的文件夹');

  h.handle.close();
});

// ---------------------------------------------------------------- 兼容面

test('导入：客户端未知字段要原样保留（PascalCase 别名只覆盖嵌套对象，此处一并记录）', async () => {
  const h = await createHarness();
  const response = await handleCiphersImport(
    importRequest({
      ciphers: [
        {
          type: 1,
          name: enc('aliased'),
          // 嵌套加密对象走 readAliasedImportProp(...)，因此 PascalCase 可用
          Login: { Username: enc('u') },
          futureClientField: 'keep-me',
          nestedFuture: { deep: [1, 2] },
        },
      ],
    }),
    h.env,
    OWNER
  );
  assert.equal(response.status, 200);

  const row = h.connection.prepare('SELECT name, data FROM ciphers WHERE user_id = ?').get(OWNER) as {
    name: string;
    data: string;
  };
  assert.equal(row.name, enc('aliased'));

  const data = JSON.parse(row.data) as Record<string, unknown>;
  assert.equal(data.futureClientField, 'keep-me', '客户端未知字段必须保留（CONTRIBUTING 硬性要求）');
  assert.deepStrictEqual(data.nestedFuture, { deep: [1, 2] });

  h.handle.close();
});

// 值得记下的**不对称**（不是缺陷，但后人容易踩）：
//   import.ts 里 `folderId` / `login` / `card` / `identity` / `secureNote` / `sshKey` … 这些字段
//   走 `readAliasedImportProp(['x', 'X'])`，**同时接受 camelCase 与 PascalCase**；
//   而 `type` / `name` / `notes` / `favorite` / `reprompt` 是直接属性访问，**只认 camelCase**。
// 官方客户端发的都是 camelCase，所以现在没问题；但假如有客户端只发 `Name`，
// 结果是 name 回退为 'Untitled' → 加密校验失败 → **400 报错并指明条目序号**，
// 即“响亮地失败”而不是静默写坏数据。因此不为此改动实现。

// ---------------------------------------------------------------- 失败时的原子性

test('导入：某条条目非法时返回 400，且**不留下任何写入**（含已解析成功的文件夹）', async () => {
  const h = await createHarness();

  const response = await handleCiphersImport(
    importRequest({
      folders: [{ name: enc('work') }, { name: enc('home') }],
      ciphers: [
        validCipher(),
        // 第 2 条 name 是明文 → 加密字段校验会拒
        validCipher({ name: 'plaintext-not-an-encstring' }),
        validCipher(),
      ],
    }),
    h.env,
    OWNER
  );

  assert.equal(response.status, 400, '非法条目应使整次导入失败');
  assert.deepStrictEqual(
    counts(h),
    { folders: 0, ciphers: 0 },
    '导入失败时库里必须原封不动 —— 留下半截数据会让用户看到"导入失败"却在库里多出东西，且重试后越积越多'
  );

  h.handle.close();
});

test('导入：失败后的重试得到与首次成功一致的结果（不累积垃圾）', async () => {
  const h = await createHarness();
  const payload = {
    folders: [{ name: enc('work') }],
    ciphers: [validCipher(), validCipher({ name: 'bad' })],
  };

  // 连续失败两次
  for (let attempt = 0; attempt < 2; attempt += 1) {
    assert.equal((await handleCiphersImport(importRequest(payload), h.env, OWNER)).status, 400);
  }
  assert.deepStrictEqual(counts(h), { folders: 0, ciphers: 0 }, '两次失败重试后仍应一条不剩');

  // 修好数据后导入成功
  const fixed = { folders: payload.folders, ciphers: [validCipher(), validCipher()] };
  assert.equal((await handleCiphersImport(importRequest(fixed), h.env, OWNER)).status, 200);
  assert.deepStrictEqual(counts(h), { folders: 1, ciphers: 2 });

  h.handle.close();
});
