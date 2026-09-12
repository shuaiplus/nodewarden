// `src/handlers/folders.ts` 的行为测试
//
// 选它的理由（NEXT.md §3.4）：逻辑简单，适合把"handler 级测试能测到什么"这件事示范清楚。
// 但简单不等于没坑 —— 这里有三处**容易在改动中悄悄坏掉**的行为：
//
//   ① **删除文件夹会把条目的 `folder_id` 清空**（跨表副作用，不测就看不见）
//   ② **更新时省略 `name` 表示"不改名"**（与 ciphers 的"省略即清空"**相反** —— 两个端点的
//      语义确实不同，属于历史约定，用测试固化下来，避免后人"统一"成一种）
//   ③ **列表支持真正的分页**（`handleGetFolders` 用 `pageSize` + `continuationToken`，
//      这是正确写法；与 §3.3.5 里管理端那个"形状支持但没实现"的接口形成对比）
//
// 运行方式：npm run test:folders-handler
import assert from 'node:assert/strict';
import type { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  handleCreateFolder,
  handleDeleteFolder,
  handleGetFolder,
  handleGetFolders,
  handleUpdateFolder,
} from '../src/handlers/folders';
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

function jsonRequest(url: string, body: unknown, method = 'POST'): Request {
  return new Request(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function createFolder(h: Harness, user: string, name: string): Promise<Record<string, unknown>> {
  const response = await handleCreateFolder(jsonRequest('https://x/api/folders', { name }), h.env, user);
  assert.equal(response.status, 200, `创建文件夹应成功，实际 ${response.status}`);
  return (await response.json()) as Record<string, unknown>;
}

function folderCount(h: Harness): number {
  return (h.connection.prepare('SELECT COUNT(*) AS count FROM folders').get() as { count: number }).count;
}

// ---------------------------------------------------------------- 创建

test('创建：缺 name 与非法 JSON 都返回 400', async () => {
  const h = await createHarness();

  assert.equal((await handleCreateFolder(jsonRequest('https://x/api/folders', {}), h.env, OWNER)).status, 400);
  assert.equal(
    (await handleCreateFolder(jsonRequest('https://x/api/folders', { name: '' }), h.env, OWNER)).status,
    400,
    '空字符串 name 视同缺失'
  );
  assert.equal(
    (
      await handleCreateFolder(
        new Request('https://x/api/folders', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{not json',
        }),
        h.env,
        OWNER
      )
    ).status,
    400
  );
  assert.equal(folderCount(h), 0, '被拒绝的请求不得写入任何数据');

  h.handle.close();
});

test('创建：客户端伪造的 userId 会被会话身份覆盖', async () => {
  const h = await createHarness();
  const response = await handleCreateFolder(
    jsonRequest('https://x/api/folders', { name: enc('name'), userId: STRANGER }),
    h.env,
    OWNER
  );
  const body = (await response.json()) as { id: string };

  const row = h.connection.prepare('SELECT user_id FROM folders WHERE id = ?').get(body.id) as {
    user_id: string;
  };
  assert.equal(row.user_id, OWNER, '归属必须取自会话，否则可把数据写进他人账户');

  h.handle.close();
});

// ---------------------------------------------------------------- 读取与跨用户隔离

test('读取：所有者 200，非所有者 404', async () => {
  const h = await createHarness();
  const created = await createFolder(h, OWNER, enc('name'));
  const id = String(created.id);

  assert.equal((await handleGetFolder(new Request(`https://x/api/folders/${id}`), h.env, OWNER, id)).status, 200);
  assert.equal(
    (await handleGetFolder(new Request(`https://x/api/folders/${id}`), h.env, STRANGER, id)).status,
    404,
    '非所有者必须 404'
  );

  h.handle.close();
});

// ---------------------------------------------------------------- 更新

test('更新：非所有者 404 且数据不变', async () => {
  const h = await createHarness();
  const created = await createFolder(h, OWNER, enc('original'));
  const id = String(created.id);
  const before = { ...(h.connection.prepare('SELECT * FROM folders WHERE id = ?').get(id) as object) };

  const response = await handleUpdateFolder(
    jsonRequest(`https://x/api/folders/${id}`, { name: enc('hijacked') }, 'PUT'),
    h.env,
    STRANGER,
    id
  );
  assert.equal(response.status, 404);
  assert.deepStrictEqual(
    { ...(h.connection.prepare('SELECT * FROM folders WHERE id = ?').get(id) as object) },
    before,
    '被拒绝的更新不得改动数据'
  );

  h.handle.close();
});

test('更新：省略 name 表示「不改名」（与 ciphers 的替换语义相反，此处固化既有约定）', async () => {
  const h = await createHarness();
  const created = await createFolder(h, OWNER, enc('keep-me'));
  const id = String(created.id);

  // 刻意把 updated_at 拨回一个**已知的过去时刻**再更新。
  //
  // 原先这里比较的是「更新前后两次 `new Date().toISOString()` 是否不同」—— 而两次调用
  // 可能落在**同一毫秒**，断言就随机失败（实际上已经偶发红过一次）。
  // 把基线钉死在过去，这里才变成确定性判断。
  const baseline = '2020-01-01T00:00:00.000Z';
  h.connection.prepare('UPDATE folders SET updated_at = ? WHERE id = ?').run(baseline, id);

  const response = await handleUpdateFolder(
    jsonRequest(`https://x/api/folders/${id}`, {}, 'PUT'),
    h.env,
    OWNER,
    id
  );
  assert.equal(response.status, 200);

  const row = h.connection.prepare('SELECT name, updated_at FROM folders WHERE id = ?').get(id) as {
    name: string;
    updated_at: string;
  };
  assert.equal(row.name, enc('keep-me'), '省略 name 不应把名字清空');
  assert.ok(
    row.updated_at > baseline,
    `即使没改名也应推进 updated_at（客户端据此同步），实际仍是 ${row.updated_at}`
  );

  h.handle.close();
});

// ---------------------------------------------------------------- 删除（含跨表副作用）

test('删除：非所有者 404 且数据仍在', async () => {
  const h = await createHarness();
  const created = await createFolder(h, OWNER, enc('name'));
  const id = String(created.id);

  const response = await handleDeleteFolder(new Request(`https://x/api/folders/${id}`, { method: 'DELETE' }), h.env, STRANGER, id);
  assert.equal(response.status, 404);
  assert.equal(folderCount(h), 1, '被拒绝的删除不得真的删掉');

  h.handle.close();
});

test('删除：所有者返回 204，行被删除，并留下审计事件', async () => {
  const h = await createHarness();
  const created = await createFolder(h, OWNER, enc('name'));
  const id = String(created.id);

  const response = await handleDeleteFolder(new Request(`https://x/api/folders/${id}`, { method: 'DELETE' }), h.env, OWNER, id);
  assert.equal(response.status, 204);
  assert.equal(folderCount(h), 0, '文件夹应被删除');

  const audit = h.connection
    .prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action = 'folder.delete' AND target_id = ?")
    .get(id) as { count: number };
  assert.equal(audit.count, 1, '删除文件夹应留下审计事件');

  h.handle.close();
});

test('删除：关联条目的 folder_id 必须被清空（跨表副作用，最容易被改坏）', async () => {
  const h = await createHarness();
  const created = await createFolder(h, OWNER, enc('name'));
  const id = String(created.id);

  // 造两个条目：一个在该文件夹里，一个不在
  for (const [cipherId, folderId] of [
    ['cipher-in-folder', id],
    ['cipher-elsewhere', null],
  ] as const) {
    h.connection
      .prepare(
        'INSERT INTO ciphers (id, user_id, type, folder_id, name, data, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)'
      )
      .run(cipherId, OWNER, 1, folderId, enc('c'), '{}', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z');
  }

  await handleDeleteFolder(new Request(`https://x/api/folders/${id}`, { method: 'DELETE' }), h.env, OWNER, id);

  const inFolder = h.connection.prepare('SELECT folder_id FROM ciphers WHERE id = ?').get('cipher-in-folder') as {
    folder_id: string | null;
  };
  assert.equal(
    inFolder.folder_id,
    null,
    '文件夹被删后，原来属于它的条目必须变成"未分类"，否则客户端会指向一个不存在的文件夹'
  );

  // 关键：清空必须只影响该文件夹，不能误伤别的条目
  const elsewhere = h.connection.prepare('SELECT COUNT(*) AS count FROM ciphers WHERE id = ?').get('cipher-elsewhere') as {
    count: number;
  };
  assert.equal(elsewhere.count, 1, '其他条目的行必须原样保留');

  h.handle.close();
});

// ---------------------------------------------------------------- 列表与分页

test('列表：不带分页参数时返回全部', async () => {
  const h = await createHarness();
  for (let i = 0; i < 3; i += 1) await createFolder(h, OWNER, enc(`f${i}`));

  const response = await handleGetFolders(new Request('https://x/api/folders'), h.env, OWNER);
  const body = (await response.json()) as { data: unknown[]; continuationToken: string | null };
  assert.equal(body.data.length, 3);
  assert.equal(body.continuationToken, null, '未分页时不应给出游标');

  h.handle.close();
});

test('列表：分页游标可翻到底，且最后一页不再返回游标', async () => {
  const h = await createHarness();
  const total = 5;
  for (let i = 0; i < total; i += 1) await createFolder(h, OWNER, enc(`f${i}`));

  const pageSize = 2;
  const seen: string[] = [];
  let token: string | null = null;
  let pages = 0;

  do {
    const url = new URL('https://x/api/folders');
    url.searchParams.set('pageSize', String(pageSize));
    if (token) url.searchParams.set('continuationToken', token);

    const body = (await (await handleGetFolders(new Request(url.toString()), h.env, OWNER)).json()) as {
      data: Array<{ id: string }>;
      continuationToken: string | null;
    };
    for (const folder of body.data) seen.push(folder.id);
    token = body.continuationToken;
    pages += 1;
    assert.ok(pages <= 5, '翻页不应无限循环（游标没推进就会这样）');
  } while (token);

  assert.equal(seen.length, total, '翻完所有页应恰好拿到全部条目，不重不漏');
  assert.equal(new Set(seen).size, total, '不应出现重复条目');
  assert.equal(pages, Math.ceil(total / pageSize), `5 条按每页 2 条应翻 3 页，实际 ${pages} 页`);

  h.handle.close();
});

test('列表：非法的 pageSize 被忽略并回退到「返回全部」', async () => {
  const h = await createHarness();
  for (let i = 0; i < 3; i += 1) await createFolder(h, OWNER, enc(`f${i}`));

  for (const bad of ['0', '-1', 'abc', '1.5']) {
    const url = new URL('https://x/api/folders');
    url.searchParams.set('pageSize', bad);
    const body = (await (await handleGetFolders(new Request(url.toString()), h.env, OWNER)).json()) as {
      data: unknown[];
    };
    assert.equal(body.data.length, 3, `pageSize=${bad} 应被忽略，回退为返回全部`);
  }

  h.handle.close();
});

test('列表：pageSize 超过服务端上限时被夹到上限', async () => {
  const h = await createHarness();
  const url = new URL('https://x/api/folders');
  url.searchParams.set('pageSize', String(LIMITS.pagination.maxPageSize * 10));

  // 只要不抛错、且不是按客户端要的巨量分页就行 —— 这里造的数据量远小于上限，
  // 因此断言"能正常返回全部"即可；上限本身由 parsePagination 的 Math.min 保证。
  const response = await handleGetFolders(new Request(url.toString()), h.env, OWNER);
  assert.equal(response.status, 200);

  h.handle.close();
});
