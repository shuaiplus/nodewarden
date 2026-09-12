// `src/handlers/attachments.ts` 的行为测试
//
// 为什么值得单独测：附件是**唯一把数据写进 R2 对象存储**的功能面，因此风险比纯 D1 的 handler 多一层：
//
//   ① **两个存储要一致**：删除必须同时清掉 R2 对象与 D1 元数据。只删一边就会产生
//      "数据库说没有、R2 里还躺着用户文件"（隐私问题）或"数据库说有条目、下载 404"（坏体验）。
//   ② **下载授权走的是签名 URL**：`?token=...` 是唯一的凭证，它必须绑定到具体的
//      cipher + attachment，且**只能用一次**（`consumeAttachmentDownloadToken`）。
//   ③ **上传是一次性的**：同一个附件重复上传应被 409 挡住，避免元数据与实际内容对不上。
//
// 运行方式：npm run test:attachments-handler
import assert from 'node:assert/strict';
import type { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  handleCreateAttachment,
  handleDeleteAttachment,
  handleGetAttachment,
  handlePublicDownloadAttachment,
  handleUploadAttachment,
} from '../src/handlers/attachments';
import { handleCreateCipher } from '../src/handlers/ciphers';
import { LIMITS } from '../src/config/limits';
import type { Env } from '../src/types';
import { createR2MemoryBucket } from './lib/r2-memory';
import { createSchemaDatabase, enc, insertUser, TEST_JWT_SECRET } from './lib/test-harness';

const OWNER = 'owner-1';
const STRANGER = 'stranger-1';

interface Harness {
  handle: Awaited<ReturnType<typeof createSchemaDatabase>>;
  connection: DatabaseSync;
  env: Env;
  bucket: ReturnType<typeof createR2MemoryBucket>;
}

async function createHarness(): Promise<Harness> {
  const handle = await createSchemaDatabase();
  insertUser(handle.connection, OWNER);
  insertUser(handle.connection, STRANGER);
  const bucket = createR2MemoryBucket();
  const env = {
    DB: handle.db,
    ATTACHMENTS: bucket.bucket,
    JWT_SECRET: TEST_JWT_SECRET,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
    },
  } as unknown as Env;
  return { handle, connection: handle.connection, env, bucket };
}

function jsonRequest(url: string, body: unknown, method = 'POST'): Request {
  return new Request(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** 造一个属于 OWNER 的条目，返回其 id */
async function seedCipher(h: Harness, owner = OWNER): Promise<string> {
  const response = await handleCreateCipher(
    jsonRequest('https://vault.example.test/api/ciphers', {
      type: 1,
      name: enc('cipher'),
      login: { username: enc('u') },
    }),
    h.env,
    owner
  );
  assert.equal(response.status, 200, `造条目失败：${response.status}`);
  return String(((await response.json()) as { id: string }).id);
}

/** 创建附件元数据，返回 attachmentId 与"上传用的 URL" */
async function createAttachment(
  h: Harness,
  cipherId: string,
  options: { owner?: string; fileName?: string; key?: string; fileSize?: number } = {}
): Promise<{ status: number; attachmentId: string; uploadIdSearch: string; body: Record<string, unknown> }> {
  const response = await handleCreateAttachment(
    jsonRequest(`https://vault.example.test/api/ciphers/${cipherId}/attachment`, {
      fileName: options.fileName ?? enc('file-name'),
      key: options.key ?? enc('file-key'),
      fileSize: options.fileSize ?? 5,
    }),
    h.env,
    options.owner ?? OWNER,
    cipherId
  );
  const body = (await response.json()) as Record<string, unknown>;
  // 响应里的 url 是绝对地址（带一次性上传 token）。只在成功时解析 ——
  // 失败时没有 url，硬解析会抛出与本用例无关的 TypeError。
  const rawUrl = typeof body.url === 'string' ? body.url : '';
  const uploadIdSearch = rawUrl ? `https://vault.example.test${new URL(rawUrl).pathname}${new URL(rawUrl).search}` : '';
  return {
    status: response.status,
    attachmentId: String(body.attachmentId ?? ''),
    uploadIdSearch,
    body,
  };
}

/** 字符串的实际字节数 —— 上传时声明的 fileSize 必须与它一致，否则会被 400 拒 */
function byteLength(content: string): number {
  return new TextEncoder().encode(content).length;
}

/** 把内容作为 multipart 表单上传（字段名必须是 `data`） */
function multipartUpload(url: string, content: string, fileName = 'file.bin'): Request {
  const form = new FormData();
  form.set('data', new File([content], fileName, { type: 'application/octet-stream' }));
  return new Request(url, { method: 'POST', body: form });
}

function attachmentRowCount(h: Harness): number {
  return (h.connection.prepare('SELECT COUNT(*) AS count FROM attachments').get() as { count: number }).count;
}

// ---------------------------------------------------------------- 创建元数据

test('创建附件：条目不存在或不属于当前用户时 404（而且不能借此探测他人条目）', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);

  assert.equal((await createAttachment(h, cipherId, { owner: STRANGER })).status, 404, '跨用户必须 404');
  assert.equal((await createAttachment(h, 'no-such-cipher')).status, 404);
  assert.equal(attachmentRowCount(h), 0, '被拒绝的创建不得写入任何元数据');

  h.handle.close();
});

test('创建附件：缺 fileName 或 key 时 400', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);

  const noKey = await handleCreateAttachment(
    jsonRequest(`https://x/api/ciphers/${cipherId}/attachment`, { fileName: enc('f') }),
    h.env,
    OWNER,
    cipherId
  );
  assert.equal(noKey.status, 400);

  const noName = await handleCreateAttachment(
    jsonRequest(`https://x/api/ciphers/${cipherId}/attachment`, { key: enc('k') }),
    h.env,
    OWNER,
    cipherId
  );
  assert.equal(noName.status, 400);
  assert.equal(attachmentRowCount(h), 0);

  h.handle.close();
});

test('创建附件：返回可直接上传的地址与令牌，并写入元数据', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  const created = await createAttachment(h, cipherId, { fileSize: 2048 });

  assert.equal(created.status, 200);
  assert.equal(created.body.object, 'attachment-fileUpload');
  assert.equal(created.body.fileUploadType, 1, '官方客户端据此判断是直传还是走表单');
  assert.ok(created.uploadIdSearch.includes('token='), '上传地址必须自带一次性令牌');
  assert.equal(attachmentRowCount(h), 1);

  const row = h.connection
    .prepare('SELECT cipher_id, size, size_name FROM attachments WHERE id = ?')
    .get(created.attachmentId) as { cipher_id: string; size: number; size_name: string };
  assert.equal(row.cipher_id, cipherId);
  assert.equal(row.size, 2048);
  assert.ok(row.size_name, '应同时给出人类可读的大小');

  h.handle.close();
});

// ---------------------------------------------------------------- 上传内容

test('上传：内容写入 R2，且键为「条目 id / 附件 id」', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  const content = 'hello-attachment-bytes';
  const created = await createAttachment(h, cipherId, { fileSize: byteLength(content) });

  const response = await handleUploadAttachment(
    multipartUpload(created.uploadIdSearch, content),
    h.env,
    OWNER,
    cipherId,
    created.attachmentId
  );
  assert.equal(response.status, 201, `上传应成功（201），实际 ${response.status}`);

  const key = `${cipherId}/${created.attachmentId}`;
  assert.ok(h.bucket.keys().includes(key), `对象应写入 ${key}，实际键：${JSON.stringify(h.bucket.keys())}`);
  assert.equal(new TextDecoder().decode(h.bucket.bytesOf(key)!), content, 'R2 里的内容应与上传一致');

  h.handle.close();
});

test('上传：同一附件重复上传返回 409（避免元数据与实际内容对不上）', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  const created = await createAttachment(h, cipherId, { fileSize: byteLength('first') });
  const key = `${cipherId}/${created.attachmentId}`;

  const first = await handleUploadAttachment(
    multipartUpload(created.uploadIdSearch, 'first'),
    h.env,
    OWNER,
    cipherId,
    created.attachmentId
  );
  assert.equal(first.status, 201, '首次上传应成功（201）');

  const second = await handleUploadAttachment(
    multipartUpload(created.uploadIdSearch, 'first'),
    h.env,
    OWNER,
    cipherId,
    created.attachmentId
  );
  assert.equal(second.status, 409, '第二次上传应被拒绝');
  assert.equal(new TextDecoder().decode(h.bucket.bytesOf(key)!), 'first', '原有内容不得被覆盖');

  h.handle.close();
});

test('上传：声明尺寸与实际上传字节数不一致时 400（服务端不信任元数据里的尺寸）', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  // 创建时声明 999 字节，实际上传 4 字节
  const created = await createAttachment(h, cipherId, { fileSize: 999 });

  const response = await handleUploadAttachment(
    multipartUpload(created.uploadIdSearch, 'tiny'),
    h.env,
    OWNER,
    cipherId,
    created.attachmentId
  );

  assert.equal(response.status, 400, '尺寸对不上应被拒，而不是照单全收');
  const body = (await response.json()) as { error?: string };
  assert.match(String(body.error ?? ''), /size does not match/i);
  assert.equal(h.bucket.size(), 0, '被拒绝的上传不得写入对象');

  h.handle.close();
});

// 说明：**没有**为"文件超过大小上限"写用例 —— 上限是 `LIMITS.attachment.maxFileSizeBytes`（100MB），
// 在测试里造一个真正超过它的请求体不现实。该分支（413）无法用当前手段可靠覆盖，
// 已在文档里记为已知的覆盖缺口，而不是写一个"看起来测了"的假用例。

// ---------------------------------------------------------------- 下载授权

test('下载信息：跨用户 404', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  const created = await createAttachment(h, cipherId);

  assert.equal(
    (await handleGetAttachment(new Request('https://x/'), h.env, OWNER, cipherId, created.attachmentId)).status,
    200
  );
  assert.equal(
    (await handleGetAttachment(new Request('https://x/'), h.env, STRANGER, cipherId, created.attachmentId)).status,
    404,
    '非所有者不得拿到下载地址'
  );

  h.handle.close();
});

test('公开下载：无令牌、令牌与路径不匹配都要 401', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  const created = await createAttachment(h, cipherId);

  const noToken = await handlePublicDownloadAttachment(
    new Request('https://x/download'),
    h.env,
    cipherId,
    created.attachmentId
  );
  assert.equal(noToken.status, 401);

  // 用另一个附件的令牌去下载本附件 → 必须被令牌绑定检查挡住
  const other = await createAttachment(h, cipherId);
  const infoResponse = await handleGetAttachment(new Request('https://x/'), h.env, OWNER, cipherId, other.attachmentId);
  const infoBody = (await infoResponse.json()) as { url?: string };
  const otherToken = new URL(String(infoBody.url)).searchParams.get('token')!;

  const mismatched = await handlePublicDownloadAttachment(
    new Request(`https://x/download?token=${encodeURIComponent(otherToken)}`),
    h.env,
    cipherId,
    created.attachmentId
  );
  assert.equal(mismatched.status, 401, '令牌必须绑定到具体条目+附件');

  h.handle.close();
});

test('公开下载：令牌只能用一次，且响应头做了防嗅探处理', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  const content = 'download-me';
  const created = await createAttachment(h, cipherId, { fileSize: byteLength(content) });
  await handleUploadAttachment(
    multipartUpload(created.uploadIdSearch, content),
    h.env,
    OWNER,
    cipherId,
    created.attachmentId
  );
  assert.equal(h.bucket.size(), 1, '前置条件：内容已写入 R2');

  const infoResponse = await handleGetAttachment(new Request('https://x/'), h.env, OWNER, cipherId, created.attachmentId);
  const infoBody = (await infoResponse.json()) as { url?: string };
  const token = new URL(String(infoBody.url)).searchParams.get('token')!;
  const downloadUrl = `https://x/download?token=${encodeURIComponent(token)}`;

  const first = await handlePublicDownloadAttachment(new Request(downloadUrl), h.env, cipherId, created.attachmentId);
  assert.equal(first.status, 200);
  assert.equal(await first.text(), content, '下载内容应与上传一致');
  assert.equal(first.headers.get('X-Content-Type-Options'), 'nosniff', '必须阻止浏览器嗅探内容类型');
  assert.match(String(first.headers.get('Content-Disposition')), /attachment/, '应作为下载而非内联展示');

  const second = await handlePublicDownloadAttachment(new Request(downloadUrl), h.env, cipherId, created.attachmentId);
  assert.equal(second.status, 401, '同一下载令牌不得重复使用');

  h.handle.close();
});

// ---------------------------------------------------------------- 删除（两个存储要一致）

test('删除：跨用户 404，且 R2 对象与元数据都不受影响', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  const content = 'keep-me';
  const created = await createAttachment(h, cipherId, { fileSize: byteLength(content) });
  await handleUploadAttachment(
    multipartUpload(created.uploadIdSearch, content),
    h.env,
    OWNER,
    cipherId,
    created.attachmentId
  );
  assert.equal(h.bucket.size(), 1, '前置条件：内容已写入 R2');

  const response = await handleDeleteAttachment(
    new Request('https://x/', { method: 'DELETE' }),
    h.env,
    STRANGER,
    cipherId,
    created.attachmentId
  );
  assert.equal(response.status, 404);
  assert.equal(attachmentRowCount(h), 1, '元数据不得被删');
  assert.equal(h.bucket.size(), 1, 'R2 对象不得被删');

  h.handle.close();
});

test('删除：所有者删除后，R2 对象与元数据都必须消失，并留下审计事件', async () => {
  const h = await createHarness();
  const cipherId = await seedCipher(h);
  const content = 'delete-me';
  const created = await createAttachment(h, cipherId, { fileSize: byteLength(content) });
  await handleUploadAttachment(
    multipartUpload(created.uploadIdSearch, content),
    h.env,
    OWNER,
    cipherId,
    created.attachmentId
  );
  assert.equal(h.bucket.size(), 1, '前置条件：对象已写入');

  const response = await handleDeleteAttachment(
    new Request('https://x/', { method: 'DELETE' }),
    h.env,
    OWNER,
    cipherId,
    created.attachmentId
  );
  assert.equal(response.status, 200);
  assert.equal(attachmentRowCount(h), 0, '元数据应被删除');
  assert.equal(h.bucket.size(), 0, 'R2 对象也必须被删除 —— 只删一边会留下"数据库说没有、对象存储里还躺着用户文件"');

  const audit = h.connection
    .prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action = 'attachment.delete'")
    .get() as { count: number };
  assert.equal(audit.count, 1, '删除附件应留下审计事件');

  h.handle.close();
});
