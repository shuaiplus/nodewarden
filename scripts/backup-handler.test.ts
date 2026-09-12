// `src/handlers/backup.ts` 的行为测试
//
// 为什么值得测：备份/恢复是**唯一直接关系数据存亡**的功能面，而且它是**管理员专用**的 ——
// 13 个端点全部吃 `actorUser`，任何一个漏掉权限判断都等于把整库导出能力开放给普通用户。
//
// 本文件分两部分：
//   ① **权限扫描**：把 13 个管理端点逐个用"非管理员"调一遍，全部必须 403。
//      写成循环而不是抄 13 遍 —— 将来新增端点时只要加进数组，忘了守卫就会红。
//   ② **本地导出**（含附件）：这是 §3.1.1 修过的缺陷，这里做端到端守卫 ——
//      勾了"包含附件"导出的 zip 必须**真的带附件字节**，而不是只有一个说"包含附件"的清单。
//
// 运行方式：npm run test:backup-handler
import assert from 'node:assert/strict';
import type { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { handleCreateCipher } from '../src/handlers/ciphers';
import { handleCreateAttachment, handleUploadAttachment } from '../src/handlers/attachments';
import {
  handleAdminExportBackup,
  handleAdminImportBackup,
  handleDeleteAdminRemoteBackup,
  handleDownloadAdminBackupAttachment,
  handleDownloadAdminRemoteBackup,
  handleGetAdminBackupSettings,
  handleGetAdminBackupSettingsRepairState,
  handleInspectAdminRemoteBackup,
  handleListAdminRemoteBackups,
  handleRepairAdminBackupSettings,
  handleRestoreAdminRemoteBackup,
  handleRunAdminConfiguredBackup,
  handleUpdateAdminBackupSettings,
} from '../src/handlers/backup';
import { parseBackupArchive } from '../src/services/backup-archive';
import { AuthService } from '../src/services/auth';
import { StorageService } from '../src/services/storage';
import type { Env, User } from '../src/types';
import { createR2MemoryBucket } from './lib/r2-memory';
import { createSchemaDatabase, enc, insertUser } from './lib/test-harness';

const ADMIN_ID = 'admin-1';
const ADMIN_EMAIL = 'admin-1@example.test';
const MEMBER_ID = 'member-1';
/** 管理员的主密码（客户端先哈希一次后上传的值） */
const CLIENT_HASH = 'admin-client-side-hash';

interface Harness {
  handle: Awaited<ReturnType<typeof createSchemaDatabase>>;
  connection: DatabaseSync;
  env: Env;
  bucket: ReturnType<typeof createR2MemoryBucket>;
  admin: User;
  member: User;
}

async function createHarness(): Promise<Harness> {
  const handle = await createSchemaDatabase();
  const bucket = createR2MemoryBucket();
  const env = {
    DB: handle.db,
    ATTACHMENTS: bucket.bucket,
    JWT_SECRET: 'test-jwt-secret-at-least-32-characters-long',
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
    },
  } as unknown as Env;

  const adminHash = await new AuthService(env).hashPasswordServer(CLIENT_HASH, ADMIN_EMAIL);
  insertUser(handle.connection, ADMIN_ID, { email: ADMIN_EMAIL, role: 'admin', masterPasswordHash: adminHash });
  insertUser(handle.connection, MEMBER_ID);

  const storage = new StorageService(handle.db);
  const admin = (await storage.getUserById(ADMIN_ID))!;
  const member = (await storage.getUserById(MEMBER_ID))!;

  return { handle, connection: handle.connection, env, bucket, admin, member };
}

function exportRequest(body: unknown, contentType = 'application/json'): Request {
  return new Request('https://vault.example.test/api/admin/backup/export', {
    method: 'POST',
    headers: { 'Content-Type': contentType },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

// ---------------------------------------------------------------- ① 权限扫描

/**
 * 全部管理端点。它们签名一致（`request, env, actorUser`），因此可以统一扫描。
 * 新增端点时把它加进来 —— 忘了 `isAdmin` 守卫，这里就会红。
 */
const ADMIN_ENDPOINTS: Array<[string, (request: Request, env: Env, actorUser: User) => Promise<Response>]> = [
  ['handleGetAdminBackupSettings', handleGetAdminBackupSettings],
  ['handleUpdateAdminBackupSettings', handleUpdateAdminBackupSettings],
  ['handleGetAdminBackupSettingsRepairState', handleGetAdminBackupSettingsRepairState],
  ['handleRepairAdminBackupSettings', handleRepairAdminBackupSettings],
  ['handleRunAdminConfiguredBackup', handleRunAdminConfiguredBackup],
  ['handleListAdminRemoteBackups', handleListAdminRemoteBackups],
  ['handleDownloadAdminRemoteBackup', handleDownloadAdminRemoteBackup],
  ['handleInspectAdminRemoteBackup', handleInspectAdminRemoteBackup],
  ['handleDeleteAdminRemoteBackup', handleDeleteAdminRemoteBackup],
  ['handleRestoreAdminRemoteBackup', handleRestoreAdminRemoteBackup],
  ['handleAdminExportBackup', handleAdminExportBackup],
  ['handleDownloadAdminBackupAttachment', handleDownloadAdminBackupAttachment],
  ['handleAdminImportBackup', handleAdminImportBackup],
];

test('权限：全部 13 个管理端点对普通用户一律 403（且不泄露任何数据）', async () => {
  const h = await createHarness();

  for (const [name, handler] of ADMIN_ENDPOINTS) {
    const request = new Request('https://vault.example.test/api/admin/backup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ masterPasswordHash: CLIENT_HASH }),
    });
    const response = await handler(request, h.env, h.member);
    assert.equal(response.status, 403, `${name} 必须拒绝非管理员，实际 ${response.status}`);
  }

  h.handle.close();
});

test('权限：未登录（actorUser 为普通用户且不带密码）同样被挡住', async () => {
  const h = await createHarness();
  const response = await handleAdminExportBackup(exportRequest({}), h.env, h.member);
  assert.equal(response.status, 403, '权限检查必须发生在密码校验之前');

  h.handle.close();
});

// ---------------------------------------------------------------- ② 本地导出

test('本地导出：缺 masterPasswordHash 或密码错误都拒绝', async () => {
  const h = await createHarness();

  const missing = await handleAdminExportBackup(exportRequest({}), h.env, h.admin);
  assert.equal(missing.status, 400, '缺密码应 400');
  assert.match(String(((await missing.json()) as { error?: string }).error ?? ''), /required/i);

  const wrong = await handleAdminExportBackup(exportRequest({ masterPasswordHash: 'wrong' }), h.env, h.admin);
  assert.equal(wrong.status, 400, '密码错误应 400');
  assert.match(String(((await wrong.json()) as { error?: string }).error ?? ''), /invalid password/i);

  h.handle.close();
});

test('本地导出：成功返回 zip，且响应头做了防嗅探与禁缓存处理', async () => {
  const h = await createHarness();
  const response = await handleAdminExportBackup(exportRequest({ masterPasswordHash: CLIENT_HASH }), h.env, h.admin);

  assert.equal(response.status, 200, `导出应成功，实际 ${response.status}`);
  assert.equal(response.headers.get('Content-Type'), 'application/zip');
  assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff', '避免浏览器把归档当成可执行内容');
  assert.equal(response.headers.get('Cache-Control'), 'no-store', '整库导出不得被缓存');
  assert.match(String(response.headers.get('Content-Disposition')), /attachment;.*\.zip/);

  // 内容确实是可解析的归档
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.ok(bytes.byteLength > 0);
  const parsed = parseBackupArchive(bytes);
  assert.ok(parsed.payload.db, '归档里应含数据库快照');

  // 导出应留下审计事件（管理员操作必须可追溯）
  const audit = h.connection
    .prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action = 'admin.backup.export'")
    .get() as { count: number };
  assert.equal(audit.count, 1, '本地导出应留下审计事件');

  h.handle.close();
});

// ---------------------------------------------------------------- ② 附件内联（§3.1.1 的端到端守卫）

/** 造一个带附件（元数据 + R2 内容）的条目，返回 cipherId / attachmentId 与内容 */
async function seedCipherWithAttachment(
  h: Harness,
  content = 'attachment-bytes-in-archive'
): Promise<{ cipherId: string; attachmentId: string; content: string }> {
  const cipherResponse = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: enc('cipher'), login: { username: enc('u') } }),
    }),
    h.env,
    ADMIN_ID
  );
  const cipherId = String(((await cipherResponse.json()) as { id: string }).id);

  const size = new TextEncoder().encode(content).length;
  const metaResponse = await handleCreateAttachment(
    new Request(`https://vault.example.test/api/ciphers/${cipherId}/attachment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileName: enc('file'), key: enc('file-key'), fileSize: size }),
    }),
    h.env,
    ADMIN_ID,
    cipherId
  );
  const meta = (await metaResponse.json()) as { attachmentId: string; url: string };
  const uploadPath = new URL(meta.url);

  const form = new FormData();
  form.set('data', new File([content], 'file.bin', { type: 'application/octet-stream' }));
  await handleUploadAttachment(
    new Request(`https://vault.example.test${uploadPath.pathname}${uploadPath.search}`, { method: 'POST', body: form }),
    h.env,
    ADMIN_ID,
    cipherId,
    meta.attachmentId
  );

  return { cipherId, attachmentId: meta.attachmentId, content };
}

test('本地导出（含附件）：zip 里必须**真的有附件字节**，而不是只有一份声称包含附件的清单', async () => {
  const h = await createHarness();
  const seeded = await seedCipherWithAttachment(h);
  assert.equal(h.bucket.size(), 1, '前置条件：附件内容已写入 R2');

  const response = await handleAdminExportBackup(
    exportRequest({ masterPasswordHash: CLIENT_HASH, includeAttachments: true }),
    h.env,
    h.admin
  );
  assert.equal(response.status, 200);

  const parsed = parseBackupArchive(new Uint8Array(await response.arrayBuffer()));
  assert.equal(parsed.payload.manifest.includes.attachments, true, '清单应声明包含附件');

  // 关键断言：归档文件里要能按附件 id 找到那个 blob，且内容与原文件一致。
  // §3.1.1 的缺陷正是"清单说有、字节没有"，所以只断言清单是不够的。
  const blobEntries = Object.entries(parsed.files).filter(([name]) => name.includes(seeded.attachmentId));
  assert.equal(blobEntries.length, 1, `归档里应恰有一个附件条目，实际：${JSON.stringify(Object.keys(parsed.files))}`);
  assert.equal(
    new TextDecoder().decode(blobEntries[0][1]),
    seeded.content,
    '归档里的附件字节应与上传内容一致'
  );

  h.handle.close();
});

test('本地导出（不含附件）：默认可正常工作，且不要求 R2 里有 blob', async () => {
  const h = await createHarness();
  // 只写元数据、不写 R2 —— 模拟"附件内容已丢失"的历史状态
  const cipherResponse = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: enc('cipher') }),
    }),
    h.env,
    ADMIN_ID
  );
  const cipherId = String(((await cipherResponse.json()) as { id: string }).id);
  await handleCreateAttachment(
    new Request(`https://vault.example.test/api/ciphers/${cipherId}/attachment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileName: enc('file'), key: enc('file-key'), fileSize: 10 }),
    }),
    h.env,
    ADMIN_ID,
    cipherId
  );

  const response = await handleAdminExportBackup(exportRequest({ masterPasswordHash: CLIENT_HASH }), h.env, h.admin);
  assert.equal(response.status, 200, '不勾选附件时不应因为缺 blob 而失败');

  h.handle.close();
});

test('本地导出（含附件）但 blob 缺失时返回 409，且提示可操作', async () => {
  const h = await createHarness();
  const cipherResponse = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: enc('cipher') }),
    }),
    h.env,
    ADMIN_ID
  );
  const cipherId = String(((await cipherResponse.json()) as { id: string }).id);
  await handleCreateAttachment(
    new Request(`https://vault.example.test/api/ciphers/${cipherId}/attachment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileName: enc('file'), key: enc('file-key'), fileSize: 10 }),
    }),
    h.env,
    ADMIN_ID,
    cipherId
  );
  assert.equal(h.bucket.size(), 0, '前置条件：R2 里确实没有对象');

  const response = await handleAdminExportBackup(
    exportRequest({ masterPasswordHash: CLIENT_HASH, includeAttachments: true }),
    h.env,
    h.admin
  );

  assert.equal(response.status, 409, `附件内容缺失应是 409（可操作）而不是 500（服务端故障），实际 ${response.status}`);
  const body = (await response.json()) as { error?: string };
  assert.match(String(body.error ?? ''), /blob missing/i, '错误信息应指出是哪个 blob 缺失');

  h.handle.close();
});
