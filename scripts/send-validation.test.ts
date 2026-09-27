import assert from 'node:assert/strict';
import test from 'node:test';
import { authedFetch, createTestEnv, seedUser } from './support/env';

const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const DAY_MS = 86_400_000;

async function setup() {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const call = (method: string, path: string, body?: unknown, userId: string | undefined = owner.id) =>
    authedFetch(env, { method, path, body, userId });
  const deletionDate = new Date(Date.now() + DAY_MS).toISOString();
  const textSend = { type: 0, name: ENCRYPTED, key: ENCRYPTED, deletionDate, text: { text: ENCRYPTED, hidden: false } };
  const fileSend = { type: 1, name: ENCRYPTED, key: ENCRYPTED, deletionDate, file: { fileName: ENCRYPTED }, fileLength: 4 };
  return { call, textSend, fileSend };
}

async function rejects(response: Promise<Response>, status: number, message: string): Promise<void> {
  const result = await response;
  assert.equal(result.status, status, message);
  assert.equal((await result.json() as { message: string }).message, message);
}

test('Send creation rejects each invalid field with its Bitwarden message', async () => {
  const { call, textSend, fileSend } = await setup();
  await rejects(call('POST', '/api/sends', { ...textSend, type: 2 }), 400, 'Invalid Send type');
  await rejects(call('POST', '/api/sends', { ...textSend, type: 1 }), 400, 'File sends should use /api/sends/file/v2');
  await rejects(call('POST', '/api/sends', { ...textSend, key: ' ' }), 400, 'Key is required');
  await rejects(call('POST', '/api/sends', { ...textSend, deletionDate: 'soon' }), 400, 'Invalid deletionDate');
  await rejects(
    call('POST', '/api/sends', { ...textSend, deletionDate: new Date(Date.now() + 60 * DAY_MS).toISOString() }),
    400,
    'You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.'
  );
  await rejects(call('POST', '/api/sends', { ...textSend, text: null }), 400, 'Send data not provided');
  await rejects(call('POST', '/api/sends', { ...textSend, maxAccessCount: -1 }), 400, 'Invalid maxAccessCount');
  await rejects(call('POST', '/api/sends', { ...textSend, expirationDate: 'later' }), 400, 'Invalid expirationDate');
  await rejects(call('POST', '/api/sends', { ...textSend, authType: 7 }), 400, 'Invalid authType');
  await rejects(call('POST', '/api/sends', { ...textSend, emails: 5 }), 400, 'Invalid emails');
  await rejects(call('POST', '/api/sends', { ...textSend, authType: 0 }), 501, 'Send email verification is not supported by this server.');
  await rejects(call('POST', '/api/sends', { ...textSend, emails: ['a@example.test'] }), 501, 'Send email verification is not supported by this server.');
  await rejects(call('POST', '/api/sends', { ...textSend, authType: 1 }), 400, 'Password is required for password auth');
  await rejects(call('POST', '/api/sends/file/v2', { ...fileSend, type: 0 }), 400, 'Send content is not a file');
  await rejects(call('POST', '/api/sends/file/v2', { ...fileSend, fileLength: 'big' }), 400, 'Invalid send length');
  await rejects(call('POST', '/api/sends/file/v2', { ...fileSend, fileLength: -1 }), 400, "Send size can't be negative");
  await rejects(call('POST', '/api/sends/delete', {}), 400, 'ids array is required');

  const blankName = await call('POST', '/api/sends', { ...textSend, name: ' ' });
  assert.deepEqual((await blankName.json() as { validationErrors: unknown }).validationErrors, { name: ['Name is required'] });
});

test('Send content round-trips client fields and numeric strings while edits keep absent fields', async () => {
  const { call, textSend, fileSend } = await setup();
  const created = await call('POST', '/api/sends', {
    ...textSend, maxAccessCount: '3', text: { text: ENCRYPTED, hidden: true, futureField: 1, response: 'echo' },
  });
  assert.equal(created.status, 200);
  const send = await created.json() as { id: string; maxAccessCount: number; text: Record<string, unknown>; revisionDate: string };
  assert.equal(send.maxAccessCount, 3);
  assert.deepEqual(send.text, { text: ENCRYPTED, hidden: true, futureField: 1 });

  await rejects(call('PUT', `/api/sends/${send.id}`, { type: 1 }), 400, "Sends can't change type");
  await rejects(call('PUT', `/api/sends/${send.id}`, { disabled: 'yes' }), 400, 'Invalid disabled');
  await rejects(call('PUT', `/api/sends/${send.id}`, { hideEmail: 3 }), 400, 'Invalid hideEmail');
  await rejects(call('PUT', `/api/sends/${send.id}`, { text: null }), 400, 'Send data not provided');
  const edited = await call('PUT', `/api/sends/${send.id}`, { disabled: true, expirationDate: '', maxAccessCount: null });
  assert.equal(edited.status, 200);
  const editedSend = await edited.json() as Record<string, unknown>;
  assert.deepEqual({ ...editedSend, revisionDate: send.revisionDate }, { ...send, disabled: true, expirationDate: null, maxAccessCount: null });

  const file = await call('POST', '/api/sends/file/v2', fileSend);
  const { sendResponse } = await file.json() as { sendResponse: { id: string; file: { size: string } } };
  assert.equal(sendResponse.file.size, '4');
  assert.equal((await call('PUT', `/api/sends/${sendResponse.id}`, { ...fileSend, text: null, file: null })).status, 200);
});

test('a password Send answers a missing or wrong password before revealing content', async () => {
  const { call, textSend } = await setup();
  const created = await call('POST', '/api/sends', { ...textSend, password: 'correct horse battery' });
  const { accessId } = await created.json() as { accessId: string };
  await rejects(call('POST', `/api/sends/access/${accessId}`, { password: 5 }, undefined), 401, 'Password not provided');
  await rejects(call('POST', `/api/sends/access/${accessId}`, { password: 'wrong' }, undefined), 400, 'Invalid password');
  assert.equal((await call('POST', `/api/sends/access/${accessId}`, { password: 'correct horse battery' }, undefined)).status, 200);
});
