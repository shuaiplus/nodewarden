import assert from 'node:assert/strict';
import { mock, test } from 'node:test';

import type { BackupDestinationRecord, S3BackupDestination } from './backup-config';
import { createRemoteBackupTransferSession } from './backup-uploader';

function s3Session(overrides: Partial<S3BackupDestination>) {
  const destination: S3BackupDestination = {
    endpoint: 'https://s3.example.com',
    bucket: 'backups',
    addressingStyle: 'path-style',
    region: 'eu-west-1',
    accessKeyId: 'AKIDEXAMPLE',
    secretAccessKey: 'secret',
    rootPath: 'nightly',
    ...overrides,
  };
  return createRemoteBackupTransferSession({ id: 'd1', type: 's3', destination } as BackupDestinationRecord);
}

test('S3 destinations send SigV4-signed requests to path-style and virtual-hosted URLs', async () => {
  const requests: Request[] = [];
  const responses = [
    new Response(null, { status: 200 }),
    new Response('<ListBucketResult><Contents><Key>nightly/vault.zip</Key><Size>7</Size></Contents></ListBucketResult>'),
    new Response(null, { status: 404 }),
  ];
  const fetchMock = mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    requests.push(new Request(input, init));
    return responses.shift() ?? new Response(null, { status: 500 });
  });
  try {
    await s3Session({ addressingStyle: 'virtual-hosted-style' }).uploadArchive(new Uint8Array([1, 2, 3]), 'vault 1.zip');
    const listing = await s3Session({}).list('');
    assert.equal(await s3Session({}).stat('missing.zip'), null);

    assert.deepEqual(listing.items.map((item) => [item.path, item.size]), [['vault.zip', 7]]);
    assert.deepEqual(requests.map((request) => `${request.method} ${request.url}`), [
      'PUT https://backups.s3.example.com/nightly/vault%201.zip',
      'GET https://s3.example.com/backups?list-type=2&delimiter=%2F&prefix=nightly%2F',
      'HEAD https://s3.example.com/backups/nightly/missing.zip',
    ]);
    assert.equal(requests[0].headers.get('Content-Type'), 'application/zip');
    // sha256 of the three-byte archive, signed so the body cannot be swapped in transit.
    assert.equal(requests[0].headers.get('X-Amz-Content-Sha256'), '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81');
    for (const request of requests) {
      assert.match(request.headers.get('Authorization') ?? '', /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/\d{8}\/eu-west-1\/s3\/aws4_request, SignedHeaders=\S*host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
      assert.match(request.headers.get('X-Amz-Date') ?? '', /^\d{8}T\d{6}Z$/);
    }
  } finally {
    fetchMock.mock.restore();
  }
});
