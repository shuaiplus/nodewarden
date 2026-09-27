import assert from 'node:assert/strict';
import { test } from 'node:test';

import { contentDispositionAttachment } from './content-type';

test('download file names cannot break out of the Content-Disposition value and fall back when blank', () => {
  assert.equal(contentDispositionAttachment('2.iv|data|mac', 'attachment'), 'attachment; filename="2.iv|data|mac"');
  assert.equal(contentDispositionAttachment(' a"b\r\nc ', 'attachment'), 'attachment; filename="a_b__c"');
  assert.equal(contentDispositionAttachment('   ', 'send-file'), 'attachment; filename="send-file"');
  assert.equal(contentDispositionAttachment('', 'send-file'), 'attachment; filename="send-file"');
  assert.equal(contentDispositionAttachment(null, 'attachment'), 'attachment; filename="attachment"');
  assert.equal(contentDispositionAttachment(undefined, 'send-file'), 'attachment; filename="send-file"');
});
