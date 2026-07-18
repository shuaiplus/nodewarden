import { normalizeBackupEndpointUrl } from '../src/services/backup-config.ts';
import fs from 'node:fs';

const scratch = process.env.SCRATCH || '.';
const cases = [
  'http://127.0.0.1',
  'http://169.254.169.254',
  'http://[::1]',
  'http://[0:0:0:0:0:0:0:1]',
  'http://[::2]',
  'http://[::]',
  'http://[fe80::1]',
  'http://[fc00::1]',
  'https://example.com',
];

const out = [];
for (const url of cases) {
  try {
    const normalized = normalizeBackupEndpointUrl(url, 'WebDAV server URL');
    out.push({ url, allowed: true, normalized });
  } catch (e) {
    out.push({ url, allowed: false, error: e instanceof Error ? e.message : String(e) });
  }
}

const path = `${scratch}/poc-normalizeBackupEndpointUrl.json`;
fs.writeFileSync(path, JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));

// Security expectation: IPv6 loopback must NOT be allowed.
const loopback = out.find((row) => row.url === 'http://[::1]');
if (loopback?.allowed) {
  console.error('FINDING_CONFIRMED: normalizeBackupEndpointUrl accepts http://[::1]');
  process.exitCode = 2;
} else {
  console.log('IPv6 loopback rejected as expected');
}
