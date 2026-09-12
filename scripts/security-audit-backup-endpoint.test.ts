// 备份目标地址主机策略回归测试
//
// 契约：备份目标（WebDAV / S3 endpoint）由管理员在设置页填写，服务端会以
// Worker 身份向其发起出站请求。因此必须拒绝一切指向内网、回环、云元数据与
// 保留地址的目标，避免形成 SSRF 通道。
//
// 本测试用宽覆盖面（约 70 条）锁定 `normalizeBackupEndpointUrl` 的行为，
// 覆盖常见的地址编码绕过手法（十进制/八进制/十六进制 IPv4、IPv6 压缩与
// IPv4-mapped、尾部点号、DNS rebinding 域名等）。
//
// 注意：本文件不得写入任何文件（早期版本会往仓库根目录写 PoC JSON）。
import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeBackupEndpointUrl } from '../src/services/backup-config';

const LABEL = 'WebDAV server URL';

function normalized(url: string): string {
  return normalizeBackupEndpointUrl(url, LABEL);
}

// ---------------------------------------------------------------- 必须拒绝

// IPv4 回环 / 私有 / 保留段。注意其中多条依赖 WHATWG URL 的归一化能力
// （十进制 2130706433、八进制 0177.0.0.1、十六进制 0x7f000001、短形式 127.1
// 都会被规范化为 127.0.0.1），这也是选择 new URL 解析的关键原因。
const BLOCKED_IPV4 = [
  'http://127.0.0.1',
  'http://127.1',
  'http://127.0.0.1:8080',
  'http://2130706433',
  'http://0177.0.0.1',
  'http://0x7f000001',
  'http://0',
  'http://0.0.0.0',
  'http://10.0.0.1',
  'http://172.16.0.1',
  'http://172.31.255.254',
  'http://192.168.1.1',
  'http://100.64.0.1',
  'http://169.254.169.254',
  'http://198.18.0.1',
  'http://198.51.100.1',
  'http://203.0.113.1',
  'http://192.0.2.1',
  'http://224.0.0.1',
  'http://240.0.0.1',
  'http://255.255.255.255',
];

// IPv6 回环 / 私有 / 保留段，含 IPv4-mapped 与 IPv4-compatible 两种嵌入形式。
// [64:ff9b::/96] 是 NAT64 well-known prefix，其后的 32 位是 IPv4 地址。
const BLOCKED_IPV6 = [
  'http://[::1]',
  'http://[0:0:0:0:0:0:0:1]',
  'http://[::]',
  'http://[::2]',
  'http://[fe80::1]',
  'http://[fc00::1]',
  'http://[fd00::1]',
  'http://[ff02::1]',
  'http://[2001:db8::1]',
  'http://[::ffff:127.0.0.1]',
  'http://[::ffff:7f00:1]',
  'http://[0:0:0:0:0:ffff:7f00:1]',
  'http://[::ffff:169.254.169.254]',
  'http://[::192.168.1.1]',
  'http://[::c0a8:101]',
  'http://[64:ff9b::7f00:1]',
  'http://[64:ff9b::a9fe:a9fe]',
];

// 特殊用途域名：本地名称、云元数据服务，以及已知的 DNS rebinding 服务
// （这些服务会把任意子域名解析到调用方指定的 IP，从而绕过 IP 字面量检查）。
const BLOCKED_HOSTNAMES = [
  'http://localhost',
  'http://LOCALHOST',
  'http://localhost:8080',
  'http://localhost.',
  'http://localhost.localdomain',
  'http://foo.localhost',
  'http://foo.local',
  'http://foo.internal',
  'http://foo.lan',
  'http://foo.home.arpa',
  'http://metadata.google.internal',
  'http://nip.io',
  'http://127.0.0.1.nip.io',
  'http://foo.sslip.io',
  'http://localtest.me',
  'http://lvh.me',
  'http://vcap.me',
  'http://xip.io',
];

for (const [name, urls] of [
  ['IPv4 回环 / 私有 / 保留段', BLOCKED_IPV4],
  ['IPv6 回环 / 私有 / 保留段', BLOCKED_IPV6],
  ['本地名称与 rebinding 域名', BLOCKED_HOSTNAMES],
] as const) {
  test(`备份目标拒绝 ${name}`, () => {
    for (const url of urls) {
      assert.throws(
        () => normalized(url),
        new Error(`${LABEL} host is not allowed`),
        `应当拒绝：${url}`
      );
    }
  });
}

test('备份目标拒绝带凭据、查询串或片段的地址', () => {
  assert.throws(
    () => normalized('http://user:pass@example.com'),
    new Error(`${LABEL} must not include credentials`)
  );
  assert.throws(
    () => normalized('https://example.com?target=1'),
    new Error(`${LABEL} must not include query or fragment`)
  );
  assert.throws(
    () => normalized('https://example.com#frag'),
    new Error(`${LABEL} must not include query or fragment`)
  );
});

test('备份目标拒绝非 http(s) 协议与非法 URL', () => {
  for (const url of ['ftp://example.com', 'file:///etc/passwd', 'ws://example.com', 'not a url', '']) {
    assert.throws(() => normalized(url), Error, `应当拒绝：${url}`);
  }
  // `new URL('https://')` 本身即失败，因此报错为「不是合法 URL」而非「缺少主机」。
  assert.throws(
    () => normalized('https://'),
    new Error(`${LABEL} must be a valid URL`)
  );
});

// ------------------------------------------------------------------ 应当放行

// 反向保护：避免为了堵 SSRF 而把正常的公网备份目标也拒掉。
test('备份目标放行公网 http(s) 地址', () => {
  const allowed = [
    'https://example.com',
    'https://example.com:8443',
    'https://dav.example.com/remote.php/dav/files/alice',
    'https://s3.us-west-2.amazonaws.com',
    'https://storage.example.co.jp',
    'https://8.8.8.8',
    'https://1.1.1.1',
    'https://[2606:4700:4700::1111]',
    'https://[2001:4860:4860::8888]',
  ];
  for (const url of allowed) {
    assert.doesNotThrow(() => normalized(url), `应当放行：${url}`);
  }
});

test('备份目标返回归一化后的地址（保留协议与端口，去掉尾部斜杠）', () => {
  assert.equal(normalized('https://example.com/'), 'https://example.com');
  assert.equal(normalized('https://example.com:8443/dav//'), 'https://example.com:8443/dav');
  assert.equal(normalized('http://example.com/dav'), 'http://example.com/dav');
});
