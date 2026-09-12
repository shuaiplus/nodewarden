// webapp 纯逻辑测试：站点 URL 解析与图标地址（§3.5 方案 A）
//
// 为什么先测这几个：它们是"点了之后算得对不对"里最基础的一层 ——
// 从条目里挑出要显示的网站、从任意形状的用户输入里解析出主机名。
// 用户输入的形状极其随意（带不带 scheme、带不带端口、粘了路径或查询串、
// 全角、前后空白），这里的容错能力直接决定"网站图标能不能显示出来"。
//
// 运行方式：npm run test:webapp-lib
import assert from 'node:assert/strict';
import test from 'node:test';

import { firstCipherUri, hostFromUri, websiteIconUrl } from '../../webapp/src/lib/website-utils';
import type { Cipher } from '../../webapp/src/lib/types';

// ---------------------------------------------------------------- hostFromUri

test('hostFromUri：完整 URL 取其主机名', () => {
  const cases: Array<[string, string, string]> = [
    ['https://example.com', 'example.com', '标准 https'],
    ['http://example.com', 'example.com', 'http 同样支持'],
    ['https://example.com:8443/login', 'example.com', '端口与路径都不进主机名'],
    ['https://sub.example.com/a/b?q=1#f', 'sub.example.com', '子域名保留，查询串与片段丢弃'],
    ['HTTPS://EXAMPLE.COM/PATH', 'example.com', 'scheme 与主机名大小写不敏感（主机名归一为小写）'],
    ['https://[::1]:8080/x', '[::1]', 'IPv6 字面量保留方括号'],
    ['https://192.168.1.1/admin', '192.168.1.1', 'IPv4'],
    ['https://xn--fiq228c.example/', 'xn--fiq228c.example', 'punycode 域名原样保留'],
  ];

  for (const [input, expected, why] of cases) {
    assert.equal(hostFromUri(input), expected, `hostFromUri(${JSON.stringify(input)}) —— ${why}`);
  }
});

test('hostFromUri：没有 scheme 时按 https 补全（用户常直接粘域名）', () => {
  assert.equal(hostFromUri('example.com'), 'example.com');
  assert.equal(hostFromUri('example.com/login?x=1'), 'example.com');
  assert.equal(hostFromUri('sub.example.com:8443'), 'sub.example.com');
});

test('hostFromUri：空与无法解析的输入返回空串，而不是抛错或返回垃圾', () => {
  for (const input of ['', '   ', '\t\n', 'http://', 'https://', 'not a url', '://x', 'http://[bad']) {
    assert.equal(hostFromUri(input), '', `hostFromUri(${JSON.stringify(input)}) 应为空串`);
  }
});

test('hostFromUri：前后空白会被裁掉（用户从地址栏复制常带空白）', () => {
  // 这条曾经真的坏过：scheme 判定用的是**未裁剪**的字符串，于是带空白的
  // `https://...` 会被再补一个 scheme，`new URL` 解析失败 → 返回空串（图标永远不显示）；
  // 而 `\thttps://a.com\n` 更糟 —— 解析器把 `https` 当主机名 → 返回垃圾值 'https'。
  assert.equal(hostFromUri('  https://example.com/x  '), 'example.com');
  assert.equal(hostFromUri('  example.com  '), 'example.com');
  assert.equal(hostFromUri('\thttps://a.com\n'), 'a.com', '制表符/换行同样要被裁掉，不能产出 `https` 这种垃圾主机名');
  assert.equal(hostFromUri('\n\t  sub.example.com:8443/path  \n'), 'sub.example.com');
});

// ---------------------------------------------------------------- firstCipherUri

/** 造一个只带 uris 的最小 Cipher */
function cipherWithUris(uris: Array<{ uri?: string; decUri?: string }> | undefined): Cipher {
  return { login: uris === undefined ? undefined : { uris } } as unknown as Cipher;
}

test('firstCipherUri：优先返回解密后的 URI，其次返回密文 URI', () => {
  assert.equal(firstCipherUri(cipherWithUris([{ uri: 'enc-1', decUri: 'https://decrypted.example' }])), 'https://decrypted.example');
  assert.equal(firstCipherUri(cipherWithUris([{ uri: 'https://plain.example' }])), 'https://plain.example');
});

test('firstCipherUri：跳过空白项，返回第一个真正有内容的', () => {
  assert.equal(
    firstCipherUri(cipherWithUris([{ decUri: '   ' }, { uri: '' }, {uri: 'https://third.example'}])),
    'https://third.example',
    '前面几个空项应被跳过'
  );
});

test('firstCipherUri：没有可用 URI 时返回空串（而不是 undefined）', () => {
  assert.equal(firstCipherUri(cipherWithUris([])), '');
  assert.equal(firstCipherUri(cipherWithUris(undefined)), '', 'login 缺失时不应抛错');
  assert.equal(firstCipherUri(cipherWithUris([{ uri: '  ' }, { decUri: '' }])), '');
});

test('firstCipherUri：返回值已去掉前后空白', () => {
  assert.equal(firstCipherUri(cipherWithUris([{ uri: '  https://example.com  ' }])), 'https://example.com');
});

// ---------------------------------------------------------------- websiteIconUrl

test('websiteIconUrl：主机名要 URL 编码，避免特殊字符破坏路径', () => {
  assert.equal(websiteIconUrl('example.com'), '/icons/example.com/icon.png?fallback=404');
  assert.equal(
    websiteIconUrl('[::1]'),
    '/icons/%5B%3A%3A1%5D/icon.png?fallback=404',
    'IPv6 的方括号与冒号必须编码'
  );
  assert.equal(
    websiteIconUrl('a/b?c=1'),
    '/icons/a%2Fb%3Fc%3D1/icon.png?fallback=404',
    '斜杠与问号必须编码，否则会改变路径结构'
  );
  assert.ok(websiteIconUrl('example.com').endsWith('?fallback=404'), '应带 fallback 参数供图标服务兜底');
});
