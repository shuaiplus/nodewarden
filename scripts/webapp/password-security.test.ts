// webapp 纯逻辑测试：密码哈希与弱密码判定（§3.5 方案 A）
//
// 为什么值得测：
//   · `sha1Password` 的输出会直接拼进 HaveIBeenPwned 的 k-anonymity 查询 URL。
//     服务端那一侧（`checkPasswordHashLeaked`）要求 **40 位大写十六进制**，
//     一旦这里的输出变成小写，查询会被判为「哈希非法」，而调用方
//     `checkPasswordLeaked` 会把异常吞掉、返回 `{ count: null, available: false }` ——
//     也就是**泄露检测静默失效**。所以这里用已知向量 + 大小写共同把住。
//   · `isWeakPassword` 是纯判定逻辑，规则边界多（公共密码表 / 长度 / 重复字符 /
//     键盘序列 / 包含用户名 / 字符类别数），值得逐条钉住。
//
// 运行方式：npm run test:webapp-lib
import assert from 'node:assert/strict';
import test from 'node:test';

import { isWeakPassword, sha1Password } from '../../webapp/src/lib/password-security';

// ---------------------------------------------------------------- SHA-1

test('sha1Password：与已知 SHA-1 向量一致', async () => {
  // 这两条是 SHA-1 的公开测试向量，可独立核对
  assert.equal(await sha1Password('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  assert.equal(await sha1Password(''), 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709');
});

test('sha1Password：输出必须是 40 位**大写**十六进制', async () => {
  const hash = await sha1Password('any-password');

  assert.match(hash, /^[A-F0-9]{40}$/, `必须匹配 HaveIBeenPwned 查询所要求的形式，实际：${hash}`);
  assert.equal(hash, hash.toUpperCase(), '不得包含小写字母 —— 小写会让泄露检测静默失效（见文件头说明）');
  assert.equal(hash.length, 40);
});

test('sha1Password：按 UTF-8 编码（非 ASCII 与中文也要稳定）', async () => {
  const first = await sha1Password('密码-with-émoji-🔐');
  const second = await sha1Password('密码-with-émoji-🔐');
  assert.equal(first, second, '同样输入必须得到确定结果');

  assert.notEqual(await sha1Password('密码'), await sha1Password('', ), '不同输入应得到不同哈希');
  assert.match(first, /^[A-F0-9]{40}$/, '非 ASCII 输入同样产出合法形式');
});

test('sha1Password：大小写敏感（Password 与 password 不是同一个）', async () => {
  assert.notEqual(await sha1Password('password'), await sha1Password('Password'));
});

// ---------------------------------------------------------------- 弱密码判定

test('isWeakPassword：长度不足 10 一律判弱（与是否在公共表里无关）', () => {
  assert.equal(isWeakPassword(''), true, '空串');
  assert.equal(isWeakPassword('abc'), true);
  assert.equal(isWeakPassword('Ab3!xYz12'), true, '只有 9 位 —— 再复杂也太短');
  assert.equal(isWeakPassword('Ab3!xYz123'), false, '刚好 10 位且类别齐全 → 不再因长度判弱');
});

test('isWeakPassword：重复字符与键盘/数字序列一律判弱', () => {
  assert.equal(isWeakPassword('aaaaaaaaaaaaaa'), true, '全同字符');
  assert.equal(isWeakPassword('11111111111111'), true, '全同数字');
  assert.equal(isWeakPassword('0123456789ab'), true, '含连续数字序列');
  assert.equal(isWeakPassword('qwertyuiop12'), true, '含键盘序列');
  assert.equal(isWeakPassword('abcdefghijklm'), true, '含字母表序列');
});

test('isWeakPassword：包含用户名（@ 前的部分，≥3 字符）时判弱', () => {
  assert.equal(isWeakPassword('johndoe-secret-99', 'johndoe@example.com'), true);
  assert.equal(
    isWeakPassword('JOHNDOE-secret-99', 'johndoe@example.com'),
    true,
    '应忽略大小写'
  );
  assert.equal(
    isWeakPassword('zz-secret-9911', 'johndoe@example.com'),
    false,
    '不含用户名，且够长够杂 → 不判弱'
  );
});

test('isWeakPassword：用户名过短（< 3 字符）时不参与判定，避免误杀', () => {
  // @ 前只有 1~2 个字符时不做包含判断，否则大量密码会被误判
  assert.equal(isWeakPassword('ab-secret-9911', 'ab@example.com'), false);
});

test('isWeakPassword：长度在 10~13 且字符类别不足 3 种时判弱', () => {
  assert.equal(isWeakPassword('onlylowercase'), true, '12 位但只有 1 种字符类别');
  assert.equal(isWeakPassword('lowercase123'), true, '12 位、2 种类别 → 不足 3 种');
  assert.equal(isWeakPassword('Lowercase123'), false, '12 位、3 种类别 → 通过');
});

test('isWeakPassword：长度达到 14 后不再要求多种字符类别', () => {
  assert.equal(
    isWeakPassword('onlylowercaseletters'),
    false,
    '22 位全小写：长度足够长，不再因"类别不足"判弱'
  );
});

test('isWeakPassword：长口令不判弱（用户选择 passphrase 时不应被拦）', () => {
  assert.equal(isWeakPassword('correct-horse-battery-staple-42'), false);
});
