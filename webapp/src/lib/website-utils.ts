import type { Cipher } from './types';

export function firstCipherUri(cipher: Cipher): string {
  const uris = cipher.login?.uris || [];
  for (const uri of uris) {
    const raw = uri.decUri || uri.uri || '';
    if (raw.trim()) return raw.trim();
  }
  return '';
}

export function hostFromUri(uri: string): string {
  // 先裁剪：用户从地址栏复制出来的地址常带前后空白（甚至换行 / 制表符）。
  //
  // 原实现用**未裁剪**的字符串去判断是否已有 scheme，于是：
  //   · `'  https://example.com  '` —— 正则匹配失败 → 又补了一个 `https://` →
  //     `new URL` 解析失败 → 返回空字符串（网站图标永远显示不出来）
  //   · `'\thttps://a.com\n'` —— URL 解析器把 `https` 当成了主机名 → 返回垃圾值 `'https'`
  //     （于是去请求一个叫 https 的站点的图标）
  // 在函数入口裁剪一次，两条路径都消失。
  const trimmed = uri.trim();
  if (!trimmed) return '';
  try {
    const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    return new URL(normalized).hostname || '';
  } catch {
    return '';
  }
}

export function websiteIconUrl(host: string): string {
  return `/icons/${encodeURIComponent(host)}/icon.png?fallback=404`;
}
