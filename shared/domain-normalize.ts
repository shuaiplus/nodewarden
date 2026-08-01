const MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
  'ac.cn',
  'com.cn',
  'edu.cn',
  'gov.cn',
  'net.cn',
  'org.cn',
  'ah.cn',
  'bj.cn',
  'cq.cn',
  'fj.cn',
  'gd.cn',
  'gs.cn',
  'gx.cn',
  'gz.cn',
  'ha.cn',
  'hb.cn',
  'he.cn',
  'hi.cn',
  'hk.cn',
  'hl.cn',
  'hn.cn',
  'jl.cn',
  'js.cn',
  'jx.cn',
  'ln.cn',
  'mo.cn',
  'nm.cn',
  'nx.cn',
  'qh.cn',
  'sc.cn',
  'sd.cn',
  'sh.cn',
  'sn.cn',
  'sx.cn',
  'tj.cn',
  'tw.cn',
  'xj.cn',
  'xz.cn',
  'yn.cn',
  'zj.cn',
  'co.uk',
  'org.uk',
  'net.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'gov.au',
  'co.nz',
  'org.nz',
  'net.nz',
  'com.br',
  'com.mx',
  'com.ar',
  'com.tr',
  'com.sg',
  'com.my',
  'com.hk',
  'com.tw',
  'co.jp',
  'ne.jp',
  'or.jp',
  'co.kr',
  'or.kr',
  'co.in',
  'firm.in',
  'net.in',
  'org.in',
  'co.id',
  'or.id',
  'web.id',
  'co.il',
  'org.il',
  'co.za',
  'com.sa',
  'com.ph',
  'com.vn',
  'com.pk',
  'com.bd',
  'com.ng',
  'github.io',
  'pages.dev',
  'workers.dev',
  'cloudflareaccess.com',
  'vercel.app',
  'netlify.app',
  'web.app',
  'firebaseapp.com',
  'herokuapp.com',
  'fly.dev',
  'railway.app',
  'render.com',
  'onrender.com',
]);

function extractHost(input: string): string {
  let raw = input.trim().toLowerCase();
  if (!raw) return '';
  raw = raw.replace(/\\/g, '/');

  try {
    const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
    const parsed = new URL(candidate);
    raw = parsed.hostname;
  } catch {
    raw = raw.split(/[/?#]/, 1)[0] || '';
    const atIndex = raw.lastIndexOf('@');
    if (atIndex >= 0) raw = raw.slice(atIndex + 1);
    if (raw.startsWith('[')) return '';
    const colonIndex = raw.lastIndexOf(':');
    if (colonIndex > -1 && raw.indexOf(':') === colonIndex) raw = raw.slice(0, colonIndex);
  }

  return raw
    .replace(/^\*+\./, '')
    .replace(/^\.+/, '')
    .replace(/\.+$/, '');
}

function isValidHost(host: string): boolean {
  if (!host || host.length > 253 || !host.includes('.')) return false;
  if (host.includes('..') || /[:/\s]/.test(host)) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false;
  return host.split('.').every((label) => (
    label.length > 0
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ));
}

export function normalizeEquivalentDomain(value: unknown): string {
  const host = extractHost(String(value || ''));
  if (!isValidHost(host)) return '';

  const labels = host.split('.');
  for (let index = 0; index < labels.length; index += 1) {
    const suffix = labels.slice(index).join('.');
    if (!MULTI_LABEL_PUBLIC_SUFFIXES.has(suffix)) continue;
    if (index === 0) return '';
    return labels.slice(index - 1).join('.');
  }

  return labels.length >= 2 ? labels.slice(-2).join('.') : '';
}

export function isValidEquivalentDomain(value: unknown): boolean {
  return !!normalizeEquivalentDomain(value);
}
