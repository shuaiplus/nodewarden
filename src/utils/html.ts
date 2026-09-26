export type SafeHtml = { readonly safeHtml: string };
export type SafeUrl = string & { readonly __safeUrl: unique symbol };

export function html(parts: TemplateStringsArray, ...values: Array<string | number | SafeHtml | SafeHtml[]>): SafeHtml {
  const escape = (value: string) => value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
  return { safeHtml: parts.reduce((out, part, i) => {
    const value = values[i];
    return out + part + (value === undefined ? '' : Array.isArray(value) ? value.map((item) => item.safeHtml).join('') : typeof value === 'object' ? value.safeHtml : escape(String(value)));
  }, '') };
}

export function toSafeUrl(url: URL): SafeUrl {
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname))) {
    throw new Error('Unsafe link protocol');
  }
  return url.href as SafeUrl;
}
