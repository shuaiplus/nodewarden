export type SafeUrl = string & { readonly __safeUrl: unique symbol };

export function toSafeUrl(url: URL): SafeUrl {
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname))) {
    throw new Error('Unsafe link protocol');
  }
  return url.href as SafeUrl;
}
