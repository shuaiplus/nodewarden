// Resolve hook backing scripts/test-bootstrap.mjs
const stubUrl = new URL('./test-stubs/cloudflare-workers.mjs', import.meta.url).href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'cloudflare:workers') {
    return { url: stubUrl, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}
