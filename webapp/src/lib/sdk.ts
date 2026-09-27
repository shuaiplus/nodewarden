import * as sdkBindings from '@bitwarden/sdk-internal/bitwarden_wasm_internal_bg.js';
import sdkWasmUrl from '@bitwarden/sdk-internal/bitwarden_wasm_internal_bg.wasm?url';

// wasm-bindgen links the module against its JS glue under this import namespace.
const SDK_WASM_IMPORT_MODULE = './bitwarden_wasm_internal_bg.js';

async function instantiateSdkWasm(): Promise<WebAssembly.Instance> {
  const imports = { [SDK_WASM_IMPORT_MODULE]: sdkBindings };
  try {
    return (await WebAssembly.instantiateStreaming(fetch(sdkWasmUrl), imports)).instance;
  } catch {
    // Streaming compilation rejects responses that are not served as application/wasm
    // (misconfigured proxies, some offline caches); compiling the downloaded bytes does not.
    const bytes = await (await fetch(sdkWasmUrl)).arrayBuffer();
    return (await WebAssembly.instantiate(bytes, imports)).instance;
  }
}

let sdkLoaded: Promise<void> | undefined;

// The package's browser entry needs the WASM instance before any PureCrypto call, and Vite has no
// WASM ESM integration, so each JS realm (page, decrypt worker) links it once here. Node resolves
// the package's self-initialising CommonJS build instead and never imports this module.
export function loadSdk(): Promise<void> {
  sdkLoaded ??= instantiateSdkWasm().then((instance) => sdkBindings.__wbg_set_wasm(instance.exports));
  return sdkLoaded;
}
