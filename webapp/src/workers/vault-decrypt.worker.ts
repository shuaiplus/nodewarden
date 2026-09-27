import { decryptSends, decryptVaultCore, type DecryptSendsArgs, type DecryptVaultCoreArgs } from '@/lib/vault-decrypt';
import { loadSdk } from '@/lib/sdk';

type WorkerRequest =
  | { id: number; kind: 'vault-core'; payload: DecryptVaultCoreArgs }
  | { id: number; kind: 'sends'; payload: DecryptSendsArgs };

// Workers are their own JS realm: link the SDK once, and let every request wait for it.
const sdkLoaded = loadSdk();

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  try {
    await sdkLoaded;
    if (request.kind === 'vault-core') {
      const result = await decryptVaultCore(request.payload);
      self.postMessage({ id: request.id, ok: true, result });
      return;
    }
    const result = await decryptSends(request.payload);
    self.postMessage({ id: request.id, ok: true, result });
  } catch (error) {
    self.postMessage({
      id: request.id,
      ok: false,
      error: error instanceof Error ? error.message : 'Decrypt failed',
    });
  }
};
