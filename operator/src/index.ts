import * as k8s from '@kubernetes/client-node';

const API_URL = process.env.NW_API_URL || process.env.BW_API_URL || 'http://localhost:8787';
const IDENTITY_URL = process.env.NW_IDENTITY_URL || process.env.BW_IDENTITY_API_URL || API_URL;
const REFRESH_SECONDS = Math.max(180, Number(process.env.NW_REFRESH_INTERVAL || process.env.BW_SECRETS_MANAGER_REFRESH_INTERVAL || 180));
const GROUP = 'k8s.bitwarden.com';
const VERSION = 'v1';
const PLURAL = 'bitwardensecrets';

interface BitwardenSecret {
  metadata: { name: string; namespace?: string };
  spec: {
    organizationId: string;
    secretName: string;
    authToken: { secretName: string; secretKey: string };
    map?: Array<{ bwSecretId: string; secretKeyName: string }>;
    onlyMappedSecrets?: boolean;
    useSecretNames?: boolean;
    projectId?: string;
  };
  status?: { lastSuccessfulSyncTime?: string };
}

async function syncSecrets(clientId: string, clientSecret: string, orgId: string, lastSyncedDate?: string) {
  const url = new URL(`${API_URL.replace(/\/+$/, '')}/organizations/${orgId}/secrets/sync`);
  if (lastSyncedDate) url.searchParams.set('lastSyncedDate', lastSyncedDate);
  const response = await fetch(url, { headers: { Authorization: `Bearer ${clientId}:${clientSecret}` } });
  if (!response.ok) throw new Error(`Secrets sync failed: ${response.status}`);
  return response.json() as Promise<{
    hasChanges: boolean;
    wrappedOrgKey?: string | null;
    secrets: Array<{ id: string; key: string; value: string; note: string | null; projectIds: string[] }>;
  }>;
}

function decodeMaybe(value: string): string {
  try {
    return Buffer.from(value, 'base64').toString('utf8');
  } catch {
    return value;
  }
}

async function reconcile(api: k8s.CustomObjectsApi, core: k8s.CoreV1Api, item: BitwardenSecret): Promise<void> {
  const namespace = item.metadata.namespace || 'default';
  const authSecret = await core.readNamespacedSecret({ name: item.spec.authToken.secretName, namespace });
  const encoded = authSecret.data?.[item.spec.authToken.secretKey];
  if (!encoded) throw new Error('Auth token key missing');
  const raw = Buffer.from(encoded, 'base64').toString('utf8').trim();
  const [clientId, clientSecret] = raw.includes('\n') ? raw.split('\n') : raw.split(':');
  const sync = await syncSecrets(clientId.trim(), (clientSecret || '').trim(), item.spec.organizationId, item.status?.lastSuccessfulSyncTime);
  if (!sync.hasChanges && item.status?.lastSuccessfulSyncTime) return;

  const mapping = new Map((item.spec.map || []).map((entry) => [entry.bwSecretId, entry.secretKeyName]));
  const data: Record<string, string> = {};
  for (const secret of sync.secrets) {
    if (item.spec.projectId && !secret.projectIds.includes(item.spec.projectId)) continue;
    if (item.spec.onlyMappedSecrets !== false && mapping.size && !mapping.has(secret.id)) continue;
    const key = item.spec.useSecretNames ? decodeMaybe(secret.key).replace(/[^A-Za-z0-9_]/g, '_') : (mapping.get(secret.id) || secret.id);
    data[key] = Buffer.from(secret.value).toString('base64');
  }

  const body = {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: item.spec.secretName,
      namespace,
      annotations: {
        'k8s.bitwarden.com/sync-time': new Date().toISOString(),
      },
    },
    data,
  };
  try {
    await core.replaceNamespacedSecret({ name: item.spec.secretName, namespace, body });
  } catch (error) {
    const status = (error as { statusCode?: number }).statusCode;
    if (status === 404) {
      await core.createNamespacedSecret({ namespace, body });
    } else {
      throw error;
    }
  }

  await api.patchNamespacedCustomObjectStatus({
    group: GROUP,
    version: VERSION,
    namespace,
    plural: PLURAL,
    name: item.metadata.name,
    body: [{ op: 'add', path: '/status/lastSuccessfulSyncTime', value: new Date().toISOString() }],
  });
}

async function main(): Promise<void> {
  const kc = new k8s.KubeConfig();
  try {
    kc.loadFromCluster();
  } catch {
    kc.loadFromDefault();
  }
  const api = kc.makeApiClient(k8s.CustomObjectsApi);
  const core = kc.makeApiClient(k8s.CoreV1Api);
  console.log(`NodeWarden operator watching ${GROUP}/${VERSION} ${PLURAL} every ${REFRESH_SECONDS}s`);

  async function tick(): Promise<void> {
    const list = await api.listClusterCustomObject({ group: GROUP, version: VERSION, plural: PLURAL }) as { items?: BitwardenSecret[] };
    for (const item of list.items || []) {
      try {
        await reconcile(api, core, item);
      } catch (error) {
        console.error(`Reconcile ${item.metadata.namespace}/${item.metadata.name} failed:`, error);
      }
    }
  }

  await tick();
  setInterval(() => {
    void tick();
  }, REFRESH_SECONDS * 1000);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
