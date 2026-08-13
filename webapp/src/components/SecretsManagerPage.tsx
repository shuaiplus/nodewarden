import { useEffect, useState } from 'preact/hooks';
import { LockKeyhole } from 'lucide-preact';
import {
  createProject,
  createSecret,
  createServiceAccountToken,
  listProjects,
  listSecrets,
  type ProfileOrganization,
  type SmProject,
} from '@/lib/api/orgs';
import { unwrapOrgKey, encodeOrgKeyB64 } from '@/lib/org-crypto';
import { encryptBw } from '@/lib/crypto';
import type { SessionState } from '@/lib/types';
import { t } from '@/lib/i18n';

interface SecretsManagerPageProps {
  organizations: ProfileOrganization[];
  session: SessionState;
  authedFetch: import('@/lib/api/shared').AuthedFetch;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
}

export default function SecretsManagerPage(props: SecretsManagerPageProps) {
  const [orgId, setOrgId] = useState(props.organizations[0]?.id || '');
  const [projects, setProjects] = useState<SmProject[]>([]);
  const [secrets, setSecrets] = useState<Array<{ id: string; key: string }>>([]);
  const [projectName, setProjectName] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [tokenResult, setTokenResult] = useState('');

  const selected = props.organizations.find((org) => org.id === orgId) || props.organizations[0] || null;

  async function refresh(): Promise<void> {
    if (!selected) return;
    setProjects(await listProjects(props.authedFetch, selected.id));
    setSecrets(await listSecrets(props.authedFetch, selected.id));
  }

  useEffect(() => {
    refresh().catch((error) => props.onNotify('error', String(error.message || error)));
  }, [selected?.id]);

  async function encryptField(value: string): Promise<string> {
    if (!selected?.key) throw new Error('Organization key unavailable');
    const orgKey = await unwrapOrgKey(props.session, selected.key);
    return encryptBw(new TextEncoder().encode(value), orgKey.encKey, orgKey.macKey);
  }

  async function onCreateProject(event: Event): Promise<void> {
    event.preventDefault();
    if (!selected) return;
    await createProject(props.authedFetch, selected.id, projectName);
    setProjectName('');
    await refresh();
  }

  async function onCreateSecret(event: Event): Promise<void> {
    event.preventDefault();
    if (!selected) return;
    await createSecret(props.authedFetch, selected.id, {
      key: await encryptField(secretKey),
      value: await encryptField(secretValue),
      projectIds: projects[0] ? [projects[0].id] : [],
    });
    setSecretKey('');
    setSecretValue('');
    await refresh();
    props.onNotify('success', t('txt_sm_secret_created'));
  }

  async function onCreateToken(): Promise<void> {
    if (!selected?.key) return;
    const orgKey = await unwrapOrgKey(props.session, selected.key);
    const wrapped = encodeOrgKeyB64(orgKey.encKey, orgKey.macKey);
    const token = await createServiceAccountToken(props.authedFetch, selected.id, 'kubernetes', wrapped);
    setTokenResult(`${token.clientId}\n${token.clientSecret}`);
  }

  return (
    <section className="page-stack">
      <header className="page-header">
        <h1><LockKeyhole size={22} /> {t('nav_secrets_manager')}</h1>
        <p>{t('txt_sm_intro')}</p>
      </header>
      {props.organizations.length === 0 ? <p>{t('txt_sm_need_org')}</p> : (
        <>
          <label className="field">
            <span>{t('txt_org_selected')}</span>
            <select className="input" value={selected?.id || ''} onChange={(event) => setOrgId((event.currentTarget as HTMLSelectElement).value)}>
              {props.organizations.map((org) => <option value={org.id}>{org.name}</option>)}
            </select>
          </label>
          <form className="card form-grid" onSubmit={onCreateProject}>
            <h2>{t('txt_sm_projects')}</h2>
            <input className="input" value={projectName} onInput={(event) => setProjectName((event.currentTarget as HTMLInputElement).value)} required />
            <button className="btn" type="submit">{t('txt_sm_add_project')}</button>
            <ul className="plain-list">{projects.map((project) => <li>{project.name}</li>)}</ul>
          </form>
          <form className="card form-grid" onSubmit={onCreateSecret}>
            <h2>{t('txt_sm_secrets')}</h2>
            <input className="input" placeholder={t('txt_sm_secret_key')} value={secretKey} onInput={(event) => setSecretKey((event.currentTarget as HTMLInputElement).value)} required />
            <input className="input" placeholder={t('txt_sm_secret_value')} value={secretValue} onInput={(event) => setSecretValue((event.currentTarget as HTMLInputElement).value)} required />
            <button className="btn primary" type="submit">{t('txt_sm_add_secret')}</button>
            <ul className="plain-list">{secrets.map((secret) => <li>{secret.id}</li>)}</ul>
          </form>
          <section className="card">
            <h2>{t('txt_sm_machine_account')}</h2>
            <button className="btn" type="button" onClick={onCreateToken}>{t('txt_sm_create_token')}</button>
            {tokenResult && <pre className="code-block">{tokenResult}</pre>}
          </section>
        </>
      )}
    </section>
  );
}
