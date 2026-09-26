import { useEffect, useState } from 'preact/hooks';
import { LockKeyhole } from 'lucide-preact';
import {
  createProject,
  createSecret,
  listProjects,
  listSecrets,
  type ProfileOrganization,
  type SmProject,
} from '@/lib/api/orgs';
import { decryptWithOrgKey, encryptWithOrgKey, unwrapOrgKey } from '@/lib/org-crypto';
import type { SessionState } from '@/lib/types';
import { t } from '@/lib/i18n';

interface SecretsManagerPageProps {
  organizations: ProfileOrganization[];
  session: SessionState;
  privateKey?: string | null;
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

  const selected = props.organizations.find((org) => org.id === orgId) || props.organizations[0] || null;
  const writableProject = projects.find((project) => project.write);
  const canCreateSecret = !!selected && (selected.type <= 1 || !!writableProject);

  function wrappedOrgKey(): string {
    if (!selected?.key) throw new Error('Organization key unavailable');
    return selected.key;
  }

  async function refresh(): Promise<void> {
    if (!selected) return;
    const encryptedProjects = await listProjects(props.authedFetch, selected.id);
    // As upstream project.service: an org key that cannot be unwrapped fails the refresh, while a
    // name that fails to decrypt (the webapp once stored names in plaintext) shows a decrypt error
    // for its row alone.
    const orgKey = await unwrapOrgKey(props.session, wrappedOrgKey(), props.privateKey);
    setProjects(await Promise.all(encryptedProjects.map(async (project) => ({
      ...project,
      name: await decryptWithOrgKey(orgKey, project.name).catch(() => t('txt_decrypt_failed')),
    }))));
    setSecrets(await listSecrets(props.authedFetch, selected.id));
  }

  useEffect(() => {
    refresh().catch((error) => props.onNotify('error', String(error.message || error)));
  }, [selected?.id]);

  async function onCreateProject(event: Event): Promise<void> {
    event.preventDefault();
    if (!selected) return;
    const orgKey = await unwrapOrgKey(props.session, wrappedOrgKey(), props.privateKey);
    await createProject(props.authedFetch, selected.id, await encryptWithOrgKey(orgKey, projectName));
    setProjectName('');
    await refresh();
  }

  async function onCreateSecret(event: Event): Promise<void> {
    event.preventDefault();
    if (!selected || !canCreateSecret) return;
    const orgKey = await unwrapOrgKey(props.session, wrappedOrgKey(), props.privateKey);
    await createSecret(props.authedFetch, selected.id, {
      key: await encryptWithOrgKey(orgKey, secretKey),
      value: await encryptWithOrgKey(orgKey, secretValue),
      note: await encryptWithOrgKey(orgKey, ''),
      projectIds: writableProject ? [writableProject.id] : [],
    });
    setSecretKey('');
    setSecretValue('');
    await refresh();
    props.onNotify('success', t('txt_sm_secret_created'));
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
            <input className="input" aria-label={t('txt_name')} value={projectName} onInput={(event) => setProjectName((event.currentTarget as HTMLInputElement).value)} required />
            <button className="btn" type="submit">{t('txt_sm_add_project')}</button>
            <ul className="plain-list">{projects.map((project) => <li>{project.name}</li>)}</ul>
          </form>
          <form className="card form-grid" onSubmit={onCreateSecret}>
            <h2>{t('txt_sm_secrets')}</h2>
            <input className="input" aria-label={t('txt_sm_secret_key')} placeholder={t('txt_sm_secret_key')} value={secretKey} onInput={(event) => setSecretKey((event.currentTarget as HTMLInputElement).value)} required />
            <input className="input" aria-label={t('txt_sm_secret_value')} placeholder={t('txt_sm_secret_value')} value={secretValue} onInput={(event) => setSecretValue((event.currentTarget as HTMLInputElement).value)} required />
            <button className="btn primary" type="submit" disabled={!canCreateSecret}>{t('txt_sm_add_secret')}</button>
            <ul className="plain-list">{secrets.map((secret) => <li>{secret.id}</li>)}</ul>
          </form>
        </>
      )}
    </section>
  );
}
