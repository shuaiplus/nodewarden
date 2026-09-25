import { useEffect, useState } from 'preact/hooks';
import { Building2, KeyRound, Plus, Shield, Users } from 'lucide-preact';
import {
  confirmMember,
  createCollection,
  createOrganization,
  inviteMembers,
  listCollections,
  listMembers,
  listPolicies,
  putPolicy,
  rotateScimKey,
  type OrgCollection,
  type OrgMember,
  type OrgPolicy,
  type ProfileOrganization,
} from '@/lib/api/orgs';
import { createOrgKey, wrapOrgKeyForMember } from '@/lib/org-crypto';
import type { SessionState } from '@/lib/types';
import { t } from '@/lib/i18n';

interface OrganizationPageProps {
  organizations: ProfileOrganization[];
  session: SessionState;
  authedFetch: import('@/lib/api/shared').AuthedFetch;
  onOrganizationsChanged: () => Promise<void> | void;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
}

const POLICY_LABELS: Record<number, string> = {
  0: 'Require two-step login',
  3: 'Single organization',
  4: 'Require SSO',
};

export default function OrganizationPage(props: OrganizationPageProps) {
  const [orgId, setOrgId] = useState(props.organizations[0]?.id || '');
  const [name, setName] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [collectionName, setCollectionName] = useState('');
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [collections, setCollections] = useState<OrgCollection[]>([]);
  const [policies, setPolicies] = useState<OrgPolicy[]>([]);
  const [scimToken, setScimToken] = useState('');
  const [busy, setBusy] = useState(false);

  const selected = props.organizations.find((org) => org.id === orgId) || props.organizations[0] || null;

  async function refresh(): Promise<void> {
    if (!selected) return;
    const [nextMembers, nextCollections, nextPolicies] = await Promise.all([
      listMembers(props.authedFetch, selected.id),
      listCollections(props.authedFetch, selected.id),
      listPolicies(props.authedFetch, selected.id),
    ]);
    setMembers(nextMembers);
    setCollections(nextCollections);
    setPolicies(nextPolicies);
  }

  useEffect(() => {
    refresh().catch((error) => props.onNotify('error', String(error.message || error)));
  }, [selected?.id]);

  async function onCreate(event: Event): Promise<void> {
    event.preventDefault();
    setBusy(true);
    try {
      const orgKey = await createOrgKey(props.session);
      await createOrganization(props.authedFetch, {
        name,
        billingEmail: props.session.email,
        collectionName: 'Default collection',
        key: orgKey.wrapped,
      });
      setName('');
      await props.onOrganizationsChanged();
      props.onNotify('success', t('txt_org_created'));
    } catch (error) {
      props.onNotify('error', String((error as Error).message || error));
    } finally {
      setBusy(false);
    }
  }

  async function onInvite(event: Event): Promise<void> {
    event.preventDefault();
    if (!selected) return;
    setBusy(true);
    try {
      await inviteMembers(props.authedFetch, selected.id, [inviteEmail]);
      setInviteEmail('');
      await refresh();
      props.onNotify('success', t('txt_org_invite_sent'));
    } catch (error) {
      props.onNotify('error', String((error as Error).message || error));
    } finally {
      setBusy(false);
    }
  }

  async function onConfirm(member: OrgMember): Promise<void> {
    if (!selected?.key) return;
    setBusy(true);
    try {
      const wrapped = await wrapOrgKeyForMember(props.session, selected.key);
      await confirmMember(props.authedFetch, selected.id, member.id, wrapped);
      await refresh();
      props.onNotify('success', t('txt_org_member_confirmed'));
    } catch (error) {
      props.onNotify('error', String((error as Error).message || error));
    } finally {
      setBusy(false);
    }
  }

  async function onCreateCollection(event: Event): Promise<void> {
    event.preventDefault();
    if (!selected) return;
    setBusy(true);
    try {
      await createCollection(props.authedFetch, selected.id, collectionName);
      setCollectionName('');
      await refresh();
    } catch (error) {
      props.onNotify('error', String((error as Error).message || error));
    } finally {
      setBusy(false);
    }
  }

  async function onTogglePolicy(type: number, enabled: boolean): Promise<void> {
    if (!selected) return;
    await putPolicy(props.authedFetch, selected.id, type, enabled);
    await refresh();
  }

  async function onScim(): Promise<void> {
    if (!selected) return;
    const token = await rotateScimKey(props.authedFetch, selected.id);
    setScimToken(token);
  }

  return (
    <section className="page-stack">
      <header className="page-header">
        <h1><Building2 size={22} /> {t('nav_organizations')}</h1>
        <p>{t('txt_org_intro')}</p>
      </header>

      <form className="card form-grid" onSubmit={onCreate}>
        <h2>{t('txt_org_create')}</h2>
        <label className="field">
          <span>{t('txt_org_name')}</span>
          <input className="input" value={name} onInput={(event) => setName((event.currentTarget as HTMLInputElement).value)} required />
        </label>
        <button className="btn primary" disabled={busy || !name.trim()} type="submit">
          <Plus size={16} /> {t('txt_org_create')}
        </button>
      </form>

      {props.organizations.length > 0 && (
        <label className="field">
          <span>{t('txt_org_selected')}</span>
          <select className="input" value={selected?.id || ''} onChange={(event) => setOrgId((event.currentTarget as HTMLSelectElement).value)}>
            {props.organizations.map((org) => <option value={org.id}>{org.name}</option>)}
          </select>
        </label>
      )}

      {selected && (
        <>
          <section className="card">
            <h2><Users size={18} /> {t('txt_org_members')}</h2>
            <form className="inline-form" onSubmit={onInvite}>
              <input className="input" type="email" placeholder={t('txt_org_invite_email')} value={inviteEmail} onInput={(event) => setInviteEmail((event.currentTarget as HTMLInputElement).value)} required />
              <button className="btn" type="submit" disabled={busy}>{t('txt_org_invite')}</button>
            </form>
            <ul className="plain-list">
              {members.map((member) => (
                <li>
                  <span>{member.email} · {t('txt_org_status')} {member.status} · {t('txt_org_role')} {member.type}</span>
                  {member.status === 1 && (
                    <button className="btn" type="button" onClick={() => onConfirm(member)}>{t('txt_org_confirm')}</button>
                  )}
                </li>
              ))}
            </ul>
          </section>

          <section className="card">
            <h2>{t('txt_org_collections')}</h2>
            <form className="inline-form" onSubmit={onCreateCollection}>
              <input className="input" value={collectionName} onInput={(event) => setCollectionName((event.currentTarget as HTMLInputElement).value)} placeholder={t('txt_org_collection_name')} required />
              <button className="btn" type="submit" disabled={busy}>{t('txt_org_add_collection')}</button>
            </form>
            <ul className="plain-list">
              {collections.map((collection) => <li>{collection.name}</li>)}
            </ul>
          </section>

          <section className="card">
            <h2><Shield size={18} /> {t('txt_org_policies')}</h2>
            {[0, 3, 4].map((type) => {
              const policy = policies.find((item) => item.type === type);
              return (
                <label className="checkbox-row">
                  <input type="checkbox" checked={!!policy?.enabled} onChange={(event) => onTogglePolicy(type, (event.currentTarget as HTMLInputElement).checked)} />
                  {POLICY_LABELS[type]}
                </label>
              );
            })}
          </section>

          <section className="card">
            <h2><KeyRound size={18} /> {t('txt_org_scim')}</h2>
            <p>{t('txt_org_scim_help')}</p>
            <button className="btn" type="button" onClick={onScim}>{t('txt_org_scim_rotate')}</button>
            {scimToken && <pre className="code-block">{scimToken}</pre>}
          </section>
        </>
      )}
    </section>
  );
}
