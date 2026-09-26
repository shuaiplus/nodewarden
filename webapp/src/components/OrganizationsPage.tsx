import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Plus, RefreshCw, SlidersHorizontal, Trash2 } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import { base64ToBytes, decryptStr } from '@/lib/crypto';
import {
  type OrganizationCollection,
  type OrganizationMember,
  type OrganizationSummary,
  acceptOrganizationInvitation,
  confirmOrganizationMember,
  createOrganization,
  createOrganizationCollection,
  deleteOrganization,
  deleteOrganizationCollection,
  getOrganizationMember,
  inviteOrganizationMembers,
  leaveOrganization,
  listMyOrganizations,
  listOrganizationCollections,
  listOrganizationMembers,
  removeOrganizationMember,
  updateOrganization,
  updateOrganizationMember,
} from '@/lib/api/organizations';
import {
  type OrgKeyParts,
  decryptPrivateKeyPkcs8,
  encryptWithOrgKey,
  generateOrganizationKeyBytes,
  generateOrganizationKeyPair,
  orgKeyBytesToParts,
  unwrapOrganizationKeyDetailed,
  wrapOrganizationKeyForUser,
} from '@/lib/org-crypto';
import type { OrgKeyMap } from '@/lib/vault-decrypt';
import type { AuthedFetch } from '@/lib/api/shared';
import type { Profile, SessionState } from '@/lib/types';
import { t } from '@/lib/i18n';

interface OrganizationsPageProps {
  profile: Profile | null;
  session: SessionState | null;
  authedFetch: AuthedFetch;
  orgKeys: OrgKeyMap | null;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  onRefresh: () => Promise<void>;
  onNavigate: (path: string) => void;
}

// Wire status values (Bitwarden OrganizationUserStatusType).
const STATUS_INVITED = 0;
const STATUS_ACCEPTED = 1;
const STATUS_CONFIRMED = 2;
const TYPE_OWNER = 0;
// Bitwarden OrganizationUserType (0=Owner 1=Admin 2=User 3=Manager 4=Custom).
const ORG_ROLE = {
  OWNER: 0,
  ADMIN: 1,
  USER: 2,
  MANAGER: 3,
  CUSTOM: 4,
} as const;

function roleLabel(type: number): string {
  if (type === ORG_ROLE.OWNER) return t('txt_organizations_owner_badge');
  if (type === ORG_ROLE.ADMIN) return t('txt_organizations_role_admin');
  if (type === ORG_ROLE.MANAGER) return t('txt_organizations_role_manager');
  if (type === ORG_ROLE.CUSTOM) return t('txt_organizations_role_custom');
  return t('txt_organizations_member_badge');
}

function orgKeyMaterialFromMap(orgKeys: OrgKeyMap | null, organizationId: string): OrgKeyParts | null {
  const material = orgKeys?.[organizationId];
  if (!material) return null;
  return {
    encB64: material.encB64,
    macB64: material.macB64,
    encBytes: base64ToBytes(material.encB64),
    macBytes: base64ToBytes(material.macB64),
  };
}

async function decryptOrgName(value: string, orgKeys: OrgKeyMap | null, organizationId: string): Promise<string> {
  const material = orgKeyMaterialFromMap(orgKeys, organizationId);
  if (!material) return '';
  try {
    return await decryptStr(value, material.encBytes, material.macBytes);
  } catch {
    return '';
  }
}

export default function OrganizationsPage(props: OrganizationsPageProps) {
  const [organizations, setOrganizations] = useState<OrganizationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [displayNames, setDisplayNames] = useState<Record<string, string>>({});
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [collections, setCollections] = useState<OrganizationCollection[]>([]);
  const [collectionNames, setCollectionNames] = useState<Record<string, string>>({});
  const [detailLoading, setDetailLoading] = useState(false);
  const [createName, setCreateName] = useState('');
  const [creating, setCreating] = useState(false);
  const [newCollectionName, setNewCollectionName] = useState('');
  const [inviteEmails, setInviteEmails] = useState('');
  const [inviteAccessAll, setInviteAccessAll] = useState(true);
  const [inviteRole, setInviteRole] = useState<number>(ORG_ROLE.USER);
  const [inviteSubmitting, setInviteSubmitting] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [permissionsMember, setPermissionsMember] = useState<OrganizationMember | null>(null);
  const [permissionsRows, setPermissionsRows] = useState<Array<{ id: string; name: string; enabled: boolean; readOnly: boolean; hidePasswords: boolean }>>([]);
  const [permissionsAccessAll, setPermissionsAccessAll] = useState(false);
  const [permissionsSubmitting, setPermissionsSubmitting] = useState(false);

  const selectedOrganization = useMemo(
    () => organizations.find((org) => org.id === selectedOrgId) || null,
    [organizations, selectedOrgId]
  );
  const selectedIsOwner = !!selectedOrganization && Number(selectedOrganization.type) === TYPE_OWNER;

  const notify = props.onNotify;
  const authedFetch = props.authedFetch;
  const orgKeys = props.orgKeys;
  const onRefreshVault = props.onRefresh;

  // Previous decrypted names, kept in a ref so refreshOrganizations does not
  // depend on the state object (which would refetch-loop via the effect).
  const displayNamesRef = useRef<Record<string, string>>({});
  useEffect(() => {
    displayNamesRef.current = displayNames;
  }, [displayNames]);

  // Repair legacy org-key wraps: keys wrapped with the legacy SHA-256 OAEP
  // hash are unreadable by official Bitwarden clients. Owners re-wrap the
  // key with the official SHA-1 hash via the (idempotent) confirm endpoint.
  const repairedLegacyOrgKeysRef = useRef<Set<string>>(new Set());
  const repairLegacyOrgKeys = useCallback(async (list: OrganizationSummary[]) => {
    if (!props.session?.symEncKey || !props.session?.symMacKey || !props.profile?.privateKey) return;
    const userEnc = base64ToBytes(props.session.symEncKey);
    const userMac = base64ToBytes(props.session.symMacKey);
    const pkcs8 = await decryptPrivateKeyPkcs8(props.profile.privateKey, userEnc, userMac);
    if (!pkcs8) return;
    for (const org of list) {
      if (Number(org.status) !== STATUS_CONFIRMED) continue;
      if (Number(org.type) !== TYPE_OWNER) continue;
      if (repairedLegacyOrgKeysRef.current.has(org.id)) continue;
      try {
        const unwrapped = await unwrapOrganizationKeyDetailed(org.id, org.key, pkcs8);
        if (!unwrapped) continue;
        if (!unwrapped.legacySha256Wrap) continue;
        const publicKey = props.profile?.publicKey;
        if (!publicKey) continue;
        const rewrapped = await wrapOrganizationKeyForUser(unwrapped.raw, publicKey);
        await confirmOrganizationMember(authedFetch, org.id, org.organizationUserId, rewrapped);
        repairedLegacyOrgKeysRef.current.add(org.id);
        await onRefreshVault();
      } catch {
        // Best-effort repair; surface nothing on failure.
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authedFetch, onRefreshVault, props.profile, props.session?.symEncKey, props.session?.symMacKey]);

  const refreshOrganizations = useCallback(async () => {
    try {
      setError('');
      const list = await listMyOrganizations(authedFetch);
      setOrganizations(list);
      const names: Record<string, string> = {};
      for (const org of list) {
        if (Number(org.status) === STATUS_CONFIRMED && orgKeys) {
          // Keep the previously resolved name when the org key is not in
          // scope yet (e.g. right after creating an organization).
          names[org.id] =
            (await decryptOrgName(org.name, orgKeys, org.id)) ||
            displayNamesRef.current[org.id] ||
            '';
        }
      }
      setDisplayNames(names);
      void repairLegacyOrgKeys(list);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('txt_organizations_load_failed'));
    } finally {
      setLoading(false);
    }
  }, [authedFetch, orgKeys, repairLegacyOrgKeys]);

  useEffect(() => {
    void refreshOrganizations();
  }, [refreshOrganizations]);

  const refreshOrgDetail = useCallback(async (organizationId: string) => {
    if (!orgKeys) return;
    setDetailLoading(true);
    try {
      const [memberList, collectionList] = await Promise.all([
        listOrganizationMembers(authedFetch, organizationId),
        listOrganizationCollections(authedFetch, organizationId),
      ]);
      setMembers(memberList);
      setCollections(collectionList);
      const names: Record<string, string> = {};
      for (const collection of collectionList) {
        try {
          names[collection.id] = await decryptStr(collection.name, base64ToBytes(orgKeys[organizationId]?.encB64 || ''), base64ToBytes(orgKeys[organizationId]?.macB64 || ''));
        } catch {
          names[collection.id] = '';
        }
      }
      setCollectionNames(names);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_load_failed'));
    } finally {
      setDetailLoading(false);
    }
  }, [authedFetch, orgKeys, notify]);

  useEffect(() => {
    if (selectedOrgId && Number(selectedOrganization?.status) === STATUS_CONFIRMED && orgKeys?.[selectedOrgId]) {
      void refreshOrgDetail(selectedOrgId);
    } else {
      setMembers([]);
      setCollections([]);
      setCollectionNames({});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedOrgId, selectedOrganization?.status, selectedOrgId ? orgKeys?.[selectedOrgId] : undefined]);

  async function handleCreateOrganization() {
    const name = createName.trim();
    if (!name) {
      notify('warning', t('txt_organizations_name_required'));
      return;
    }
    setCreating(true);
    try {
      const rawKey = generateOrganizationKeyBytes();
      const parts = orgKeyBytesToParts(rawKey);
      const keyPair = await generateOrganizationKeyPair(parts);
      if (!props.profile?.publicKey) {
        throw new Error(t('txt_organizations_missing_public_key'));
      }
      const wrappedKey = await wrapOrganizationKeyForUser(rawKey, props.profile.publicKey);
      const encName = await encryptWithOrgKey(name, parts);
      const encCollectionName = await encryptWithOrgKey(name, parts);
      const created = await createOrganization(authedFetch, {
        name: encName,
        key: wrappedKey,
        keys: { publicKey: keyPair.publicKeyB64, encryptedPrivateKey: keyPair.encryptedPrivateKey },
        collectionName: encCollectionName,
        billingEmail: props.profile?.email || null,
      });
      setCreateName('');
      // The org key is not resolved through the profile pipeline yet; show
      // the given name immediately instead of the org id fallback.
      setDisplayNames((prev) => ({ ...prev, [created.id]: name }));
      notify('success', t('txt_organizations_created'));
      await refreshOrganizations();
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_create_failed'));
    } finally {
      setCreating(false);
    }
  }

  async function handleAcceptInvitation(org: OrganizationSummary) {
    setBusy(org.id);
    try {
      await acceptOrganizationInvitation(authedFetch, org.id, org.organizationUserId);
      notify('success', t('txt_organizations_invite_accepted'));
      await refreshOrganizations();
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_invite_accept_failed'));
    } finally {
      setBusy(null);
    }
  }

  async function handleConfirmMember(member: OrganizationMember) {
    if (!selectedOrgId || !orgKeys?.[selectedOrgId] || !member.userId) return;
    setBusy(member.id);
    try {
      const details = await getOrganizationMember(authedFetch, selectedOrgId, member.id);
      if (!details.publicKey) {
        throw new Error(t('txt_organizations_member_no_key'));
      }
      const material = orgKeys[selectedOrgId];
      const raw = new Uint8Array(64);
      raw.set(base64ToBytes(material.encB64), 0);
      raw.set(base64ToBytes(material.macB64), 32);
      const wrapped = await wrapOrganizationKeyForUser(raw, details.publicKey);
      await confirmOrganizationMember(authedFetch, selectedOrgId, member.id, wrapped);
      notify('success', t('txt_organizations_member_confirmed'));
      await refreshOrgDetail(selectedOrgId);
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_confirm_failed'));
    } finally {
      setBusy(null);
    }
  }

  async function handleInvite() {
    if (!selectedOrgId) return;
    const emails = inviteEmails
      .split(/[\s,;]+/)
      .map((email) => email.trim().toLowerCase())
      .filter(Boolean);
    if (!emails.length) {
      notify('warning', t('txt_organizations_invite_emails_required'));
      return;
    }
    setInviteSubmitting(true);
    try {
      const result = await inviteOrganizationMembers(authedFetch, selectedOrgId, {
        emails,
        type: inviteRole,
        accessAll: inviteAccessAll,
      });
      const withCode = result.invited.filter((item) => item.inviteCode).length;
      const needsAdmin = result.invited.filter((item) => item.requiresAdminRegistration).length;
      let message: string;
      if (result.invited.length > 0 && needsAdmin === result.invited.length) {
        message = t('txt_organizations_invite_admin_registration_note', { count: String(needsAdmin) });
      } else {
        message = t('txt_organizations_invite_sent', { count: String(result.invited.length) });
        if (withCode > 0) {
          message += ' ' + t('txt_organizations_invite_codes_note', { count: String(withCode) });
        }
        if (needsAdmin > 0) {
          message += ' ' + t('txt_organizations_invite_admin_registration_note', { count: String(needsAdmin) });
        }
      }
      notify('success', message);
      setInviteEmails('');
      await refreshOrgDetail(selectedOrgId);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_invite_failed'));
    } finally {
      setInviteSubmitting(false);
    }
  }

  async function handleRemoveMember(member: OrganizationMember) {
    if (!selectedOrgId) return;
    setBusy(member.id);
    try {
      await removeOrganizationMember(authedFetch, selectedOrgId, member.id);
      notify('success', t('txt_organizations_member_removed'));
      await refreshOrgDetail(selectedOrgId);
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_member_remove_failed'));
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateCollection() {
    if (!selectedOrgId || !orgKeys?.[selectedOrgId]) return;
    const name = newCollectionName.trim();
    if (!name) {
      notify('warning', t('txt_organizations_collection_name_required'));
      return;
    }
    setBusy('new-collection');
    try {
      const material = orgKeys[selectedOrgId];
      const encName = await encryptWithOrgKey(name, {
        encB64: material.encB64,
        macB64: material.macB64,
        encBytes: base64ToBytes(material.encB64),
        macBytes: base64ToBytes(material.macB64),
      });
      await createOrganizationCollection(authedFetch, selectedOrgId, encName);
      setNewCollectionName('');
      notify('success', t('txt_organizations_collection_created'));
      await refreshOrgDetail(selectedOrgId);
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_collection_create_failed'));
    } finally {
      setBusy(null);
    }
  }

  async function handleDeleteCollection(collection: OrganizationCollection) {
    if (!selectedOrgId) return;
    setBusy(collection.id);
    try {
      await deleteOrganizationCollection(authedFetch, selectedOrgId, collection.id);
      notify('success', t('txt_organizations_collection_deleted'));
      await refreshOrgDetail(selectedOrgId);
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_collection_delete_failed'));
    } finally {
      setBusy(null);
    }
  }

  // Per-collection permission editor: seed a row per org collection from the
  // member's current access, then replace the whole set on save.
  async function openMemberPermissions(member: OrganizationMember) {
    if (!selectedOrgId || !orgKeys?.[selectedOrgId]) return;
    try {
      const details = await getOrganizationMember(authedFetch, selectedOrgId, member.id);
      const assigned = new Map(
        (details.collections || []).map((row) => [row.id, row])
      );
      const rows = collections.map((collection) => {
        const existing = assigned.get(collection.id);
        return {
          id: collection.id,
          name: collectionNames[collection.id] || collection.id.slice(0, 8),
          enabled: !!existing,
          readOnly: !!existing?.readOnly,
          hidePasswords: !!existing?.hidePasswords,
        };
      });
      setPermissionsRows(rows);
      setPermissionsAccessAll(!!member.accessAll);
      setPermissionsMember(member);
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_member_update_failed'));
    }
  }

  async function saveMemberPermissions() {
    if (!selectedOrgId || !permissionsMember) return;
    setPermissionsSubmitting(true);
    try {
      // Bitwarden semantics: "access all items" ignores (and clears) explicit
      // collection assignments; without it, ONLY the checked rows grant access.
      const collectionsPayload = permissionsAccessAll
        ? []
        : permissionsRows
            .filter((row) => row.enabled)
            .map((row) => ({ id: row.id, readOnly: row.readOnly, hidePasswords: row.hidePasswords }));
      await updateOrganizationMember(authedFetch, selectedOrgId, permissionsMember.id, {
        accessAll: permissionsAccessAll,
        collections: collectionsPayload,
      });
      notify('success', t('txt_organizations_permissions_saved'));
      setPermissionsMember(null);
      setPermissionsRows([]);
      await refreshOrgDetail(selectedOrgId);
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_member_update_failed'));
    } finally {
      setPermissionsSubmitting(false);
    }
  }

  async function handleRenameOrganization() {
    if (!selectedOrgId || !orgKeys?.[selectedOrgId] || !selectedOrganization) return;
    const material = orgKeys[selectedOrgId];
    const current = displayNames[selectedOrgId] || '';
    const next = window.prompt(t('txt_organizations_rename_prompt'), current);
    if (!next || next.trim() === current) return;
    setBusy('rename');
    try {
      const encName = await encryptWithOrgKey(next.trim(), {
        encB64: material.encB64,
        macB64: material.macB64,
        encBytes: base64ToBytes(material.encB64),
        macBytes: base64ToBytes(material.macB64),
      });
      await updateOrganization(authedFetch, selectedOrgId, encName);
      notify('success', t('txt_organizations_renamed'));
      await refreshOrganizations();
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_rename_failed'));
    } finally {
      setBusy(null);
    }
  }

  async function handleLeaveOrganization() {
    if (!selectedOrgId) return;
    if (!window.confirm(t('txt_organizations_leave_confirm'))) return;
    setBusy('leave');
    try {
      await leaveOrganization(authedFetch, selectedOrgId);
      notify('success', t('txt_organizations_left'));
      setSelectedOrgId(null);
      await refreshOrganizations();
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_leave_failed'));
    } finally {
      setBusy(null);
    }
  }

  async function handleDeleteOrganization() {
    if (!selectedOrgId) return;
    if (!window.confirm(t('txt_organizations_delete_confirm'))) return;
    setBusy('delete-org');
    try {
      await deleteOrganization(authedFetch, selectedOrgId);
      notify('success', t('txt_organizations_deleted'));
      setSelectedOrgId(null);
      await refreshOrganizations();
      await onRefreshVault();
    } catch (err) {
      notify('error', err instanceof Error ? err.message : t('txt_organizations_delete_failed'));
    } finally {
      setBusy(null);
    }
  }

  function statusLabel(status: number): string {
    if (status === STATUS_INVITED) return t('txt_organizations_status_invited');
    if (status === STATUS_ACCEPTED) return t('txt_organizations_status_accepted');
    if (status === STATUS_CONFIRMED) return t('txt_organizations_status_confirmed');
    return String(status);
  }

  const pendingInvitations = organizations.filter(
    (org) => Number(org.status) === STATUS_INVITED || Number(org.status) === STATUS_ACCEPTED
  );
  const confirmedOrganizations = organizations.filter((org) => Number(org.status) === STATUS_CONFIRMED);

  return (
    <div className="stack">
      {!!error && (
        <div className="local-error">
          <span>{error}</span>
          <button type="button" className="btn btn-secondary small" onClick={() => void refreshOrganizations()}>
            <RefreshCw size={14} className="btn-icon" />
            {t('txt_refresh')}
          </button>
        </div>
      )}

      {pendingInvitations.length > 0 && (
        <section className="card">
          <div className="section-head">
            <h3>{t('txt_organizations_pending_invitations')}</h3>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>{t('txt_organizations_invited_by')}</th>
                <th>{t('txt_status')}</th>
                <th>{t('txt_actions')}</th>
              </tr>
            </thead>
            <tbody>
              {pendingInvitations.map((org) => (
                <tr key={org.id}>
                  <td>{org.ownerEmail || '-'}</td>
                  <td>{statusLabel(Number(org.status))}</td>
                  <td>
                    {Number(org.status) === STATUS_INVITED ? (
                      <button
                        type="button"
                        className="btn btn-primary small"
                        disabled={busy === org.id}
                        onClick={() => void handleAcceptInvitation(org)}
                      >
                        {t('txt_organizations_accept')}
                      </button>
                    ) : (
                      <span className="muted">{t('txt_organizations_awaiting_confirmation')}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="card">
        <div className="section-head">
          <h3>{t('txt_organizations_title')}</h3>
        </div>
        <div className="org-create-row">
          <input
            type="text"
            className="input"
            placeholder={t('txt_organizations_name_placeholder')}
            value={createName}
            onInput={(event) => setCreateName((event.target as HTMLInputElement).value)}
          />
          <button type="button" className="btn btn-primary" disabled={creating} onClick={() => void handleCreateOrganization()}>
            <Plus size={14} className="btn-icon" />
            {creating ? t('txt_creating') : t('txt_organizations_create')}
          </button>
        </div>
        <p className="muted small-note">{t('txt_organizations_create_note')}</p>

        {loading ? (
          <p className="muted">{t('txt_loading')}</p>
        ) : confirmedOrganizations.length === 0 ? (
          <p className="muted">{t('txt_organizations_none')}</p>
        ) : (
          <div className="org-list">
            {confirmedOrganizations.map((org) => (
              <button
                key={org.id}
                type="button"
                className={`org-list-item ${selectedOrgId === org.id ? 'active' : ''}`}
                onClick={() => setSelectedOrgId(org.id === selectedOrgId ? null : org.id)}
              >
                <span className="org-list-name">{displayNames[org.id] || org.id.slice(0, 8)}</span>
                {Number(org.type) === TYPE_OWNER && <span className="badge">{t('txt_organizations_owner_badge')}</span>}
              </button>
            ))}
          </div>
        )}
      </section>

      {selectedOrganization && Number(selectedOrganization.status) === STATUS_CONFIRMED && (
        <section className="card">
          <div className="section-head">
            <h3>
              {displayNames[selectedOrganization.id] || selectedOrganization.id.slice(0, 8)}
              {orgKeys?.[selectedOrganization.id] ? '' : ` (${t('txt_organizations_key_unavailable')})`}
            </h3>
            <div className="section-head-actions">
              <button type="button" className="btn btn-secondary small" disabled={busy === 'rename'} onClick={() => void handleRenameOrganization()}>
                {t('txt_organizations_rename')}
              </button>
              <button type="button" className="btn btn-secondary small" disabled={busy === 'leave'} onClick={() => void handleLeaveOrganization()}>
                {t('txt_organizations_leave')}
              </button>
              {selectedIsOwner && (
                <button type="button" className="btn btn-danger small" disabled={busy === 'delete-org'} onClick={() => void handleDeleteOrganization()}>
                  <Trash2 size={14} className="btn-icon" />
                  {t('txt_organizations_delete')}
                </button>
              )}
            </div>
          </div>

          {!orgKeys?.[selectedOrganization.id] ? (
            <p className="muted">{t('txt_organizations_key_unavailable_note')}</p>
          ) : (
            <>
              {selectedIsOwner && (
                <div className="org-section">
                  <h4>{t('txt_organizations_invite_members')}</h4>
                  <div className="org-create-row">
                    <input
                      type="text"
                      className="input"
                      placeholder={t('txt_organizations_invite_emails_placeholder')}
                      value={inviteEmails}
                      onInput={(event) => setInviteEmails((event.target as HTMLInputElement).value)}
                    />
                    <button type="button" className="btn btn-primary" disabled={inviteSubmitting} onClick={() => void handleInvite()}>
                      {inviteSubmitting ? t('txt_sending') : t('txt_organizations_invite')}
                    </button>
                  </div>
                  <label className="field">
                    <span>{t('txt_organizations_role')}</span>
                    <select
                      className="input"
                      value={String(inviteRole)}
                      disabled={inviteSubmitting}
                      onChange={(event) => setInviteRole(Number((event.target as HTMLSelectElement).value))}
                    >
                      <option value={String(ORG_ROLE.OWNER)}>{t('txt_organizations_owner_badge')}</option>
                      <option value={String(ORG_ROLE.ADMIN)}>{t('txt_organizations_role_admin')}</option>
                      <option value={String(ORG_ROLE.MANAGER)}>{t('txt_organizations_role_manager')}</option>
                      <option value={String(ORG_ROLE.USER)}>{t('txt_organizations_member_badge')}</option>
                      <option value={String(ORG_ROLE.CUSTOM)}>{t('txt_organizations_role_custom')}</option>
                    </select>
                  </label>
                  <label className="checkbox-row">
                    <input
                      type="checkbox"
                      checked={inviteAccessAll}
                      onChange={(event) => setInviteAccessAll((event.target as HTMLInputElement).checked)}
                    />
                    {t('txt_organizations_invite_access_all')}
                  </label>
                </div>
              )}

              <div className="org-section">
                <h4>{t('txt_organizations_members')}</h4>
                {detailLoading ? (
                  <p className="muted">{t('txt_loading')}</p>
                ) : (
                  <table className="table">
                    <thead>
                      <tr>
                        <th>{t('txt_email')}</th>
                        <th>{t('txt_organizations_role')}</th>
                        <th>{t('txt_status')}</th>
                        <th>{t('txt_organizations_access')}</th>
                        <th>{t('txt_actions')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {members.map((member) => (
                        <tr key={member.id}>
                          <td>
                            {member.email}
                            {(() => {
                              // Squatter signal: account created after the invitation
                              if (!member.userCreatedAt || !member.invitationDate) return null;
                              try {
                                return Date.parse(member.userCreatedAt) > Date.parse(member.invitationDate)
                                  ? <span className="org-item-badge org-item-badge-readonly" title={t('txt_organizations_invite_squatter_warning')}>{t('txt_organizations_invite_squatter_warning')}</span>
                                  : null;
                              } catch { return null; }
                            })()}
                          </td>
                          <td>{roleLabel(Number(member.type))}</td>
                          <td>{statusLabel(Number(member.status))}</td>
                          <td>
                            {Number(member.status) === STATUS_CONFIRMED
                              ? member.accessAll
                                ? t('txt_organizations_access_all')
                                : t('txt_organizations_access_per_collection')
                              : '-'}
                          </td>
                          <td>
                            {selectedIsOwner && Number(member.status) === STATUS_CONFIRMED && (
                              <button
                                type="button"
                                className="btn btn-secondary small"
                                disabled={busy === member.id}
                                onClick={() => void openMemberPermissions(member)}
                              >
                                <SlidersHorizontal size={14} className="btn-icon" />
                                {t('txt_organizations_permissions')}
                              </button>
                            )}
                            {selectedIsOwner && Number(member.status) === STATUS_ACCEPTED && (
                              <button
                                type="button"
                                className="btn btn-primary small"
                                disabled={busy === member.id}
                                onClick={() => void handleConfirmMember(member)}
                              >
                                {t('txt_organizations_confirm')}
                              </button>
                            )}
                            {selectedIsOwner && member.userId !== props.profile?.id && (
                              <button
                                type="button"
                                className="btn btn-danger small"
                                disabled={busy === member.id}
                                onClick={() => void handleRemoveMember(member)}
                              >
                                {t('txt_organizations_remove')}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              <div className="org-section">
                <h4>{t('txt_organizations_collections')}</h4>
                <div className="org-create-row">
                  <input
                    type="text"
                    className="input"
                    placeholder={t('txt_organizations_collection_name_placeholder')}
                    value={newCollectionName}
                    onInput={(event) => setNewCollectionName((event.target as HTMLInputElement).value)}
                  />
                  <button type="button" className="btn btn-primary" disabled={busy === 'new-collection'} onClick={() => void handleCreateCollection()}>
                    <Plus size={14} className="btn-icon" />
                    {t('txt_organizations_add_collection')}
                  </button>
                </div>
                {detailLoading ? (
                  <p className="muted">{t('txt_loading')}</p>
                ) : (
                  <ul className="org-collections">
                    {collections.map((collection) => (
                      <li key={collection.id} className="org-collection-row">
                        <span>{collectionNames[collection.id] || collection.id.slice(0, 8)}</span>
                        {selectedIsOwner && (
                          <button
                            type="button"
                            className="btn btn-danger small"
                            disabled={busy === collection.id}
                            onClick={() => void handleDeleteCollection(collection)}
                          >
                            <Trash2 size={14} className="btn-icon" />
                            {t('txt_delete')}
                          </button>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </>
          )}
        </section>
      )}

      <ConfirmDialog
        open={!!permissionsMember}
        title={t('txt_organizations_permissions_title', { email: permissionsMember?.email || '' })}
        message={t('txt_organizations_permissions_hint')}
        confirmText={t('txt_save')}
        cancelText={t('txt_cancel')}
        confirmDisabled={permissionsSubmitting}
        cancelDisabled={permissionsSubmitting}
        onConfirm={() => void saveMemberPermissions()}
        onCancel={() => {
          setPermissionsMember(null);
          setPermissionsRows([]);
        }}
      >
        <div className="org-permissions-rows">
          <label className="checkbox-row org-permission-enable">
            <input
              type="checkbox"
              checked={permissionsAccessAll}
              onChange={(event) => setPermissionsAccessAll((event.target as HTMLInputElement).checked)}
            />
            <span className="org-permission-name">{t('txt_organizations_access_all')}</span>
          </label>
          <p className="small-note">{t('txt_organizations_access_all_note')}</p>
          {!permissionsAccessAll && (
            <>
              {permissionsRows.length === 0 && (
                <p className="muted">{t('txt_organizations_no_collections')}</p>
              )}
              {permissionsRows.map((row) => (
                <div key={row.id} className="org-permission-row">
                  <label className="checkbox-row org-permission-enable">
                    <input
                      type="checkbox"
                      checked={row.enabled}
                      onChange={(event) => setPermissionsRows((rows) => rows.map((item) => (
                        item.id === row.id ? { ...item, enabled: (event.target as HTMLInputElement).checked } : item
                      )))}
                    />
                    <span className="org-permission-name">{row.name}</span>
                  </label>
                  {row.enabled && (
                    <div className="org-permission-flags">
                      <label className="checkbox-row">
                        <input
                          type="checkbox"
                          checked={row.readOnly}
                          onChange={(event) => setPermissionsRows((rows) => rows.map((item) => (
                            item.id === row.id ? { ...item, readOnly: (event.target as HTMLInputElement).checked } : item
                          )))}
                        />
                        {t('txt_organizations_readonly_badge')}
                      </label>
                      <label className="checkbox-row">
                        <input
                          type="checkbox"
                          checked={row.hidePasswords}
                          onChange={(event) => setPermissionsRows((rows) => rows.map((item) => (
                            item.id === row.id ? { ...item, hidePasswords: (event.target as HTMLInputElement).checked } : item
                          )))}
                        />
                        {t('txt_organizations_hide_passwords')}
                      </label>
                    </div>
                  )}
                </div>
              ))}
            </>
          )}
        </div>
      </ConfirmDialog>
    </div>
  );
}
