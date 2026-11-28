// CONTRACT:
// Legacy org-key wrap repair.
//
// Webapp versions before 2026-09-18 wrapped each member's organization key
// with RSA-OAEP SHA-256, but official Bitwarden clients unwrap type-4
// EncStrings with SHA-1 only (see org-crypto.ts). A member with a legacy
// wrap can log in and sync successfully, yet every org field — the org name
// in the ownership dropdown included — fails to decrypt in the extension
// and desktop app and displays as the raw "2.xxx" cipherstring. The
// NodeWarden webapp itself still reads legacy wraps through its SHA-256
// fallback, which is why the breakage is invisible there.
//
// Wraps are RSA-OAEP to each member's public key, so a legacy row is
// detectable only by the member holding the private key, and repairable
// only by an owner (the confirm endpoint is owner-gated and the org key is
// needed to re-wrap). Repair strategy:
//   1. An owner whose own wrap is legacy dates the org to before the fix;
//      repairing their row implies other pre-fix members may be legacy too,
//      so the same pass re-wraps every confirmed member.
//   2. A healthy wrap gives no signal about other members' rows, so owners
//      also have a manual re-encrypt action that unconditionally re-wraps
//      all confirmed members (idempotent — safe to run any time).
//   3. Non-owner members cannot repair anything; the org page surfaces a
//      banner telling them to ask an owner.
import {
  confirmOrganizationMember,
  getOrganizationMember,
  listOrganizationMembers,
  updateOrganization,
  type OrganizationMember,
  type OrganizationSummary,
} from './api/organizations';
import { unwrapOrganizationKeyDetailed, wrapOrganizationKeyForUser } from './org-crypto';
import { base64ToBytes, decryptStr, looksLikeEncString } from './crypto';
import type { OrgKeyMap } from './vault-decrypt';
import type { AuthedFetch } from './api/shared';

// Bitwarden OrganizationUserStatusType.Confirmed / OrganizationUserType.Owner.
const WIRE_STATUS_CONFIRMED = 2;
const WIRE_TYPE_OWNER = 0;

export interface OrgKeyRepairContext {
  authedFetch: AuthedFetch;
  /** Acting user's decrypted RSA private key (raw PKCS8 bytes). */
  pkcs8: Uint8Array;
  /** Acting user's plaintext public key (SPKI base64); used to re-wrap their own row. */
  publicKey: string | null;
}

// Session-scoped guards. `repairedOrgIds` makes later checks cheap and
// prevents re-sweeping (each confirm bumps every member's revision date,
// forcing vault re-syncs); `sweepingOrgIds` prevents concurrent sweeps from
// double-confirming the same rows.
const repairedOrgIds = new Set<string>();
const sweepingOrgIds = new Set<string>();
// Orgs whose legacy encrypted name has been rewritten as plaintext.
const migratedOrgNameIds = new Set<string>();

/** True when this member's wrapped org key uses the legacy SHA-256 OAEP hash. */
export async function isLegacyOrgKeyWrap(
  organizationId: string,
  orgKeyEnc: string | null | undefined,
  pkcs8: Uint8Array
): Promise<boolean> {
  if (!orgKeyEnc) return false;
  const unwrapped = await unwrapOrganizationKeyDetailed(organizationId, orgKeyEnc, pkcs8);
  return !!unwrapped?.legacySha256Wrap;
}

function isSweepableMember(member: OrganizationMember): boolean {
  // Only confirmed members carry a wrapped key; members without a linked
  // account (userId null) have no key row to repair.
  return Number(member.status) === WIRE_STATUS_CONFIRMED && !!member.userId;
}

/**
 * Re-wrap the org key (SHA-1) for every confirmed member of an org.
 * Idempotent: members already on SHA-1 are harmlessly re-wrapped with the
 * same org key. `exceptOrganizationUserId` skips one row (the owner's own,
 * which the auto path repairs first). Returns the number of members
 * re-encrypted.
 */
export async function reencryptOrganizationMemberKeys(
  authedFetch: AuthedFetch,
  organizationId: string,
  orgRawKey: Uint8Array,
  options: { exceptOrganizationUserId?: string } = {}
): Promise<number> {
  if (sweepingOrgIds.has(organizationId)) return 0;
  sweepingOrgIds.add(organizationId);
  try {
    const members = await listOrganizationMembers(authedFetch, organizationId);
    let repaired = 0;
    for (const member of members) {
      if (!isSweepableMember(member)) continue;
      if (member.id === options.exceptOrganizationUserId) continue;
      try {
        const details = await getOrganizationMember(authedFetch, organizationId, member.id);
        if (!details.publicKey) continue; // pre-key account: nothing to wrap with
        const wrapped = await wrapOrganizationKeyForUser(orgRawKey, details.publicKey);
        await confirmOrganizationMember(authedFetch, organizationId, member.id, wrapped);
        repaired += 1;
      } catch {
        // One bad member row must not abort the rest of the sweep.
      }
    }
    return repaired;
  } finally {
    sweepingOrgIds.delete(organizationId);
  }
}

/**
 * Auto-repair owned orgs whose own membership key is a legacy SHA-256 wrap.
 * Repairs the owner's row with the official SHA-1 hash, then re-wraps every
 * other confirmed member of that org. Returns true when any repair happened.
 */
export async function repairLegacyOrganizationKeysForSelf(
  organizations: OrganizationSummary[],
  context: OrgKeyRepairContext
): Promise<boolean> {
  let anyRepaired = false;
  for (const org of organizations) {
    if (Number(org.status) !== WIRE_STATUS_CONFIRMED) continue;
    if (Number(org.type) !== WIRE_TYPE_OWNER) continue;
    if (!org.key) continue;
    if (repairedOrgIds.has(org.id)) continue;
    try {
      const unwrapped = await unwrapOrganizationKeyDetailed(org.id, org.key, context.pkcs8);
      if (!unwrapped) continue;
      if (!unwrapped.legacySha256Wrap) {
        // Own row is healthy — nothing detectable to repair (other members'
        // rows are opaque). Mark so later passes skip the unwrap entirely.
        repairedOrgIds.add(org.id);
        continue;
      }
      // Owner's own row: re-wrap with the official SHA-1 hash.
      if (context.publicKey) {
        const rewrapped = await wrapOrganizationKeyForUser(unwrapped.raw, context.publicKey);
        await confirmOrganizationMember(context.authedFetch, org.id, org.organizationUserId, rewrapped);
      }
      // Every other confirmed member: unconditional SHA-1 re-wrap (the org
      // predates the fix, so their rows may be legacy too — undetectable
      // from outside, and the confirm endpoint is idempotent).
      await reencryptOrganizationMemberKeys(context.authedFetch, org.id, unwrapped.raw, {
        exceptOrganizationUserId: org.organizationUserId,
      });
      repairedOrgIds.add(org.id);
      anyRepaired = true;
    } catch {
      // Best-effort: leave the org unmarked so the next pass retries.
    }
  }
  return anyRepaired;
}

// Migrate legacy org-key-encrypted org names to plaintext. Current official
// Bitwarden clients render profile.organizations[].name verbatim (no
// decryption), so an EncString name shows up as raw "2.xxx" garbage in the
// extension and desktop app. The server never decrypts, so only a member
// holding the org key can rewrite it — and only an owner may rename. For
// every owned confirmed org whose name still looks like an EncString,
// decrypt it with the org key and PUT the plaintext name back (which bumps
// every member's revision date, so connected clients resync immediately).
export async function migrateLegacyEncryptedOrgNames(
  organizations: Array<{ id: string; name: string; key?: string | null; status: number; type: number }>,
  context: { authedFetch: AuthedFetch; orgKeys: OrgKeyMap | null }
): Promise<boolean> {
  if (!context.orgKeys) return false;
  let anyMigrated = false;
  for (const org of organizations) {
    if (Number(org.status) !== WIRE_STATUS_CONFIRMED) continue;
    if (Number(org.type) !== WIRE_TYPE_OWNER) continue; // rename is owner-gated
    if (!looksLikeEncString(org.name)) continue;
    if (migratedOrgNameIds.has(org.id)) continue;
    const material = context.orgKeys[org.id];
    if (!material) continue;
    try {
      const plain = await decryptStr(
        org.name,
        base64ToBytes(material.encB64),
        base64ToBytes(material.macB64)
      );
      if (!plain) continue;
      await updateOrganization(context.authedFetch, org.id, plain);
      migratedOrgNameIds.add(org.id);
      anyMigrated = true;
    } catch {
      // Best-effort: leave unmarked so a later pass retries.
    }
  }
  return anyMigrated;
}
