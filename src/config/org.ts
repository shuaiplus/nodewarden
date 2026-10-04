// Bitwarden-compatible organization domain constants, kept beside their type
// aliases in ../types so every layer can share one encoding. These used to
// live in a handler module, which forced handler-to-handler import cycles and
// pushed the storage repos into re-encoding the scale as bare SQL literals —
// the exact drift that once caused a status-scale migration.

// Bitwarden OrganizationUserStatusType, stored natively (no translation
// layer): Revoked=-1, Invited=0, Accepted=1, Confirmed=2.
export const ORG_USER_STATUS = {
  REVOKED: -1,
  INVITED: 0,
  ACCEPTED: 1,
  CONFIRMED: 2,
} as const;

// Bitwarden OrganizationUserType. MANAGER and CUSTOM are stored and surfaced
// on the wire for parity, but management operations stay owner-gated until a
// permissions editor exists; access is driven by accessAll + collection
// grants like a regular User.
export const ORG_USER_TYPE = {
  OWNER: 0,
  ADMIN: 1,
  USER: 2,
  MANAGER: 3,
  CUSTOM: 4,
} as const;

// Config key gating org-invite registration-code minting. Default OFF: org
// owners can invite unregistered emails (pending invitations are still
// created), but only the server admin may mint registration codes. Instance
// admins can opt in via POST /api/admin/settings/org-self-service-registration.
export const ORG_SELF_SERVICE_REGISTRATION_CONFIG_KEY = 'org.selfServiceRegistration';
