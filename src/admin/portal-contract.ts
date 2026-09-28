// The admin portal's view of the Worker. The SvelteKit pages in admin/ reach it only through
// `platform.portal`, never by importing Worker modules, so the portal and the API share one module graph
// (user cache, ORM, notification stubs) and the portal type-checks without Cloudflare's types.

export type AdminSession = {
  email: string;
  stampHash: string;
  authTime: number;
  id: string;
  token: string;
  csrf: string;
};

export type PortalFields = Array<[string, string | number]>;

export type Throttled = { kind: 'throttled'; retryAfterSeconds: number };

export type LoginRequestOutcome =
  { kind: 'invalid-email' } | { kind: 'no-client' } | Throttled | { kind: 'sent'; nonce: string };

export type LoginRedeemOutcome = { kind: 'invalid' } | { kind: 'signed-in'; session: AdminSession; returnPath: string };

// Destructive actions need a recent sign-in, the typed confirmation and a share of the hourly budget.
export type SensitiveCheck = { kind: 'allowed' } | { kind: 'reauth' } | { kind: 'mismatch' } | Throttled;

export type ActionOutcome = { kind: 'done' } | { kind: 'not-found' } | { kind: 'refused'; refusal: string };

export type Page<Row> = { rows: Row[]; page: number; count: number; hasMore: boolean };

export type UserRow = {
  id: string;
  email: string;
  name: string | null;
  createdAt: string;
  status: string;
  role: string;
  twoFactor: boolean;
};

export type UserDetail = {
  id: string;
  email: string;
  emailVerified: boolean;
  status: 'active' | 'banned';
  hasTwoFactor: boolean;
  // Verifying a listed administrator's address also grants them the vault admin role.
  verificationGrantsVaultAdmin: boolean;
  fields: PortalFields;
};

export type OrganizationRow = { id: string; name: string; createdAt: string; billingEmail: string };

export type OrganizationDetail = {
  id: string;
  name: string;
  fields: PortalFields;
  administrators: Array<{ email: string; type: 'Owner' | 'Admin'; status: string }>;
};

export type Dashboard = {
  settings: PortalFields;
  events: Array<{ createdAt: string; action: string; adminEmail: string }>;
};

export interface AdminPortal {
  readonly cookies: {
    readonly session: { readonly name: string; readonly maxAge: number };
    readonly login: { readonly name: string; readonly maxAge: number };
  };
  // False when ADMIN_EMAILS is malformed; the portal then answers every request with a configuration error.
  readonly configured: boolean;
  acceptsRequest(): boolean;
  readCookie(name: string): string;
  returnPath(input: string): string;
  mailEnabled(): boolean;
  isLoginToken(token: string): boolean;
  requestLoginLink(email: string, returnUrl: string): Promise<LoginRequestOutcome>;
  redeemLoginLink(token: string): Promise<LoginRedeemOutcome>;
  readSession(): Promise<AdminSession | null>;
  csrfMatches(session: AdminSession, csrf: unknown): boolean;
  signOut(session: AdminSession): Promise<void>;
  checkSensitiveAction(session: AdminSession, confirmation: string, expected: string): Promise<SensitiveCheck>;
  dashboard(): Promise<Dashboard>;
  searchUsers(query: URLSearchParams): Promise<Page<UserRow>>;
  userDetail(id: string): Promise<UserDetail | null>;
  deleteUser(session: AdminSession, id: string): Promise<ActionOutcome>;
  setUserStatus(session: AdminSession, id: string, next: 'active' | 'banned'): Promise<ActionOutcome>;
  verifyUserEmail(session: AdminSession, id: string): Promise<void>;
  resetUserTwoFactor(session: AdminSession, id: string): Promise<void>;
  searchOrganizations(query: URLSearchParams): Promise<Page<OrganizationRow>>;
  organizationDetail(id: string): Promise<OrganizationDetail | null>;
  deleteOrganization(session: AdminSession, id: string): Promise<void>;
}
