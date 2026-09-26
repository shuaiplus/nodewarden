# Enterprise mode, licenses, and emergency access

Official Bitwarden self-host web **always** shows “upload a valid license file” when creating an organization. That is client UI, not a NodeWarden setting.

## How to create an org on official web

1. Sign in at the official web (Pages).
2. Download a NodeWarden Enterprise license while logged in:

   `GET /api/licenses/nodewarden-enterprise.json`

   Save it as `bitwarden_organization_license.json`.
3. On **New organization**, upload that file.

`POST /api/organizations/licenses/self-hosted` accepts **any JSON** (commercial Bitwarden licenses included). NodeWarden does **not** validate Bitwarden Inc signatures. The upload creates an Enterprise org (`planType` 20, `productTierType` 3) with SSO, SCIM, policies, groups, Secrets Manager, and reset-password / emergency-access flags enabled.

`POST /api/accounts/license` is accepted as a no-op because every account is already treated as Premium.

## Emergency access

Individual Premium + Enterprise flags are always on (`premium: true`, `premiumFromOrganization: true`).

Routes match official clients: `/emergency-access/trusted|granted|invite` and `/:id/{accept,confirm,initiate,approve,reject,view,takeover,password}`.

With mail and a configured vault origin, every invitation starts Invited and sends a dedicated five-day token. Acceptance requires the invited account and that token. Without mail or a vault origin, inviting an existing user still marks the contact Accepted immediately. New-account invitees need open registration; an emergency-access token does not bypass it. Pending invitations created before enabling mail need a reinvite.

After Confirm, the grantee can Initiate; wait-time 0 approves immediately. The Worker cron also auto-approves recoveries whose wait has elapsed.
