<p align="center">
  <img src="./NodeWarden.svg" alt="NodeWarden Logo" />
</p>

<p align="center">
  Bitwarden-compatible server running on Cloudflare Workers
</p>

<p align="center">
  <a href="https://workers.cloudflare.com/"><img src="https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white" alt="Powered by Cloudflare" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-LGPL--3.0-2ea44f" alt="License: LGPL-3.0" /></a>
  <a href="https://github.com/shuaiplus/NodeWarden/releases/latest"><img src="https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag" alt="Latest Release" /></a>

</p>

<p align="center">
  <a href="https://t.me/NodeWarden_News">Telegram Channel</a> |
  <a href="https://t.me/NodeWarden_Official">Telegram Group</a>
</p>

<p align="center">
  <a href="./README_ZH.md">中文</a> |
  <a href="./CONTRIBUTING.md">Contributing</a> |
  <a href="https://nodewarden.app">Official wiki</a>
</p>

> **Disclaimer**  
> This project is for learning and discussion purposes only. Please back up your vault regularly.  
> This project is not affiliated with Bitwarden. Please do not report NodeWarden issues to the official Bitwarden team.

---

## Feature comparison with the official Bitwarden server

| Feature | Bitwarden Free | NodeWarden | Notes |
|---|---|---|---|
| Web vault | ✅ | ✅ | Official Bitwarden web, served by the Worker |
| TOTP | ❌ | ✅ | Authenticator codes in every official client |
| **Passkey login** | ✅ | ✅ | **passwordless auth** |
| API keys | ✅ | ✅ | CLI keys; create and rotate |
| Login 2FA | ✅ | ✅ | TOTP, YubiKey, Passkey |
| 2FA recovery codes | ✅ | ✅ | One-time 2FA disable codes |
| Real-time push sync | ✅ | ✅ | All device sync |
| Attachments / Send | ✅ | ✅ | Cloudflare R2 or KV |
| Import / export | ✅ | ✅ | Through official clients |
| **Cloud backups** | ❌ | ✅ | **Scheduled WebDAV / S3 incrementals, configured through the admin API** |
| Device management | ✅ | ✅ | **Remove devices; trust controls** |
| Login requests | ✅ | ✅ | **Cross-device login approval/unlock** |
| **Multi-user** | ✅ | ✅ | Invite-code registration |
| Domain rules | ✅ | ✅ | Equivalent domains, global exclusions |
| Fill-assist | ✅ | ✅ | `POST /fill-assist`|
| Organizations / collections / roles | ✅ | ✅ | Owner/Admin/Manager/Custom + collections |
| SSO / SCIM / directory | ✅ | ✅ | OIDC SSO; SCIM v2 Users/Groups |
| Secrets Manager | ✅ | ✅ | Projects, secrets, machine accounts |
| Kubernetes operator | ✅ | ✅ | Compatible `BitwardenSecret` CRD |

---

## Tested clients

- ✅ Windows desktop
- ✅ Mobile app
- ✅ Browser extension
- ✅ Linux desktop
- ⚠️ macOS desktop not fully verified yet

---

## Visual quick deploy

1. Fork the NodeWarden repository to your GitHub account
2. Open [Cloudflare Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create)
3. Choose **Continue with GitHub** and select your fork
4. Leave the **build command** empty and set the **deploy command** to `npm run deploy`
   - For KV mode, change the deploy command to `npm run deploy:kv`
5. After deployment finishes, open the generated Workers URL

- The default Workers hostname may be unreachable on some networks. To use a custom domain, add it in [Workers settings](https://dash.cloudflare.com/?to=/:account/workers/services/view/nodewarden/production/settings).

- If the site reports a missing `JWT_SECRET`, add it as a **Secret** in Workers settings. In production use a random string of at least 32 characters; do not use temporary or example values.

- In this flow you hand code to Cloudflare to build and deploy. `wrangler.toml` or `wrangler.kv.toml` in the repo defines binding names; the Worker initializes the D1 schema on first request—no manual SQL upload.

- Optional SSO: set `SSO_ENABLED=1`, `SSO_AUTHORITY`, `SSO_CLIENT_ID`, and `SSO_CLIENT_SECRET`.
- Uploads larger than 100 MB use R2 S3 presigned PUTs. Set `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and `R2_BUCKET`.
- Kubernetes: use the official [Bitwarden Secrets Manager operator](https://github.com/bitwarden/sm-kubernetes). See [NodeWarden configuration](#kubernetes-secrets-manager).


> [!TIP] 
> Default R2 vs optional KV:
>   | Storage | Card required | Max single attachment / Send file | Free tier |
>   |---|---|---|---|
>   | R2 | Yes | 100 MB (soft limit, adjustable) | 10 GB |
>   | KV | No | 25 MiB (Cloudflare limit) | 1 GB |


## FAQ

- **After forking the repository, why can't I see my repository when connecting GitHub to Cloudflare, or why do I get a 404 after selecting it?**  
  This is usually related to how the GitHub fork is identified or how Cloudflare handles repository authorization and synchronization. If the fork keeps a repository name, description, or other information that is very similar to the upstream project, it may be more likely to trigger related restrictions or issues. It is recommended to rename the repository to something different from the upstream project when creating the fork, and change the repository description as well. For example, you can rename it to `2233warden`. If you have already created the fork, you can rename the repository and update its description in the GitHub repository settings, then try connecting it to Cloudflare again.

- **I deleted my deployment and redeployed it. Why does registration require an invite code again?**  
  Deleting the Worker or redeploying it does not automatically delete the persistent data that was already created. The users, invite codes, and related configuration stored in the D1 database and KV namespace are still there, so the newly deployed Worker continues to read the existing data and enforce the invite-code requirement.  
  If you want to start completely from scratch, you need to delete the corresponding **D1 database and KV namespace** as well.

- **I configured `JWT_SECRET`, but the page still says it is missing. Why?**  
  Make sure `JWT_SECRET` is configured under **Workers → Settings → Variables and Secrets**, specifically as a **Runtime variable or Secret**, rather than under **Build variables**.  
  Build-time variables are only available during the build process. They are not available to the Worker at runtime, so the build may succeed while the application still reports that `JWT_SECRET` is missing.

- **Why does `JWT_SECRET` seem to disappear after an upgrade or redeployment?**  
  It is recommended to store `JWT_SECRET` as a **Secret** rather than as a plain-text variable. `JWT_SECRET` is a sensitive runtime credential and should not be committed to the repository.  
  If your deployment process recreates or overwrites the Worker variable configuration, ordinary variables may be affected. Secrets are more appropriate for sensitive configuration that needs to remain available across multiple deployments. If the application still reports that `JWT_SECRET` is missing after a redeployment, check **Variables and Secrets** for the current Worker and make sure the Secret is still configured.

---

## How to update

- Manual: open your fork on GitHub; when the sync banner appears, click **Sync fork** → **Update branch**




## CLI deploy

```powershell
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

npm install
npx wrangler login

# Default: R2 mode
npm run deploy

# Optional: KV mode
npm run deploy:kv

# Local development
npm run dev
npm run dev:kv

# Official Bitwarden web, served by the Worker from the same origin as the API
npm run build:official-web   # once per pinned release; deploy and dev include it
```

Set `WEB_VAULT_ORIGINS` to the Worker origin. Current official web builds refuse `http://` API calls, so run the Worker over HTTPS for browser tests:

```bash
npx wrangler dev --local-protocol https
E2E_ORIGIN=https://127.0.0.1:8787 OFFICIAL_WEB_ORIGIN=https://127.0.0.1:8787 npm run test:e2e
```

Official clients register through `/identity/accounts/register/*`; set `ALLOW_OPEN_REGISTRATION=1` if you want signups after the first admin without NodeWarden invite codes.

The web vault built by this repository creates organizations from a name, without a license upload. Its small Bitwarden frontend patch preserves browser-side key generation and opens Secrets Manager when creation starts there. Unmodified self-hosted Bitwarden web builds still use the license-upload dialog; `GET /api/licenses/nodewarden-enterprise.json` remains available for their compatibility flow.

`npm run test:e2e` runs the API suite and the official-web signup smoke. `npm run test:e2e:official` is only the signup file. Pass `OFFICIAL_WEB_ORIGIN` when the vault is not on the `E2E_ORIGIN` origin.

---


## License

LGPL-3.0 License

---

## Credits

- [Bitwarden](https://bitwarden.com/) - Original design and clients
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - Server implementation reference
- [Cloudflare Workers](https://workers.cloudflare.com/) - Serverless platform

---

## Contributors

<a href="https://github.com/shuaiplus/nodewarden/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=shuaiplus/nodewarden" alt="NodeWarden contributors" />
</a>

## Star History

<a href="https://www.star-history.com/?repos=shuaiplus%2FNodeWarden&type=timeline&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&theme=dark&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
 </picture>
</a>

## Kubernetes Secrets Manager

Create a machine account and grant its projects or individual secrets in official web, then issue an access token. The full token has the form `0.<id>.<secret>:<seed>`. The operator decrypts secrets locally.

Install the official [Bitwarden operator Helm chart](https://github.com/bitwarden/helm-charts/tree/main/charts/sm-operator) with these values (replace the origin):

```yaml
settings:
  cloudRegion: ""
  bwApiUrlOverride: https://nodewarden.example/api
  bwIdentityUrlOverride: https://nodewarden.example/identity
  bwSecretsManagerRefreshInterval: 300
```

Store the full token in a Kubernetes Secret named `nodewarden-sm-token`, under the key `token`, in the same namespace as this resource:

```yaml
apiVersion: k8s.bitwarden.com/v1
kind: BitwardenSecret
metadata:
  name: nodewarden-secrets
spec:
  organizationId: "<organization UUID>"
  secretName: app-secrets
  authToken:
    secretName: nodewarden-sm-token
    secretKey: token
  map:
    - bwSecretId: "<secret UUID>"
      secretKeyName: DATABASE_PASSWORD
```

The operator writes the decrypted value to `app-secrets`. Existing NodeWarden machine tokens must be re-issued after upgrading to the upstream token format. The former `operator/` implementation has been removed; replace its resources with the official operator and the `BitwardenSecret` resource above.

Email delivery uses the Cloudflare `EMAIL` binding. Set `EMAIL_FROM` to an address on your onboarded sending domain and `EMAIL_FROM_NAME` to the sender display name (default `NodeWarden`). A dedicated sending subdomain is recommended. Arbitrary recipients require Workers Paid; Workers Free can send to verified Email Routing destinations. Local development simulates delivery; do not set `remote = true` for email tests.

The separate system administrator portal is at `/admin` on the Worker origin. Set `ADMIN_EMAILS` to comma-separated email addresses, optionally `email:stamp`; rotating a stamp revokes that administrator's links and sessions. Administrators need no vault account. Sign-in links must be opened in the requesting browser, expire after 15 minutes, and are consumed only by the confirmation POST. Vault administration remains at `/admin-panel`. When `ADMIN_EMAILS` is configured, vault administrator roles follow the listed, verified email addresses. Check existing users at `/admin/users` before listing an address: accounts created before this change are already marked verified. If no listed, verified, active account exists, roles stay unchanged to prevent lockout. New accounts registered without an emailed verification token need verification before they can gain the derived role; the first registrant retains bootstrap administrator access. With mail disabled, only existing verified accounts or that first registrant can hold the role. On Workers Free, verify administrator addresses as Email Routing destinations. Turn off Cloudflare Email preview because messages contain sign-in links.
`EMAIL_SENDS_PER_HOUR` caps user-triggered mail per instance (default `100`); keep this value × 24 below your Cloudflare daily quota. Each recipient is also limited to five user-triggered messages per hour. Administrator login and security notices have separate limits and do not consume these budgets.
Email two-step login requires access to the enrolled mailbox. Keep the recovery code or another factor available: an Email factor stays enforced if sending is disabled or delivery fails. Sign-in codes have their own per-user budget so ordinary invitation or setup traffic cannot exhaust it.
Set `ENABLE_NEW_DEVICE_VERIFICATION=1` to require emailed codes for unknown devices on password-only accounts at least one day old. It is off by default and inactive without configured mail. Known devices, first-device logins, two-step login, SSO and approved device requests are exempt. A malformed flag disables only this check and is logged; it does not disable Email two-step login. If a user loses mailbox access, the operator can turn this flag off. Restoring a pre-feature archive leaves verification off for its users until they enable it.


`DISABLE_EMAIL_NEW_DEVICE=true` (or `1`) suppresses new-device sign-in notices. The default is false; malformed values make email misconfigured and log the field name.
