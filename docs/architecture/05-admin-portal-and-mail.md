# Admin portal and mail

Transactional email uses Cloudflare's `EMAIL` binding through `sendMail` and data-only templates. Every message has text and escaped HTML, one recipient, and `Auto-Submitted: auto-generated`. User-supplied names are stripped of control characters, addresses and link schemes before rendering. Subjects never include tokens. Documentation domains are skipped.

`EMAIL` absent disables delivery. With the binding present, an invalid sender or sender name is a configuration error. Authenticated invitation flows await delivery before saving; disabled mail preserves local invite behavior, invalid config gives 503 and failed delivery gives 502. Error responses and logs omit recipient addresses and tokens.

Set `EMAIL_FROM` to an address on an onboarded sending domain and optionally set `EMAIL_FROM_NAME` (default `NodeWarden`). Use a sending subdomain. Arbitrary recipients require Workers Paid; verified Email Routing destinations can be used on Free. Development uses the local simulator, without `remote = true`.

Vault links use configured `WEB_VAULT_ORIGINS`. They never follow `X-Forwarded-Host`. Delivery code is independent of the background task adapter, which attaches notices to Workers `waitUntil`.

Cloudflare API references: [Workers API](https://developers.cloudflare.com/email-service/api/send-emails/workers-api/), [local email simulation](https://developers.cloudflare.com/email-service/local-development/sending/).

## Administrator access

`ADMIN_EMAILS` enables `/admin` on the Worker origin and defines full administrators independently of vault accounts. Each comma-separated entry is `email` or `email:stamp`. Removing an address or rotating its stamp immediately invalidates links and sessions. Unset configuration hides the portal; malformed entries give a generic portal error without disabling the vault.

Sign-in links use 32 random bytes, stored hashed in `verification`, and expire in 15 minutes. GET only renders a button. POST consumes the row atomically, requires the requesting browser's secure HttpOnly nonce cookie, and creates a fixed two-day revocable session. Requesting another link replaces that browser nonce. Links cannot be opened on another device. Worker request logs can contain the GET token, so disable Email preview and protect logs; the token alone is insufficient without its browser cookie.

All portal responses disable caching and CORS. Form POSTs require the exact Worker origin (or same-origin Fetch Metadata when Origin is absent); authenticated forms also need a session-derived CSRF token. Requests with Fetch Metadata must be document navigations, preventing webapp scripts from reading forms. Logout deletes the server session. Login requests are capped per IP; link delivery is separately capped per administrator without revealing that budget or directory membership in the response.

The dashboard shows account/organization/admin counts, compatibility version, mail/SSO/push/Yubico configuration status, registration and vault-origin settings, and the last 20 portal audit events. It never renders credentials or the configured admin directory and makes no outbound requests.

Users can be searched by literal email prefix and paged at up to 100 rows. Details expose account metadata, factor status and counts only; personal item counts exclude organization items. Deletion requires CSRF, a sign-in within 15 minutes and typing the user's email. A shared service refuses sole owners, accounts with organization items that cannot be reassigned, and the last active vault administrator. Organization items are handed to another confirmed member and retain their blobs; personal blobs are removed only after the atomic deletion and audit batch commits. Administrator invite codes cascade on deletion. Portal deletes are capped at 20 per administrator per hour.
