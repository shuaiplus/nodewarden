# Admin portal and mail

Transactional email uses Cloudflare's `EMAIL` binding through `sendMail` and data-only templates. Every message has text and escaped HTML, one recipient, and `Auto-Submitted: auto-generated`. User-supplied names are stripped of control characters, addresses and link schemes before rendering. Subjects never include tokens. Documentation domains are skipped.

`EMAIL` absent disables delivery. With the binding present, an invalid sender or sender name is a configuration error. Authenticated invitation flows await delivery before saving; disabled mail preserves local invite behavior, invalid config gives 503 and failed delivery gives 502. Error responses and logs omit recipient addresses and tokens.

Set `EMAIL_FROM` to an address on an onboarded sending domain and optionally set `EMAIL_FROM_NAME` (default `NodeWarden`). Use a sending subdomain. Arbitrary recipients require Workers Paid; verified Email Routing destinations can be used on Free. Development uses the local simulator, without `remote = true`.

Vault links use configured `WEB_VAULT_ORIGINS`. They never follow `X-Forwarded-Host`. Delivery code is independent of the background task adapter, which attaches notices to Workers `waitUntil`.

Cloudflare API references: [Workers API](https://developers.cloudflare.com/email-service/api/send-emails/workers-api/), [local email simulation](https://developers.cloudflare.com/email-service/local-development/sending/).
