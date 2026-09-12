# Security Policy

## Reporting a Vulnerability

Thank you for helping keep NodeWarden safe.

Please **do not report security vulnerabilities through public GitHub issues, discussions, pull requests, or chat groups**.

Use GitHub Private Vulnerability Reporting instead:

1. Open the NodeWarden repository on GitHub.
2. Go to **Security and quality**.
3. Click **Report a vulnerability**.
4. Submit the report privately.

NodeWarden is independent from Bitwarden. Please do not report NodeWarden-specific issues to the official Bitwarden team.

## What to Include

Please include as much detail as possible:

* A clear description of the vulnerability.
* Steps to reproduce.
* Affected version, commit, or deployment method.
* Affected area, such as login, sync, vault data, attachments, Send, import/export, backup/restore, Passkey, WebAuthn, or API routes.
* Expected behavior and actual behavior.
* Security impact, such as authentication bypass, authorization bypass, replay, cross-user access, token misuse, data leakage, or secret exposure.
* Proof of concept, logs, screenshots, or request examples, if safe to share privately.

Please redact real passwords, tokens, private keys, recovery keys, vault data, and other secrets before submitting.

## Scope

Security reports are welcome for issues affecting NodeWarden itself, including:

* Authentication and session handling.
* User authorization and cross-user access.
* Vault data, cipher sync, attachments, and Send.
* Import, export, backup, and restore.
* Passkey, WebAuthn, and two-factor authentication.
* Secret handling and provider credentials.
* Cloudflare Workers, D1, R2, KV, WebDAV, or S3 behavior caused by NodeWarden code or documentation.

## Out of Scope

The following are usually out of scope:

* Issues only affecting third-party services or user infrastructure.
* Misconfigured personal deployments not caused by NodeWarden defaults.
* Social engineering or phishing.
* Denial-of-service testing.
* Scanner-only reports without a practical exploit path.
* Reports that only mention outdated dependencies without showing real impact.

## Response

NodeWarden is maintained on a best-effort basis.

We aim to acknowledge valid private reports within 72 hours, investigate the issue, and release a fix or mitigation when appropriate.

Please do not publicly disclose vulnerability details before a fix or mitigation is available.

## Administrator Bootstrap and Role Assignment

NodeWarden has no separate setup step or setup token. Administrator privilege is
assigned as follows.

**First account.** The first account that registers on an instance is granted the
`admin` role, and the instance is then marked as registered. This is recorded in
the security audit log as `user.register.first_admin`.

**Later accounts.** After the first account exists, registration requires an
invite code (`Invite code is required`, HTTP 403) and the new account gets the
default `user` role. These are recorded as `user.register.invite`. Registration
can therefore not be used to obtain administrator privilege on an existing
instance.

**Recovery when no administrator exists.** If an instance ends up with no account
holding the `admin` role — for example the last administrator account was deleted
— the database bootstrap promotes the **earliest-created** account back to `admin`
on its next schema initialization. This is a system action with no actor, and is
recorded in the security audit log as `user.bootstrap.admin_promoted`.

Two properties of that recovery path are worth knowing:

* **Administrator accounts are not protected against deletion.** NodeWarden does
  not block deleting the last administrator. The bootstrap exists so an instance
  cannot become permanently unmanageable, but it is not a substitute for
  administrative care on a multi-user instance.
* **The account that regains the role is selected by account creation time, not
  by trust.** On a multi-user instance, make sure you intend to delete an
  administrator account before doing so.

The bootstrap only runs when the runtime schema is initialized or re-initialized
(for example after a schema version change), not on every request. Operators who
need tighter control over administrator assignment should edit the `users.role`
column directly and treat the bootstrap as a recovery mechanism only.

## Supported Versions

Security fixes are generally provided for the latest release and the latest code on the default branch.

| Version        | Supported              |
| -------------- | ---------------------- |
| Latest release | Yes                    |
| `main` branch  | Yes                    |
| Older releases | Best effort            |
| Modified forks | Not directly supported |

## Rewards

NodeWarden does not currently operate a paid bug bounty program.
