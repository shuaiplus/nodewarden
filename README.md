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
| Web vault | ✅ | ✅ | **Original Web Vault UI** |
| TOTP | ❌ | ✅ | Includes `steam://` support |
| **PWA / offline** | ❌ | ✅ | **Installable, offline** |
| **Passkey login** | ✅ | ✅ | **passwordless auth** |
| API keys | ✅ | ✅ | CLI keys; create and rotate |
| Login 2FA | ✅ | ✅ | TOTP, YubiKey, Passkey |
| 2FA recovery codes | ✅ | ✅ | One-time 2FA disable codes |
| Real-time push sync | ✅ | ✅ | All device sync |
| Attachments / Send | ✅ | ✅ | Cloudflare R2 or KV |
| Import / export | ✅ | ✅ | Bitwarden JSON / CSV / **ZIP** |
| **Cloud backup center** | ❌ | ✅ | **Scheduled WebDAV / S3 incrementals** |
| Device management | ✅ | ✅ | **Remove devices; trust controls** |
| Login requests | ✅ | ✅ | **Cross-device login approval/unlock** |
| **Multi-user** | ✅ | ✅ | Invite-code registration |
| Domain rules | ✅ | ✅ | Equivalent domains, global exclusions |
| Fill-assist | ✅ | ✅ | `POST /fill-assist`|
| Organizations / collections / roles | ✅ | ❌ | Not implemented |
| SSO / SCIM / directory | ✅ | ❌ | Not implemented |

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
4. Set **build command** to `npm run build` and **deploy command** to `npm run deploy`
   - For KV mode, change the deploy command to `npm run deploy:kv`
5. After deployment finishes, open the generated Workers URL

- The default Workers hostname may be unreachable on some networks. To use a custom domain, add it in [Workers settings](https://dash.cloudflare.com/?to=/:account/workers/services/view/nodewarden/production/settings).

- If the site reports a missing `JWT_SECRET`, add it as a **Secret** in Workers settings. In production use a random string of at least 32 characters; do not use temporary or example values.

- To hide the Web Vault, add a text variable named `HIDE_WEB_VAULT` with the value `1` under **Workers settings → Variables and Secrets**. While enabled, server-hosted frontend pages and static assets return `404 Not Found`, while the login, sync, attachment, icon, notification, and other server endpoints used by Bitwarden clients remain available; an already installed or cached PWA can continue using its local frontend. Delete the variable (or change it to anything other than `1`) to restore the server-hosted Web Vault.

- In this flow you hand code to Cloudflare to build and deploy. `wrangler.toml` or `wrangler.kv.toml` in the repo defines binding names; the Worker initializes the D1 schema on first request—no manual SQL upload.


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
```

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
