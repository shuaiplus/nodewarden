<!--
Release note writing rules:
1. Always add the newest release at the top of this file; do not delete older release notes.
2. Move previous releases down unchanged, then write the new release above them.
3. Use this exact release structure:
   - One H1 title: "# vX.Y.Z - Short English Summary".
   - English section first with "### Added", "### Improved", and "### Fixed".
   - Then a horizontal rule "---".
   - Chinese section second with "### 新增", "### 改进", and "### 修复".
4. Use numbered items under each group. Each item must be:
   - "1. **Short feature/fix title.** One concise paragraph explaining what changed and why it matters."
   - No one-line commit dumps, no raw changelog lists, no vague marketing copy.
   - Merge related commits into one readable item instead of listing every commit separately.
5. Keep the tone user-friendly and concrete:
   - Explain behavior, compatibility, UI impact, migration impact, or bug impact in plain language.
   - Be concise but specific; one item is usually 1-3 sentences.
   - Avoid internal-only implementation details unless they explain a user-visible change.
6. Add GitHub commit links at the end of every numbered item:
   - English: "Commit: [abc1234](...)." or "Commits: [abc1234](...), [def5678](...)."
   - Chinese: "提交：[abc1234](...)。" or "提交：[abc1234](...)、[def5678](...)。"
7. The English and Chinese versions should match in content and ordering, not be two different summaries.
-->

# v1.8.0 - Deployment Control, Session Reliability, and Compatibility Fixes

### Added

1. **Web Vault visibility control.** Cloudflare Workers deployments can now set `HIDE_WEB_VAULT=1` to return `404 Not Found` for server-hosted Web Vault pages and static assets while keeping Bitwarden login, sync, attachment, icon, notification, and compatibility endpoints available. Removing the variable restores the Web Vault, and already installed or cached PWAs can continue using their local frontend. Commit: [d990b2c](https://github.com/shuaiplus/nodewarden/commit/d990b2c71ff43a43f4598cad715b09c673e87b53).

### Improved

1. **Simpler desktop and mobile navigation.** The Web Vault now uses a consistent grouped sidebar with persistent expanded sections, clearer separation between tools, settings, and system management, and matching mobile settings navigation. This removes the previous layout-mode picker and makes frequently used destinations easier to find. Commit: [e25ec15](https://github.com/shuaiplus/nodewarden/commit/e25ec159bb2cd07ec6b3a794032a8a2978340d3d).

1. **Safer YubiKey validation credential management.** Yubico validation credentials now use centralized, concurrency-safe initialization; only active administrators can view or replace configured credentials, and credential initialization and reconfiguration are recorded in the security audit log. Regular users can still enroll YubiKeys without gaining access to server-wide credentials. Commit: [573451c](https://github.com/shuaiplus/nodewarden/commit/573451c52f02978dee5ab8379ff86e59da805437).

1. **Bitwarden-compatible personal API keys and safer backups.** Personal API keys can now be viewed after master-password verification and rotated without revoking unrelated sessions. Legacy hashed keys continue to authenticate until the user explicitly rotates them, while new backups exclude personal API keys and runtime authentication or device-trust state; older archives remain importable, but that runtime state is intentionally ignored during restore. Commit: [299eda5](https://github.com/shuaiplus/nodewarden/commit/299eda597ff8a07bf0b7ddfb6e3a5e7f800096db).

### Fixed

1. **Unexpected logout during temporary refresh failures.** Refresh sessions now use client-aware sliding lifetimes with an absolute upper bound, and transient network or service failures no longer turn a locked Web Vault into a forced full login. The Web Vault preserves the locked session, shows a retry path, and keeps official desktop, mobile, browser-extension, and web-cookie flows compatible. Commit: [b731a01](https://github.com/shuaiplus/nodewarden/commit/b731a014f1d86552615110cdf543f809a5c6a7e6).

1. **Complete key data required for master-password changes.** Password changes now reject incomplete or inconsistent authentication and unlock data, require the newly wrapped user key, and prevent KDF settings from being changed through the password-only endpoint. This avoids accepting a password update that could leave the account unable to decrypt its vault. Commit: [19de8d6](https://github.com/shuaiplus/nodewarden/commit/19de8d6e5769be463f973c8f2ec4de2e1530005c).

1. **Extended vault item imports preserve their data.** Web imports now correctly map bank accounts, driver's licenses, and passports instead of reducing item types 6-8 to incomplete generic drafts. Import summaries also report these item types by name. Commit: [e943357](https://github.com/shuaiplus/nodewarden/commit/e943357067236deeaa76ac0003020fa986abf2ab).

1. **Reliable bulk folder deletion.** Bulk folder deletion now calculates Cloudflare D1 bind limits correctly and batches the related cipher cleanup and folder removal statements safely, preventing large selections from failing or leaving partially updated folder references. Commit: [63b642b](https://github.com/shuaiplus/nodewarden/commit/63b642b2511207f435546802e197b6842f5c7aca).

1. **Fresh remote backup directory listings.** Opening a remote backup destination now automatically refreshes directory data when the saved cache is older than five minutes, so newly created backup files appear without requiring a manual refresh. Commit: [72d8ec9](https://github.com/shuaiplus/nodewarden/commit/72d8ec9cbadcb1b74d032deb5e5eea96e785d9c4).

---

### 新增

1. **Web Vault 显示开关。** Cloudflare Workers 部署现在可以设置 `HIDE_WEB_VAULT=1`，让服务器托管的 Web Vault 页面和静态资源统一返回 `404 Not Found`，同时继续提供 Bitwarden 客户端所需的登录、同步、附件、图标、通知和兼容接口。删除变量即可恢复 Web Vault，已经安装或缓存的 PWA 仍可继续使用本地前端。提交：[d990b2c](https://github.com/shuaiplus/nodewarden/commit/d990b2c71ff43a43f4598cad715b09c673e87b53)。

### 改进

1. **更简洁的桌面端和移动端导航。** Web Vault 现在统一使用分组侧边栏，并会保存各分组的展开状态；工具、设置和系统管理的层级更加清楚，移动端设置入口也同步调整。原有布局模式选择器已移除，常用功能更容易查找。提交：[e25ec15](https://github.com/shuaiplus/nodewarden/commit/e25ec159bb2cd07ec6b3a794032a8a2978340d3d)。

1. **更安全的 YubiKey 验证凭据管理。** Yubico 验证凭据现在通过统一且可防并发冲突的流程初始化；只有状态正常的管理员能够查看或替换服务器凭据，初始化和重新配置操作也会写入安全审计日志。普通用户仍可绑定 YubiKey，但无法接触服务器级凭据。提交：[573451c](https://github.com/shuaiplus/nodewarden/commit/573451c52f02978dee5ab8379ff86e59da805437)。

1. **兼容 Bitwarden 的个人 API Key 与更安全的备份。** 用户现在可以在验证主密码后查看个人 API Key，并在不撤销无关会话的情况下轮换密钥。旧版哈希密钥在用户主动轮换前仍可继续认证；新备份不再包含个人 API Key、运行中的认证状态或设备信任状态，旧备份仍能导入，但其中这类运行时状态会被主动忽略。提交：[299eda5](https://github.com/shuaiplus/nodewarden/commit/299eda597ff8a07bf0b7ddfb6e3a5e7f800096db)。

### 修复

1. **临时刷新失败导致意外退出登录。** 刷新会话现在根据客户端采用滑动有效期，并保留绝对最长时限；临时网络或服务故障不会再把已锁定的 Web Vault 直接变成完整登录页。Web Vault 会保留锁定会话并提供重试入口，同时兼容官方桌面端、移动端、浏览器扩展和 Web Cookie 会话。提交：[b731a01](https://github.com/shuaiplus/nodewarden/commit/b731a014f1d86552615110cdf543f809a5c6a7e6)。

1. **修改主密码时必须提交完整密钥数据。** 密码修改接口现在会拒绝不完整或不一致的认证与解锁数据，强制要求新的用户密钥包装结果，并禁止通过仅修改密码的接口顺带更改 KDF 设置，避免出现密码已更新但保险库无法解密的账户状态。提交：[19de8d6](https://github.com/shuaiplus/nodewarden/commit/19de8d6e5769be463f973c8f2ec4de2e1530005c)。

1. **扩展保险库条目导入时完整保留数据。** Web 导入现在会正确映射银行账户、驾驶证和护照，不再把类型 6-8 转换为字段缺失的通用草稿；导入结果摘要也会按名称显示这些条目类型。提交：[e943357](https://github.com/shuaiplus/nodewarden/commit/e943357067236deeaa76ac0003020fa986abf2ab)。

1. **可靠的批量文件夹删除。** 批量删除文件夹时现在会正确计算 Cloudflare D1 的绑定参数上限，并安全批处理密码条目引用清理和文件夹删除语句，避免大量选择时失败或留下只更新了一部分的文件夹引用。提交：[63b642b](https://github.com/shuaiplus/nodewarden/commit/63b642b2511207f435546802e197b6842f5c7aca)。

1. **远端备份目录自动显示最新文件。** 打开远端备份目标时，如果已保存的目录缓存超过五分钟，页面会自动获取最新数据，新生成的备份文件无需手动点击刷新即可出现。提交：[72d8ec9](https://github.com/shuaiplus/nodewarden/commit/72d8ec9cbadcb1b74d032deb5e5eea96e785d9c4)。

# v1.7.4 - Password Tools, Localization, and Security Hardening

### Added

1. **Built-in password generator.** The web vault now provides a dedicated generator for creating strong, configurable passwords, including memorable passphrases backed by the EFF word list. Generated values can be used while creating or editing vault items without leaving the app. Commits: [dfc9800](https://github.com/shuaiplus/nodewarden/commit/dfc98008cb58e9ed01b21ba158bb2584291462a3), [fb37679](https://github.com/shuaiplus/nodewarden/commit/fb376797d266003f8e23b64870f3638fde35d428).

1. **Password security dashboard.** A new password-security view scans the vault and reports weak, reused, exposed, and missing two-factor-authentication passwords, helping users prioritize account cleanup. Commit: [99b5027](https://github.com/shuaiplus/nodewarden/commit/99b50275a6a845e6ebbbae4d647350df939457f9).

1. **Duplicate-item selection tools.** Duplicate results are grouped by color and sorted alphabetically, and the vault now lets users select the unique items from a duplicate group for quicker review and cleanup. Commits: [0992170](https://github.com/shuaiplus/nodewarden/commit/099217062a4cb3a3caacce7513354bb388e8d76c), [39d9df7](https://github.com/shuaiplus/nodewarden/commit/39d9df78ea324fb2d1509221606408b1bb610118).

1. **Five additional interface languages.** Finnish, German, French, Italian, and Swedish are now available in the web vault, expanding the supported interface languages to ten. Commits: [dd90d7b](https://github.com/shuaiplus/nodewarden/commit/dd90d7b8b88a8a49ff1423bb36abb4eeb8f2f329), [9caa064](https://github.com/shuaiplus/nodewarden/commit/9caa0644888c25db835f8c5c93b8341ed80a42fe).

### Improved

1. **Passkey unlock and Bitwarden-client compatibility.** Account passkeys can now unlock the web vault directly, and supported FIDO2 origins, worker-routed fill-assist, Android asset-links checks, and web bootstrap paths are recognized more consistently. Commits: [8c65cb2](https://github.com/shuaiplus/nodewarden/commit/8c65cb2e80c6e5454fb53dbd7ea45cb83bf88ef7), [db31792](https://github.com/shuaiplus/nodewarden/commit/db31792cefc0f21fd543faf21407107a53b8dac2).

1. **Clearer offline and Send experiences.** The app now clearly indicates when it is operating offline, Send pages use improved date formatting, and closing dialogs retain their title through the animation to avoid a visual flash. Commits: [aae614a](https://github.com/shuaiplus/nodewarden/commit/aae614a079b5fa151e2bb98506f1b4fceac29072), [04cb475](https://github.com/shuaiplus/nodewarden/commit/04cb4759358b85029e3e32a5cab6ca39cbbef744), [525b773](https://github.com/shuaiplus/nodewarden/commit/525b773cf4799913ac24e34857348e3aa176608b).

1. **Simplified new-device sign-in.** New-device verification is no longer enforced, removing an extra login step for devices that are otherwise able to authenticate successfully. Commit: [14dff8e](https://github.com/shuaiplus/nodewarden/commit/14dff8ee6a59b741d86a42b25451116b120ac404).

### Fixed

1. **Backup destination SSRF protection.** Backup destination validation now rejects IPv6 loopback addresses, closing a path that could otherwise bypass loopback-host safeguards. Commit: [3c581d1](https://github.com/shuaiplus/nodewarden/commit/3c581d1fb1d92da9e00d3ff139c46f080462e6e8).

1. **Sensitive admin actions require the master password.** Administrative operations and device-wipe actions now require master-password confirmation, reducing the impact of an unattended or compromised web session. Commit: [fa611dc](https://github.com/shuaiplus/nodewarden/commit/fa611dc8430fc80744662feaaf3912341d5b63f2).

---

### 新增

1. **内置密码生成器。** Web 保险库现在提供专用的密码生成器，可创建高强度且可配置的密码，也支持基于 EFF 词表的易记口令短语。生成的值可直接用于新建或编辑保险库条目，无需离开应用。提交：[dfc9800](https://github.com/shuaiplus/nodewarden/commit/dfc98008cb58e9ed01b21ba158bb2584291462a3)、[fb37679](https://github.com/shuaiplus/nodewarden/commit/fb376797d266003f8e23b64870f3638fde35d428)。

1. **密码安全仪表板。** 新增的密码安全视图会扫描保险库，并报告弱密码、重复密码、已泄露密码和缺少双因素认证的密码，帮助用户优先处理需要清理的账户。提交：[99b5027](https://github.com/shuaiplus/nodewarden/commit/99b50275a6a845e6ebbbae4d647350df939457f9)。

1. **重复条目选择工具。** 重复项结果会按颜色分组并按字母顺序排序；保险库现在还可以从重复组中选择唯一条目，以便更快地审查和清理。提交：[0992170](https://github.com/shuaiplus/nodewarden/commit/099217062a4cb3a3caacce7513354bb388e8d76c)、[39d9df7](https://github.com/shuaiplus/nodewarden/commit/39d9df78ea324fb2d1509221606408b1bb610118)。

1. **新增五种界面语言。** Web 保险库现在提供芬兰语、德语、法语、意大利语和瑞典语，支持的界面语言扩展至十种。提交：[dd90d7b](https://github.com/shuaiplus/nodewarden/commit/dd90d7b8b88a8a49ff1423bb36abb4eeb8f2f329)、[9caa064](https://github.com/shuaiplus/nodewarden/commit/9caa0644888c25db835f8c5c93b8341ed80a42fe)。

### 改进

1. **通行密钥解锁和 Bitwarden 客户端兼容性。** 账户通行密钥现在可以直接解锁 Web 保险库；同时，对受支持 FIDO2 来源、Worker 路由的 fill-assist、Android asset-links 检查和 Web 启动路径的识别更加一致。提交：[8c65cb2](https://github.com/shuaiplus/nodewarden/commit/8c65cb2e80c6e5454fb53dbd7ea45cb83bf88ef7)、[db31792](https://github.com/shuaiplus/nodewarden/commit/db31792cefc0f21fd543faf21407107a53b8dac2)。

1. **更清晰的离线和 Send 使用体验。** 应用现在会明确提示离线运行状态，Send 页面采用了更好的日期格式，关闭对话框时会在动画期间保留标题，避免视觉闪烁。提交：[aae614a](https://github.com/shuaiplus/nodewarden/commit/aae614a079b5fa151e2bb98506f1b4fceac29072)、[04cb475](https://github.com/shuaiplus/nodewarden/commit/04cb4759358b85029e3e32a5cab6ca39cbbef744)、[525b773](https://github.com/shuaiplus/nodewarden/commit/525b773cf4799913ac24e34857348e3aa176608b)。

1. **简化新设备登录。** 不再强制执行新设备验证，能够正常完成身份验证的设备无需额外登录步骤。提交：[14dff8e](https://github.com/shuaiplus/nodewarden/commit/14dff8ee6a59b741d86a42b25451116b120ac404)。

### 修复

1. **备份目标的 SSRF 防护。** 备份目标校验现在会拒绝 IPv6 回环地址，堵住了可能绕过回环主机保护的路径。提交：[3c581d1](https://github.com/shuaiplus/nodewarden/commit/3c581d1fb1d92da9e00d3ff139c46f080462e6e8)。

1. **敏感管理员操作需要主密码。** 管理员操作和设备擦除操作现在需要确认主密码，降低无人值守或会话遭入侵时的影响。提交：[fa611dc](https://github.com/shuaiplus/nodewarden/commit/fa611dc8430fc80744662feaaf3912341d5b63f2)。

# v1.7.3 - Stronger Two-Step Login and Client Compatibility

### Added

1. **YubiKey OTP and passkey two-step login.** NodeWarden now supports YubiKey OTP as a managed two-factor provider and adds passkey-based two-factor authentication, including setup screens, WebAuthn fallback connector handling, multi-provider login prompts, and safer WebAuthn response normalization. Commits: [f63b745](https://github.com/shuaiplus/nodewarden/commit/f63b745), [c019c93](https://github.com/shuaiplus/nodewarden/commit/c019c93), [e73ae3d](https://github.com/shuaiplus/nodewarden/commit/e73ae3d), [d8cc88d](https://github.com/shuaiplus/nodewarden/commit/d8cc88d).

1. **Bitwarden extended vault item types.** Vault items now cover bank accounts, driver's licenses, and passports in addition to the existing login, card, identity, secure note, and SSH key flows. The web vault can create, display, decrypt, import, and export these item types with clearer sidebar icons. Commits: [109593d](https://github.com/shuaiplus/nodewarden/commit/109593d), [9de0d3b](https://github.com/shuaiplus/nodewarden/commit/9de0d3b).

1. **More Bitwarden client compatibility endpoints.** Added device verification settings, device registration routes, admin auth-request compatibility, fill-assist alignment, and push relay installation handling so more official Bitwarden client flows receive expected responses. Unsupported email verification and KDF routes now return explicit unsupported responses instead of ambiguous failures. Commits: [e376a84](https://github.com/shuaiplus/nodewarden/commit/e376a84), [8b2f98b](https://github.com/shuaiplus/nodewarden/commit/8b2f98b), [f0e5233](https://github.com/shuaiplus/nodewarden/commit/f0e5233), [56b301f](https://github.com/shuaiplus/nodewarden/commit/56b301f), [fd46dff](https://github.com/shuaiplus/nodewarden/commit/fd46dff), [cde4555](https://github.com/shuaiplus/nodewarden/commit/cde4555).

### Improved

1. **TOTP QR scanning and Bitwarden-compatible TOTP behavior.** Uploading TOTP QR codes now falls back to `jsQR` when browser `BarcodeDetector` support is incomplete, handles transparent PNGs correctly, validates uploaded QR images, and throttles camera fallback decoding to reduce CPU usage. TOTP storage and decryption behavior is also aligned more closely with Bitwarden clients. Commits: [b0a679b](https://github.com/shuaiplus/nodewarden/commit/b0a679b), [d024798](https://github.com/shuaiplus/nodewarden/commit/d024798), [73bbe8b](https://github.com/shuaiplus/nodewarden/commit/73bbe8b), [6e72220](https://github.com/shuaiplus/nodewarden/commit/6e72220), [8a5b210](https://github.com/shuaiplus/nodewarden/commit/8a5b210).

1. **Settings, device management, and localization polish.** Device management now lives inside Settings with updated navigation, the two-step provider UI is more responsive, and new settings, audit-log, and validation messages are localized across supported languages. This makes the security settings area easier to scan on desktop and mobile. Commits: [c7eb6c6](https://github.com/shuaiplus/nodewarden/commit/c7eb6c6), [062c966](https://github.com/shuaiplus/nodewarden/commit/062c966), [12af18e](https://github.com/shuaiplus/nodewarden/commit/12af18e), [c53d71f](https://github.com/shuaiplus/nodewarden/commit/c53d71f), [01ff627](https://github.com/shuaiplus/nodewarden/commit/01ff627).

1. **Encrypted Send password visibility and editing.** Password-protected Sends now show a lock indicator in the list, display masked password dots when editing an existing protected Send, and provide a compact trash-icon control for removing the stored password. This makes password state visible without exposing the password itself. Commits: [a870142](https://github.com/shuaiplus/nodewarden/commit/a870142), [ebc8e8e](https://github.com/shuaiplus/nodewarden/commit/ebc8e8e).

1. **Website icon behavior and workflow maintenance.** Website icons are now always available without the old `WEBSITE_ICONS_ENABLED` environment toggle, while icon requests keep privacy protections. The global-domains sync workflow also validates its ref before running. Commits: [57c5ef9](https://github.com/shuaiplus/nodewarden/commit/57c5ef9), [c643874](https://github.com/shuaiplus/nodewarden/commit/c643874), [680e287](https://github.com/shuaiplus/nodewarden/commit/680e287).

### Fixed

1. **Authentication, token, and rate-limit hardening.** API keys are stored as hashes, password rotation and JWT handling were tightened, user cache invalidates on token handling, remembered 2FA tokens survive a bad password attempt, the current access-token session is revoked correctly, and known rate-limit reset bypasses were closed. Commits: [1545881](https://github.com/shuaiplus/nodewarden/commit/1545881), [439683d](https://github.com/shuaiplus/nodewarden/commit/439683d), [60dd298](https://github.com/shuaiplus/nodewarden/commit/60dd298), [d9a36fe](https://github.com/shuaiplus/nodewarden/commit/d9a36fe), [1bad32f](https://github.com/shuaiplus/nodewarden/commit/1bad32f), [2df43cc](https://github.com/shuaiplus/nodewarden/commit/2df43cc), [ae168be](https://github.com/shuaiplus/nodewarden/commit/ae168be).

1. **User data isolation and request validation.** Storage reads are scoped by user, Send file routes gate access more strictly, anonymous notification hub requests are validated, and multipart backup/upload requests now have caps. This reduces the chance of cross-user data reads or oversized requests reaching deeper handlers. Commits: [baf5699](https://github.com/shuaiplus/nodewarden/commit/baf5699), [8c481a1](https://github.com/shuaiplus/nodewarden/commit/8c481a1), [23c53bd](https://github.com/shuaiplus/nodewarden/commit/23c53bd), [5142846](https://github.com/shuaiplus/nodewarden/commit/5142846).

1. **Backup, restore, and download safety.** Remote backup deletes are verified, archives and backup blobs are validated before use, destination secrets are redacted from settings responses, backup/download token flows are harder to misuse, and WebAuthn credential purpose survives backup export/import. A backup uploader redirect guard was also reverted to restore compatible remote behavior. Commits: [0cef6a0](https://github.com/shuaiplus/nodewarden/commit/0cef6a0), [00e0ec0](https://github.com/shuaiplus/nodewarden/commit/00e0ec0), [5c8f01b](https://github.com/shuaiplus/nodewarden/commit/5c8f01b), [cc4a830](https://github.com/shuaiplus/nodewarden/commit/cc4a830), [f532d3a](https://github.com/shuaiplus/nodewarden/commit/f532d3a), [a366acb](https://github.com/shuaiplus/nodewarden/commit/a366acb).

1. **Import compatibility and encrypted-field validation.** Imports now validate payload structure and ZIP entries before processing, and plaintext FIDO2 credential, SSH key, and password-history fields are rejected instead of being silently accepted and later dropped. This makes failed imports clearer and protects encrypted vault fields from incompatible plaintext data. Commits: [cf14704](https://github.com/shuaiplus/nodewarden/commit/cf14704), [1ec6ed4](https://github.com/shuaiplus/nodewarden/commit/1ec6ed4).

1. **Admin, audit, WebAuthn, and backup endpoint edge cases.** Admin audit-clears are recorded, passkey 2FA status is reported correctly, WebAuthn extension origins are constrained, and auth-request plus backup endpoint checks were tightened around sensitive flows. Commits: [d028b19](https://github.com/shuaiplus/nodewarden/commit/d028b19), [ace00e8](https://github.com/shuaiplus/nodewarden/commit/ace00e8), [7ac6ae5](https://github.com/shuaiplus/nodewarden/commit/7ac6ae5).

---

### 新增

1. **YubiKey OTP 和通行密钥两步登录。** NodeWarden 现在支持将 YubiKey OTP 作为可管理的双因素提供商，并新增基于通行密钥的双因素认证，包含设置界面、WebAuthn 备用连接器处理、多提供商登录提示，以及更安全的 WebAuthn 响应规范化。提交：[f63b745](https://github.com/shuaiplus/nodewarden/commit/f63b745)、[c019c93](https://github.com/shuaiplus/nodewarden/commit/c019c93)、[e73ae3d](https://github.com/shuaiplus/nodewarden/commit/e73ae3d)、[d8cc88d](https://github.com/shuaiplus/nodewarden/commit/d8cc88d)。

1. **Bitwarden 扩展保险库条目类型。** 除现有登录、银行卡、身份、安全笔记和 SSH 密钥流程外，保险库条目现在还覆盖银行账户、驾驶证和护照。Web 保险库可以创建、展示、解密、导入和导出这些条目类型，并提供更清晰的侧边栏图标。提交：[109593d](https://github.com/shuaiplus/nodewarden/commit/109593d)、[9de0d3b](https://github.com/shuaiplus/nodewarden/commit/9de0d3b)。

1. **更多 Bitwarden 客户端兼容端点。** 新增设备验证设置、设备注册路由、管理员认证请求兼容、fill-assist 对齐和推送中继安装处理，让更多官方 Bitwarden 客户端流程能获得预期响应。不支持的邮箱验证和 KDF 路由现在会返回明确的不支持响应，而不是含糊失败。提交：[e376a84](https://github.com/shuaiplus/nodewarden/commit/e376a84)、[8b2f98b](https://github.com/shuaiplus/nodewarden/commit/8b2f98b)、[f0e5233](https://github.com/shuaiplus/nodewarden/commit/f0e5233)、[56b301f](https://github.com/shuaiplus/nodewarden/commit/56b301f)、[fd46dff](https://github.com/shuaiplus/nodewarden/commit/fd46dff)、[cde4555](https://github.com/shuaiplus/nodewarden/commit/cde4555)。

### 改进

1. **TOTP 二维码扫描和 Bitwarden 兼容 TOTP 行为。** 上传 TOTP 二维码时，如果浏览器 `BarcodeDetector` 支持不完整，现在会回退到 `jsQR`，并正确处理透明 PNG、校验上传的二维码图片、限制摄像头回退解码频率以降低 CPU 占用。TOTP 的存储和解密行为也更贴近 Bitwarden 客户端。提交：[b0a679b](https://github.com/shuaiplus/nodewarden/commit/b0a679b)、[d024798](https://github.com/shuaiplus/nodewarden/commit/d024798)、[73bbe8b](https://github.com/shuaiplus/nodewarden/commit/73bbe8b)、[6e72220](https://github.com/shuaiplus/nodewarden/commit/6e72220)、[8a5b210](https://github.com/shuaiplus/nodewarden/commit/8a5b210)。

1. **设置、设备管理和本地化打磨。** 设备管理现在整合进设置页并更新了导航，两步验证提供商界面在响应式布局下更顺手，新的设置、审计日志和校验消息也补齐了受支持语言的本地化。安全设置区域在桌面和移动端都更容易浏览。提交：[c7eb6c6](https://github.com/shuaiplus/nodewarden/commit/c7eb6c6)、[062c966](https://github.com/shuaiplus/nodewarden/commit/062c966)、[12af18e](https://github.com/shuaiplus/nodewarden/commit/12af18e)、[c53d71f](https://github.com/shuaiplus/nodewarden/commit/c53d71f)、[01ff627](https://github.com/shuaiplus/nodewarden/commit/01ff627)。

1. **加密 Send 的密码状态展示与编辑。** 受密码保护的 Send 现在会在列表中显示锁定标记，编辑已有受保护 Send 时会显示密码掩码圆点，并提供紧凑的垃圾桶图标用于移除已保存密码。这样可以看清密码状态，同时不暴露密码本身。提交：[a870142](https://github.com/shuaiplus/nodewarden/commit/a870142)、[ebc8e8e](https://github.com/shuaiplus/nodewarden/commit/ebc8e8e)。

1. **网站图标行为和工作流维护。** 网站图标现在无需旧的 `WEBSITE_ICONS_ENABLED` 环境开关即可始终可用，同时图标请求仍保留隐私保护。global-domains 同步工作流也会在运行前校验引用。提交：[57c5ef9](https://github.com/shuaiplus/nodewarden/commit/57c5ef9)、[c643874](https://github.com/shuaiplus/nodewarden/commit/c643874)、[680e287](https://github.com/shuaiplus/nodewarden/commit/680e287)。

### 修复

1. **认证、令牌和速率限制加固。** API key 现在以哈希形式存储，密码轮换和 JWT 处理更严格，令牌处理时会使用户缓存失效，错误密码不会丢失已记住的 2FA token，当前访问令牌会被正确撤销，并关闭了已知的速率限制重置绕过路径。提交：[1545881](https://github.com/shuaiplus/nodewarden/commit/1545881)、[439683d](https://github.com/shuaiplus/nodewarden/commit/439683d)、[60dd298](https://github.com/shuaiplus/nodewarden/commit/60dd298)、[d9a36fe](https://github.com/shuaiplus/nodewarden/commit/d9a36fe)、[1bad32f](https://github.com/shuaiplus/nodewarden/commit/1bad32f)、[2df43cc](https://github.com/shuaiplus/nodewarden/commit/2df43cc)、[ae168be](https://github.com/shuaiplus/nodewarden/commit/ae168be)。

1. **用户数据隔离和请求校验。** 存储读取现在按用户限定范围，Send 文件路由更严格地拦截访问，匿名通知 hub 请求会被校验，并且多段备份/上传请求增加了上限。这降低了跨用户数据读取或超大请求进入深层处理器的风险。提交：[baf5699](https://github.com/shuaiplus/nodewarden/commit/baf5699)、[8c481a1](https://github.com/shuaiplus/nodewarden/commit/8c481a1)、[23c53bd](https://github.com/shuaiplus/nodewarden/commit/23c53bd)、[5142846](https://github.com/shuaiplus/nodewarden/commit/5142846)。

1. **备份、恢复和下载安全性。** 远端备份删除现在会被验证，归档和备份 blob 使用前会校验，目标配置里的密钥会在设置响应中脱敏，备份/下载令牌流程更难被误用，WebAuthn 凭据用途也会在备份导出/导入中保留。备份上传器的重定向防护也已回退，以恢复兼容的远端行为。提交：[0cef6a0](https://github.com/shuaiplus/nodewarden/commit/0cef6a0)、[00e0ec0](https://github.com/shuaiplus/nodewarden/commit/00e0ec0)、[5c8f01b](https://github.com/shuaiplus/nodewarden/commit/5c8f01b)、[cc4a830](https://github.com/shuaiplus/nodewarden/commit/cc4a830)、[f532d3a](https://github.com/shuaiplus/nodewarden/commit/f532d3a)、[a366acb](https://github.com/shuaiplus/nodewarden/commit/a366acb)。

1. **导入兼容性和加密字段校验。** 导入流程现在会在处理前校验 payload 结构和 ZIP 条目，明文 FIDO2 凭据、SSH 密钥和密码历史字段会被拒绝，而不是先被静默接受再在响应时丢弃。这让失败导入更清楚，也保护加密保险库字段不接收不兼容的明文数据。提交：[cf14704](https://github.com/shuaiplus/nodewarden/commit/cf14704)、[1ec6ed4](https://github.com/shuaiplus/nodewarden/commit/1ec6ed4)。

1. **管理员、审计、WebAuthn 和备份端点边界情况。** 管理员清空审计日志会被记录，通行密钥 2FA 状态会正确上报，WebAuthn 扩展来源会受到限制，并且认证请求与备份端点围绕敏感流程的校验也更严格。提交：[d028b19](https://github.com/shuaiplus/nodewarden/commit/d028b19)、[ace00e8](https://github.com/shuaiplus/nodewarden/commit/ace00e8)、[7ac6ae5](https://github.com/shuaiplus/nodewarden/commit/7ac6ae5)。

---

# v1.7.2 - New Backup Providers, WebAuthn PRF, and UI Polish

### Added

1. **Three new S3-compatible backup providers: Backblaze B2, Cloudflare R2, and Tigris.** Each new destination comes with detailed provider-specific recommendations, storage-class guidance, and localization strings across all five supported languages. You can now back up to more services without custom scripting. Commits: [1acc31e](https://github.com/shuaiplus/nodewarden/commit/1acc31e), [c3dc53b](https://github.com/shuaiplus/nodewarden/commit/c3dc53b), [ff85698](https://github.com/shuaiplus/nodewarden/commit/ff85698).

2. **WebAuthn PRF (pseudorandom function) extension support.** Credential creation and assertion now pass browser-compatible PRF extension requests, support excluding PRF extensions where the client doesn't need them, and handle the underlying passkey operations more robustly. This improves WebAuthn compatibility with modern browsers and password managers that rely on PRF for per-credential keys. Commits: [8942e5b](https://github.com/shuaiplus/nodewarden/commit/8942e5b), [31cfd19](https://github.com/shuaiplus/nodewarden/commit/31cfd19), [6a1a835](https://github.com/shuaiplus/nodewarden/commit/6a1a835), [bf6ac7b](https://github.com/shuaiplus/nodewarden/commit/bf6ac7b).

3. **Backup import locking and checksum verification.** Restoring a full backup now acquires an exclusive lock so concurrent imports cannot collide, and the importer verifies file checksums before applying the data. This makes disaster recovery safer when multiple admins might trigger restores. Commit: [e9272ec](https://github.com/shuaiplus/nodewarden/commit/e9272ec).

4. **Fullscreen layout toggle.** The web vault can now switch to fullscreen mode with a dedicated toggle button, with corresponding localization updates. Useful for kiosk-mode or presentation setups. Commit: [d722815](https://github.com/shuaiplus/nodewarden/commit/d722815).

5. **Fill-assist API handlers.** NodeWarden now implements Bitwarden-compatible credential fill-assist endpoints, letting clients fetch credentials inline via the new `POST /fill-assist` route. Device response types are also updated to include the fields needed by the fill-assist flow. Commit: [e4215b4](https://github.com/shuaiplus/nodewarden/commit/e4215b4).

6. **Device selection and removal in SecurityDevicesPage.** The security devices panel now supports selecting individual trusted devices and removing them directly from the web UI, so you no longer need to use the API to revoke a specific device. Commit: [a5ad16a](https://github.com/shuaiplus/nodewarden/commit/a5ad16a).

7. **Delete invalid organization invitations.** Admins can now detect and remove dangling or invalid invitations from the admin panel, helping keep the invitation list clean. The API also renamed `revokeInvite` to `deleteInvite` for clearer semantics. Commits: [0d1bb19](https://github.com/shuaiplus/nodewarden/commit/0d1bb19), [f82dcc3](https://github.com/shuaiplus/nodewarden/commit/f82dcc3).

8. **validFolderIds support in cipher responses.** Sync and cipher responses now include a `validFolderIds` field so clients can distinguish real folders from orphaned references. The folder repository also validates folder existence more strictly. Commit: [82f968e](https://github.com/shuaiplus/nodewarden/commit/82f968e).

9. **Pending auth request loading state.** The pending login-request panel shows a refreshing indicator while fetching or updating the request list, providing clearer feedback during auth request workflows. Commit: [4378e1b](https://github.com/shuaiplus/nodewarden/commit/4378e1b).

### Improved

1. **Enhanced Bitwarden CSV import with custom field and multiline support.** The CSV parser now recognizes custom fields and restores their metadata correctly during import. It also preserves multiline values such as SSH private keys—previously, any line without a `: ` delimiter was silently dropped, truncating private keys to the first line. Text fields containing newlines now survive a full export-import round-trip. Commits: [5eeaf4e](https://github.com/shuaiplus/nodewarden/commit/5eeaf4e), [68c42a0](https://github.com/shuaiplus/nodewarden/commit/68c42a0).

2. **Consolidated security devices UI.** Device management and authorized devices sections are merged into a single coherent card on SecurityDevicesPage, and the pending-auth-requests panel has been removed from the general SettingsPage to reduce clutter. The device list also includes improved selection controls. Commit: [c694f1b](https://github.com/shuaiplus/nodewarden/commit/c694f1b).

3. **Refined app-shell styles and dark mode consistency.** Removed redundant global styles, cleaned up shell component spacing, and improved dark-mode visual consistency across the header, sidebar, and main content areas. Commit: [1bfb9a6](https://github.com/shuaiplus/nodewarden/commit/1bfb9a6).

4. **Backup and restore error messages across all locales.** New error strings for backup/restore edge cases—lock failures, checksum mismatches, missing files—are now localized in all five supported languages (en, es, ru, zh-CN, zh-TW), with improved UI prompts for backup browser refresh scenarios. Commit: [4cd9ad0](https://github.com/shuaiplus/nodewarden/commit/4cd9ad0).

5. **Updated project wiki link and removed obsolete security scripts.** The issue-template wiki link now points to the correct URL, and the old local security scanning scripts and workflows have been removed in favor of GitHub-native security automation (CodeQL, security-extra workflows). Commit: [e31f82c](https://github.com/shuaiplus/nodewarden/commit/e31f82c).

6. **Security automation and dependency hardening.** Added GitHub-native CodeQL and security-extra workflows, overrode a `ws` vulnerability, and upgraded CI actions to pinned major versions (checkout v7, setup-node v6, create-pull-request v8). Dependencies refreshed include TypeScript 6.0, `@types/node` 26, `lucide-preact` 1.x, and many others across npm and GitHub Actions. Commits: [64f26e7](https://github.com/shuaiplus/nodewarden/commit/64f26e7), [32b3d2a](https://github.com/shuaiplus/nodewarden/commit/32b3d2a), [5dd9dff](https://github.com/shuaiplus/nodewarden/commit/5dd9dff), [8d292ca](https://github.com/shuaiplus/nodewarden/commit/8d292ca), [5bd7dab](https://github.com/shuaiplus/nodewarden/commit/5bd7dab), [99f2d7f](https://github.com/shuaiplus/nodewarden/commit/99f2d7f), [fb9a2ae](https://github.com/shuaiplus/nodewarden/commit/fb9a2ae), [c87e6ac](https://github.com/shuaiplus/nodewarden/commit/c87e6ac).

### Fixed

1. **CSV import truncating multiline field values.** `parseBitwardenCsvFieldLines` previously discarded any line that did not contain a `: ` delimiter, silently dropping SSH private keys and other multiline content to only the first line. The parser now accumulates continuation lines correctly, restoring full private key content through a CSV round-trip. Commit: [68c42a0](https://github.com/shuaiplus/nodewarden/commit/68c42a0).

---

### 新增

1. **三个新的 S3 兼容备份提供商：Backblaze B2、Cloudflare R2 和 Tigris。** 每个新目标都带有详细的提供商建议、存储层级指导和五种语言的本地化字符串，无需额外脚本即可将备份扩展到更多存储服务。提交：[1acc31e](https://github.com/shuaiplus/nodewarden/commit/1acc31e)、[c3dc53b](https://github.com/shuaiplus/nodewarden/commit/c3dc53b)、[ff85698](https://github.com/shuaiplus/nodewarden/commit/ff85698)。

2. **WebAuthn PRF（伪随机函数）扩展支持。** 创建和断言凭证时会传递浏览器兼容的 PRF 扩展请求，支持在不需要时排除 PRF 扩展，并且底层密钥操作更健壮。这改善了与依赖 PRF 做每凭据密钥派生功能的现代浏览器和密码管理器的兼容性。提交：[8942e5b](https://github.com/shuaiplus/nodewarden/commit/8942e5b)、[31cfd19](https://github.com/shuaiplus/nodewarden/commit/31cfd19)、[6a1a835](https://github.com/shuaiplus/nodewarden/commit/6a1a835)、[bf6ac7b](https://github.com/shuaiplus/nodewarden/commit/bf6ac7b)。

3. **备份导入加锁和校验和验证。** 完整恢复备份时现在会获取独占锁，防止并发导入冲突；导入前还会验证文件校验和再应用数据。多管理员可能同时触发恢复时，该机制让灾难恢复更加安全。提交：[e9272ec](https://github.com/shuaiplus/nodewarden/commit/e9272ec)。

4. **全屏布局切换。** Web 保险库现在可以通过专用按钮切换全屏模式，附带对应本地化更新。适合信息亭模式或展示等场景。提交：[d722815](https://github.com/shuaiplus/nodewarden/commit/d722815)。

5. **Fill-assist API 处理器。** NodeWarden 现在实现了与 Bitwarden 兼容的凭据填充辅助端点，客户端可以通过新的 `POST /fill-assist` 路由内联获取凭据。设备响应类型也补上了 fill-assist 流程需要的字段。提交：[e4215b4](https://github.com/shuaiplus/nodewarden/commit/e4215b4)。

6. **安全设备页的设备选择与删除。** 设备面板现在支持在 Web UI 中直接选择单个可信设备并移除，无需通过 API 手动撤销指定设备。提交：[a5ad16a](https://github.com/shuaiplus/nodewarden/commit/a5ad16a)。

7. **删除无效邀请码。** 管理员现在可以在管理面板中检测并删除悬空或无效的邀请，保持邀请列表整洁。API 也将 `revokeInvite` 改名为 `deleteInvite`，语义更清晰。提交：[0d1bb19](https://github.com/shuaiplus/nodewarden/commit/0d1bb19)、[f82dcc3](https://github.com/shuaiplus/nodewarden/commit/f82dcc3)。

8. **密码条目响应增加 validFolderIds。** 同步和密码条目响应现在包含 `validFolderIds` 字段，方便客户端区分真实文件夹和孤立引用；文件夹存储也加强了对文件夹存在性的校验。提交：[82f968e](https://github.com/shuaiplus/nodewarden/commit/82f968e)。

9. **待处理认证请求的加载状态。** 待处理的登录请求面板现在会在获取或更新请求列表时显示刷新指示器，为认证请求操作提供更清晰的反馈。提交：[4378e1b](https://github.com/shuaiplus/nodewarden/commit/4378e1b)。

### 改进

1. **增强的 Bitwarden CSV 导入——自定义字段和多行支持。** CSV 解析器现在可以识别自定义字段并在导入时正确恢复其元数据。同时保留了 SSH 私钥等多行值——之前任何不带 `: ` 分隔符的行都会被丢弃，导致私钥只保留第一行。包含换行符的文本字段现在可以完整通过导出-导入周期。提交：[5eeaf4e](https://github.com/shuaiplus/nodewarden/commit/5eeaf4e)、[68c42a0](https://github.com/shuaiplus/nodewarden/commit/68c42a0)。

2. **整合安全设备界面。** 设备管理和已授权设备两个部分合并为 SecurityDevicesPage 上的一个统一卡片；待处理认证请求面板从 SettingsPage 中移除以减少杂乱。设备列表也改进了选择操作。提交：[c694f1b](https://github.com/shuaiplus/nodewarden/commit/c694f1b)。

3. **精简应用外壳样式与暗色模式一致性。** 移除了冗余全局样式，清理了外壳组件间距，改善了头部、侧边栏和主内容区在暗色模式下的视觉一致性。提交：[1bfb9a6](https://github.com/shuaiplus/nodewarden/commit/1bfb9a6)。

4. **备份/恢复错误消息全语言本地化。** 备份/恢复边界场景（加锁失败、校验和不匹配、文件缺失）的新错误字符串已在五种支持语言（en、es、ru、zh-CN、zh-TW）中完成本地化，同时改进了备份浏览器刷新场景下的界面提示。提交：[4cd9ad0](https://github.com/shuaiplus/nodewarden/commit/4cd9ad0)。

5. **更新项目 Wiki 链接并移除过时安全脚本。** 议题模板中的 Wiki 链接已指向正确 URL；老旧的本地安全扫描脚本和工作流已移除，改用 GitHub 原生安全自动化（CodeQL、security-extra 工作流）。提交：[e31f82c](https://github.com/shuaiplus/nodewarden/commit/e31f82c)。

6. **安全自动化和依赖加固。** 新增 GitHub 原生 CodeQL 和 security-extra 工作流；覆盖了 `ws` 的已知漏洞；将 CI Action 升级到钉死的主要版本（checkout v7、setup-node v6、create-pull-request v8）。依赖升级包括 TypeScript 6.0、`@types/node` 26、`lucide-preact` 1.x，以及 npm 和 GitHub Actions 的多项更新。提交：[64f26e7](https://github.com/shuaiplus/nodewarden/commit/64f26e7)、[32b3d2a](https://github.com/shuaiplus/nodewarden/commit/32b3d2a)、[5dd9dff](https://github.com/shuaiplus/nodewarden/commit/5dd9dff)、[8d292ca](https://github.com/shuaiplus/nodewarden/commit/8d292ca)、[5bd7dab](https://github.com/shuaiplus/nodewarden/commit/5bd7dab)、[99f2d7f](https://github.com/shuaiplus/nodewarden/commit/99f2d7f)、[fb9a2ae](https://github.com/shuaiplus/nodewarden/commit/fb9a2ae)、[c87e6ac](https://github.com/shuaiplus/nodewarden/commit/c87e6ac)。

### 修复

1. **CSV 导入截断多行字段值。** `parseBitwardenCsvFieldLines` 之前会丢弃任何不包含 `: ` 分隔符的行，导致 SSH 私钥等多行内容被静默截断为仅第一行。解析器现已正确累积后续行，使私钥等完整内容能够通过 CSV 导出-导入周期完好保留。提交：[68c42a0](https://github.com/shuaiplus/nodewarden/commit/68c42a0)。

# v1.7.1 - Security Hardening Update

Thanks to GN998 for responsibly reporting security issues addressed in this release.

### Added

1. **No new user-facing features.** This patch release intentionally focuses on security fixes and defensive hardening rather than new product functionality. Commits: [7279668](https://github.com/shuaiplus/nodewarden/commit/7279668), [850fe0f](https://github.com/shuaiplus/nodewarden/commit/850fe0f), [a2a8f1c](https://github.com/shuaiplus/nodewarden/commit/a2a8f1c), [23b23f3](https://github.com/shuaiplus/nodewarden/commit/23b23f3).

### Improved

1. **Stronger security defaults.** NodeWarden now applies more conservative handling around sensitive authentication, backup, and file-delivery flows while keeping existing clients compatible. Upgrade is recommended for all deployments. Commits: [7279668](https://github.com/shuaiplus/nodewarden/commit/7279668), [850fe0f](https://github.com/shuaiplus/nodewarden/commit/850fe0f), [a2a8f1c](https://github.com/shuaiplus/nodewarden/commit/a2a8f1c), [23b23f3](https://github.com/shuaiplus/nodewarden/commit/23b23f3).

### Fixed

1. **High-priority security fixes.** This release closes multiple reported security issues across sensitive server-side flows and response hardening without exposing operational details in the public notes. Commits: [7279668](https://github.com/shuaiplus/nodewarden/commit/7279668), [850fe0f](https://github.com/shuaiplus/nodewarden/commit/850fe0f), [a2a8f1c](https://github.com/shuaiplus/nodewarden/commit/a2a8f1c), [23b23f3](https://github.com/shuaiplus/nodewarden/commit/23b23f3).

2. **Security dependency overrides.** Package overrides were added for selected transitive dependencies so installs resolve to patched versions where applicable. Commit: [0daad46](https://github.com/shuaiplus/nodewarden/commit/0daad46).

---

### 新增

感谢 GN998 负责任地报告了本次发布中修复的安全问题。

1. **没有新增面向用户的功能。** 本次补丁发布刻意专注于安全修复和防护加固，不包含新的产品功能。提交：[7279668](https://github.com/shuaiplus/nodewarden/commit/7279668)、[850fe0f](https://github.com/shuaiplus/nodewarden/commit/850fe0f)、[a2a8f1c](https://github.com/shuaiplus/nodewarden/commit/a2a8f1c)、[23b23f3](https://github.com/shuaiplus/nodewarden/commit/23b23f3)。

### 改进

1. **更稳妥的安全默认行为。** NodeWarden 对敏感认证、备份和文件响应流程采用了更保守的处理方式，同时保持现有客户端兼容。建议所有部署尽快升级。提交：[7279668](https://github.com/shuaiplus/nodewarden/commit/7279668)、[850fe0f](https://github.com/shuaiplus/nodewarden/commit/850fe0f)、[a2a8f1c](https://github.com/shuaiplus/nodewarden/commit/a2a8f1c)、[23b23f3](https://github.com/shuaiplus/nodewarden/commit/23b23f3)。

### 修复

1. **高优先级安全修复。** 本次发布修复了多项已报告的安全问题，覆盖敏感服务端流程和响应加固；公开说明中不会展开可操作的攻击细节。提交：[7279668](https://github.com/shuaiplus/nodewarden/commit/7279668)、[850fe0f](https://github.com/shuaiplus/nodewarden/commit/850fe0f)、[a2a8f1c](https://github.com/shuaiplus/nodewarden/commit/a2a8f1c)、[23b23f3](https://github.com/shuaiplus/nodewarden/commit/23b23f3)。

2. **安全依赖覆盖。** 为部分传递依赖添加了版本覆盖，让安装时尽可能解析到已修复版本。提交：[0daad46](https://github.com/shuaiplus/nodewarden/commit/0daad46)。

# v1.7.0 - Faster Multi-Device Sync, Mobile Push, and a Smoother Vault


### Added

1. **Resource-level realtime sync.** NodeWarden now sends Bitwarden-style notifications for cipher, folder, and Send create, update, and delete events. The web app can refresh only the affected resource instead of reloading the full vault every time, and state-changing operations such as attachment uploads, attachment deletes, public Send access counts, and Send file downloads also emit the right updates. Commits: [fe0c66c](https://github.com/shuaiplus/nodewarden/commit/fe0c66c), [42b765b](https://github.com/shuaiplus/nodewarden/commit/42b765b), [045b23f](https://github.com/shuaiplus/nodewarden/commit/045b23f), [46ba8b9](https://github.com/shuaiplus/nodewarden/commit/46ba8b9), [f096681](https://github.com/shuaiplus/nodewarden/commit/f096681).

2. **Bitwarden mobile push relay support.** Devices can now store `push_uuid` and `push_token`, register or unregister through the Bitwarden push relay, and receive mobile push notifications when vault resources change. The database schema includes the new push fields and indexes needed to detect push-capable devices. Commit: [79ed7c9](https://github.com/shuaiplus/nodewarden/commit/79ed7c9).

3. **Bitwarden CSV export.** The web app can now export a Bitwarden-compatible CSV file alongside the existing JSON, encrypted JSON, and attachment ZIP formats. Multiple login URIs are serialized safely, and non-login item types such as cards, identities, and SSH keys are preserved as clearly as possible in field text. Commits: [b024226](https://github.com/shuaiplus/nodewarden/commit/b024226), [a06cb0e](https://github.com/shuaiplus/nodewarden/commit/a06cb0e).

4. **More duplicate detection modes.** Duplicate search can now compare exact item content, login site plus credentials, username plus password, or password alone. Duplicate groups are color-coded, and the mobile vault UI includes the new duplicate mode selector and improved filter controls. Commits: [7b3be2c](https://github.com/shuaiplus/nodewarden/commit/7b3be2c), [b444c0f](https://github.com/shuaiplus/nodewarden/commit/b444c0f).

5. **S3 addressing style selection.** Backup destinations can now choose between path-style and virtual-hosted-style S3 URLs, improving compatibility with more S3-compatible providers and self-hosted object storage. Commit: [a818316](https://github.com/shuaiplus/nodewarden/commit/a818316).

### Improved

1. **Web vault updates feel immediate.** Creating, editing, deleting, archiving, restoring, and moving items; creating or deleting folders; and creating, updating, or deleting Sends now update the local encrypted snapshot, decrypted lists, and revision timestamp directly. This reduces visible lag after successful actions and makes cached vault validation work better with resource-level sync. Commits: [42b765b](https://github.com/shuaiplus/nodewarden/commit/42b765b), [045b23f](https://github.com/shuaiplus/nodewarden/commit/045b23f).

2. **Better Bitwarden client compatibility.** Profile and sync responses now include fields such as `organizationsNew`, `policiesNew`, and `V2UpgradeToken`; `/api/accounts/keys` supports GET; password change and password verification accept newer `authenticationData` and `unlockData` request shapes; and device routes work with both `/api/devices` and `/devices`. Cipher responses also preserve stored `edit`, `viewPassword`, and `permissions` flags instead of resetting them. Commits: [add921b](https://github.com/shuaiplus/nodewarden/commit/add921b), [f9fe532](https://github.com/shuaiplus/nodewarden/commit/f9fe532).

3. **Cleaner mobile and narrow-screen UI.** Topbar controls, network status, theme switching, and lock buttons now share more consistent sizing and styling. The vault list search, sorting, filtering, create button, and bulk selection toolbar are more compact on mobile, and mobile filter menus can switch between all items, favorites, archive, trash, duplicates, types, and folders. Commits: [7e0406f](https://github.com/shuaiplus/nodewarden/commit/7e0406f), [16bde22](https://github.com/shuaiplus/nodewarden/commit/16bde22), [cd2ec82](https://github.com/shuaiplus/nodewarden/commit/cd2ec82), [c1f5795](https://github.com/shuaiplus/nodewarden/commit/c1f5795).

4. **More tolerant TOTP handling.** TOTP codes are grouped more naturally for 5-digit, 6-digit, 8-digit, and other lengths, and the TOTP list no longer overflows narrow screens because of fixed column widths. `otpauth://` parsing is also more tolerant of unusual parameter encoding, with more stable Steam-code detection. Commits: [9e0908f](https://github.com/shuaiplus/nodewarden/commit/9e0908f), [d5c2ab2](https://github.com/shuaiplus/nodewarden/commit/d5c2ab2).

5. **Less jumpy network status.** The web app no longer switches offline after one short failed probe. It uses a longer timeout, waits for repeated failures, and lets normal API successes or failures update the network state, reducing false offline unlock fallbacks when the service is reachable but slow. Commit: [b4dfb04](https://github.com/shuaiplus/nodewarden/commit/b4dfb04).

6. **More complete backups.** Full instance backups now include trusted two-factor device tokens and restore them during import. The importer validates token ownership, device identifiers, expiration times, and duplicates, so remembered two-factor devices can survive a full migration. Commit: [f6169b7](https://github.com/shuaiplus/nodewarden/commit/f6169b7).

### Fixed

1. **Realtime notification correctness.** Resource notification type numbers now match Bitwarden semantics, while NodeWarden-specific device status and backup progress notifications use internal values to avoid conflicts with official Send update types. SignalR MessagePack invocations now include `streamIds`, pending auth request notifications refresh the login request list, and the web app ignores notifications sent by the current device to avoid redundant refreshes. Commits: [fe0c66c](https://github.com/shuaiplus/nodewarden/commit/fe0c66c), [9a21504](https://github.com/shuaiplus/nodewarden/commit/9a21504), [4900de0](https://github.com/shuaiplus/nodewarden/commit/4900de0).

2. **Attachment and Send download details.** Public attachment and Send file downloads now include `Content-Disposition` filenames and `X-Content-Type-Options: nosniff`, making browser downloads keep better filenames and reducing content sniffing issues. Attachment delete responses now include both uppercase and lowercase field forms for broader client compatibility. Commit: [add921b](https://github.com/shuaiplus/nodewarden/commit/add921b).

3. **Deleted item and bulk action edge cases.** Vault paging now detects deleted items from both database columns and older JSON payload fields, preventing old deleted items from appearing in the normal vault list. Bulk archive skips deleted items, and duplicate detection now uses decrypted password history instead of encrypted stored text. Commits: [add921b](https://github.com/shuaiplus/nodewarden/commit/add921b), [b444c0f](https://github.com/shuaiplus/nodewarden/commit/b444c0f).

4. **Export, dialog, and toast polish.** CSV export now escapes login URIs correctly inside a single CSV cell; some dialog dismissal behavior is more stable; login and unlock success toasts are less noisy; and the toast close button now uses a styled SVG icon. Commits: [b024226](https://github.com/shuaiplus/nodewarden/commit/b024226), [a06cb0e](https://github.com/shuaiplus/nodewarden/commit/a06cb0e), [8f2704f](https://github.com/shuaiplus/nodewarden/commit/8f2704f), [907126d](https://github.com/shuaiplus/nodewarden/commit/907126d).

5. **S3 backup URL construction.** Virtual-hosted-style backup operations now use the `bucket.endpoint` form for upload, download, delete, and existence checks, while avoiding duplicate bucket names when the endpoint already includes the bucket. Path-style mode keeps the existing `endpoint/bucket` behavior. Commit: [a818316](https://github.com/shuaiplus/nodewarden/commit/a818316).

---

### 新增

1. **资源级实时同步。** NodeWarden 现在会按 Bitwarden 风格发送密码条目、文件夹、Send 的新增、更新和删除通知。Web 端收到通知后可以只刷新受影响的资源，而不是每次都重新同步整个保险库；附件上传、附件删除、公开 Send 访问计数、Send 文件下载等会改变状态的操作，也会触发对应更新。提交：[fe0c66c](https://github.com/shuaiplus/nodewarden/commit/fe0c66c)、[42b765b](https://github.com/shuaiplus/nodewarden/commit/42b765b)、[045b23f](https://github.com/shuaiplus/nodewarden/commit/045b23f)、[46ba8b9](https://github.com/shuaiplus/nodewarden/commit/46ba8b9)、[f096681](https://github.com/shuaiplus/nodewarden/commit/f096681)。

2. **Bitwarden 移动端推送中继支持。** 设备现在可以保存 `push_uuid` 和 `push_token`，通过 Bitwarden push relay 注册或注销，并在保险库资源变化时尝试接收移动端推送。数据库结构也补上了推送字段和索引，用于识别哪些设备可以被推送。提交：[79ed7c9](https://github.com/shuaiplus/nodewarden/commit/79ed7c9)。

3. **Bitwarden CSV 导出。** 除了原有 JSON、加密 JSON 和带附件 ZIP 导出，现在 Web 端可以直接导出 Bitwarden 兼容 CSV。多个登录 URI 会按 CSV 规则安全序列化，卡片、身份、SSH Key 等非登录类型也会尽量保留到字段文本中，方便迁移或人工整理。提交：[b024226](https://github.com/shuaiplus/nodewarden/commit/b024226)、[a06cb0e](https://github.com/shuaiplus/nodewarden/commit/a06cb0e)。

4. **更多重复项检测模式。** 重复项现在可以按完全一致、登录站点加凭据、用户名加密码、单独密码等方式判断。重复组会用颜色辅助区分，移动端保险库也补上了重复项模式选择和更完整的筛选入口。提交：[7b3be2c](https://github.com/shuaiplus/nodewarden/commit/7b3be2c)、[b444c0f](https://github.com/shuaiplus/nodewarden/commit/b444c0f)。

5. **S3 地址样式选择。** 远程备份目标现在可以选择 path-style 或 virtual-hosted-style，兼容更多 S3 服务和自建对象存储。提交：[a818316](https://github.com/shuaiplus/nodewarden/commit/a818316)。

### 改进

1. **Web 保险库操作反馈更及时。** 创建、编辑、删除、归档、恢复、移动条目，创建或删除文件夹，以及创建、更新、删除 Send 时，前端会直接更新本地加密快照、解密列表和修订时间。这样操作成功后列表更快跟上，也让资源级同步下的本地缓存校验更稳定。提交：[42b765b](https://github.com/shuaiplus/nodewarden/commit/42b765b)、[045b23f](https://github.com/shuaiplus/nodewarden/commit/045b23f)。

2. **Bitwarden 客户端兼容性更好。** 账户资料和同步响应补齐了 `organizationsNew`、`policiesNew`、`V2UpgradeToken` 等字段；`/api/accounts/keys` 支持 GET；改密和校验密码接口兼容较新的 `authenticationData`、`unlockData` 请求结构；设备路由同时兼容 `/api/devices` 和 `/devices`。密码条目响应也会保留已存储的 `edit`、`viewPassword` 和 `permissions`，避免跨客户端编辑时权限标记被重置。提交：[add921b](https://github.com/shuaiplus/nodewarden/commit/add921b)、[f9fe532](https://github.com/shuaiplus/nodewarden/commit/f9fe532)。

3. **移动端和小屏界面更顺手。** 顶部栏按钮、网络状态、主题切换、锁定按钮的尺寸和样式更统一。保险库列表里的搜索、排序、筛选、创建按钮和批量选择工具栏在移动端更紧凑；移动筛选菜单可以直接切换全部、收藏、归档、回收站、重复项、类型和文件夹。提交：[7e0406f](https://github.com/shuaiplus/nodewarden/commit/7e0406f)、[16bde22](https://github.com/shuaiplus/nodewarden/commit/16bde22)、[cd2ec82](https://github.com/shuaiplus/nodewarden/commit/cd2ec82)、[c1f5795](https://github.com/shuaiplus/nodewarden/commit/c1f5795)。

4. **TOTP 展示和解析更稳。** 验证码会按 5 位、6 位、8 位等不同长度更自然地分组，列表在窄屏下不会再被固定列宽撑破。`otpauth://` 解析也更能容忍特殊参数编码，Steam 类验证码识别更稳定。提交：[9e0908f](https://github.com/shuaiplus/nodewarden/commit/9e0908f)、[d5c2ab2](https://github.com/shuaiplus/nodewarden/commit/d5c2ab2)。

5. **网络状态不再过度敏感。** Web 端不会因为一次短暂探测失败就立刻判定离线，而是延长探测超时并等待连续失败；普通 API 请求成功或失败也会反向更新网络状态。在线但网络较慢时，不容易误进入离线解锁流程。提交：[b4dfb04](https://github.com/shuaiplus/nodewarden/commit/b4dfb04)。

6. **备份内容更完整。** 完整实例备份现在会导出和还原可信二步验证设备令牌。导入时会校验令牌所属用户、设备标识、过期时间和重复项，让“记住此设备”的二步验证状态在完整迁移后也能保留下来。提交：[f6169b7](https://github.com/shuaiplus/nodewarden/commit/f6169b7)。

### 修复

1. **实时通知类型和刷新逻辑。** 资源通知的类型编号调整为与 Bitwarden 官方语义一致，NodeWarden 自定义的设备状态和备份进度通知改用内部编号，避免和官方 Send 更新类型冲突。SignalR MessagePack 调用补齐了 `streamIds`，认证请求通知会刷新待处理登录请求列表，Web 端也会忽略当前设备自己发出的通知，避免重复刷新。提交：[fe0c66c](https://github.com/shuaiplus/nodewarden/commit/fe0c66c)、[9a21504](https://github.com/shuaiplus/nodewarden/commit/9a21504)、[4900de0](https://github.com/shuaiplus/nodewarden/commit/4900de0)。

2. **附件和 Send 文件下载细节。** 公开附件和 Send 文件下载现在会带上 `Content-Disposition` 文件名和 `X-Content-Type-Options: nosniff`，浏览器保存文件时更接近原文件名，也减少类型嗅探问题。删除附件的响应同时提供大小写两套字段，兼容不同客户端读取方式。提交：[add921b](https://github.com/shuaiplus/nodewarden/commit/add921b)。

3. **已删除条目和批量操作边界。** 保险库分页查询现在会同时识别数据库列和历史 JSON 数据里的删除时间，避免旧数据中已删除条目出现在正常列表。批量归档会跳过已删除条目，重复项判断也会使用已解密的密码历史，避免加密文本影响结果。提交：[add921b](https://github.com/shuaiplus/nodewarden/commit/add921b)、[b444c0f](https://github.com/shuaiplus/nodewarden/commit/b444c0f)。

4. **导出、弹窗和提示细节。** CSV 导出中的登录 URI 会按单行 CSV 单元格正确转义；部分弹窗关闭行为更稳定；登录或解锁成功后的 toast 更克制，避免重复提示；toast 关闭按钮换成了 SVG 图标并调整了样式。提交：[b024226](https://github.com/shuaiplus/nodewarden/commit/b024226)、[a06cb0e](https://github.com/shuaiplus/nodewarden/commit/a06cb0e)、[8f2704f](https://github.com/shuaiplus/nodewarden/commit/8f2704f)、[907126d](https://github.com/shuaiplus/nodewarden/commit/907126d)。

5. **S3 备份地址拼接。** 选择 virtual-hosted-style 时，备份上传、下载、删除和存在性检查会使用 `bucket.endpoint` 形式；如果 endpoint 已经带有 bucket，也不会重复拼接 bucket。path-style 仍保持原有 `endpoint/bucket` 形式。提交：[a818316](https://github.com/shuaiplus/nodewarden/commit/a818316)。
