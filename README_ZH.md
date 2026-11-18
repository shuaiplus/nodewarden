<p align="center">
  <img src="./NodeWarden.svg" alt="NodeWarden Logo" />
</p>

<p align="center">
  运行在 Cloudflare Workers 上的 Bitwarden 兼容服务端
</p>

<p align="center">
  <a href="https://workers.cloudflare.com/"><img src="https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white" alt="Powered by Cloudflare" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-LGPL--3.0-2ea44f" alt="License: LGPL-3.0" /></a>
  <a href="https://github.com/shuaiplus/NodeWarden/releases/latest"><img src="https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag" alt="Latest Release" /></a>

</p>

<p align="center">
  <a href="https://t.me/NodeWarden_News">Telegram 频道</a> |
  <a href="https://t.me/NodeWarden_Official">Telegram 群组</a>
</p>

<p align="center">
  <a href="./README.md">English</a> |
  <a href="./CONTRIBUTING.md">贡献指南</a> |
  <a href="https://nodewarden.app">官方wiki</a>
</p>

> **免责声明**  
> 本项目仅供学习与交流使用，请定期备份你的密码库。  
> 本项目与 Bitwarden 官方无关，请不要向 Bitwarden 官方反馈 NodeWarden 的问题。

---

## 与 Bitwarden 官方服务端能力对比

| 能力 | Bitwarden免费版 | NodeWarden | 说明 |
|---|---|---|---|
| 网页密码库 | ✅ | ✅ | **原创Web Vault界面** |
| TOTP | ❌ | ✅ | 包括 `steam://` 支持 |
| **PWA / 离线使用** | ❌ | ✅ | **可安装、离线使用、App快捷方式** |
| **Passkey 登录** | ✅ | ✅ | **支持WebAuthn/FIDO2无密码登录** |
| API 密钥 | ✅ | ✅ | 供bitwarden cli使用，支持获取和轮换 |
| 登录 2FA | ✅ | ✅ | 支持 TOTP、YubiKey、Passkey |
| 2FA 恢复码 | ✅ | ✅ | 一次性恢复码用于禁用 2FA |
| 实时推送同步 | ✅ | ✅ | 网页端、浏览器扩展、电脑端和手机端实时同步 |
| 附件 / Send| ✅ | ✅ | Cloudflare R2 或 KV |
| 导入 / 导出 | ✅ | ✅ | 支持 Bitwarden JSON / CSV / **ZIP 导入（包括附件）** |
| **云端备份中心** | ❌ | ✅ | **支持 WebDAV / S3 定时增量备份** |
| 设备管理 | ✅ | ✅ | **删除设备、撤销信任、永久信任** |
| 登录请求 | ✅ | ✅ | **多端免密登录审批、跨设备解锁请求** |
| **多用户使用** | ✅ | ✅ | 支持邀请码注册 |
| 域名规则 | ✅ | ✅ | 自定义等效域名、全局域名排除 |
| Fill-assist | ✅ | ✅ | `POST /fill-assist` 辅助客户端自动填充；不能绕过保险库解锁 |
| 组织 / 集合 / 成员权限 | ✅ | ❌ | 未实现 |
| SSO / SCIM / 企业目录 | ✅ | ❌ | 未实现 |

---

## 已测试客户端

- ✅ Windows 桌面端
- ✅ 手机 App
- ✅ 浏览器扩展
- ✅ Linux 桌面端
- ⚠️ macOS 桌面端尚未完整验证

---

## 可视化快速部署

1. Fork NodeWarden 仓库到自己的 GitHub 账号
2. 进入 [Cloudflare Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create)
3. 选择 Continue with GitHub 并选择你的仓库
4. 构建命令填 `npm run build`，部署命令填 `npm run deploy`
- 如果你打算用 KV 模式，把部署命令改成 `npm run deploy:kv`
5. 等部署完成后，打开生成的 Workers 域名

- Workers 默认域名在部分网络环境不可直连。如需自定义域名，到 [Workers 设置](https://dash.cloudflare.com/?to=/:account/workers/services/view/nodewarden/production/settings)里添加。

- 页面提示缺少 `JWT_SECRET` 时，到 Workers 设置里添加 Secret。正式环境至少使用 32 个字符以上的随机字符串，不要使用临时值或示例值。

- 如需隐藏 Web Vault，在 Workers 的“设置 → 变量和机密”中添加文本变量 `HIDE_WEB_VAULT`，值设为 `1`。启用后，服务器上的前端页面和静态资源统一返回 `404 Not Found`，Bitwarden 客户端所需的登录、同步、附件、图标、通知等服务端接口仍可使用；已经安装或缓存的 PWA 可以继续使用本地前端。删除该变量（或将值改为非 `1`）即可恢复服务器上的 Web Vault。

- 这套流程里，用户实际做的是把代码交给 Cloudflare 构建并部署。代码里的 `wrangler.toml` 或 `wrangler.kv.toml` 决定绑定名，Worker 第一次处理请求时会自动初始化 D1 schema，不需要用户上传 SQL。


> [!TIP] 
> 默认R2与可选KV的区别：
>   | 储存 | 是否需绑卡 | 单个附件/Send文件上限 | 免费额度 |
>   |---|---|---|---|
>   | R2 | 需要 | 100 MB（软限制可更改） | 10 GB |
>   | KV | 不需要 | 25 MiB（Cloudflare限制） | 1 GB |


## 常见问题：
- **Fork 完仓库后，在 Cloudflare 连接 GitHub 账户时看不到自己的仓库，或者选择仓库后返回 404？**  
  这通常与 GitHub Fork 仓库的识别或 Cloudflare 对仓库的授权/同步有关。如果 Fork 后仓库名称、描述等信息与上游项目高度一致，可能更容易触发相关限制或异常。建议在 Fork 时就将仓库名称修改为与上游不同的名称，并同时修改仓库描述，例如改为 `2233warden`。如果已经完成 Fork，也可以直接在 GitHub 仓库设置中修改名称和描述，然后重新尝试在 Cloudflare 中连接。

- **我删掉部署后重新部署，为什么注册又开始要求邀请码了？**  
  因为删除 Worker 或重新部署并不会自动删除已经创建的持久化数据。D1 数据库和 KV 命名空间中的用户、邀请码及相关配置仍然存在，因此重新部署后仍会读取原来的数据，并继续要求邀请码。  
  如果希望完全重新开始，需要同时删除对应的 **D1 数据库和 KV 命名空间**。

- **我配置了 `JWT_SECRET`，为什么页面仍然提示缺少？**  
  请将 `JWT_SECRET` 配置在 Cloudflare Workers 的 **Settings → Variables and Secrets** 中，并确保它属于 **Runtime variables and secrets**，而不是 **Build variables**。  
  Build 阶段的变量只在项目构建过程中可用，Worker 实际运行时无法通过运行时环境读取，因此即使构建能够正常完成，页面仍可能提示 `JWT_SECRET` 缺失。

- **为什么升级或重新部署后，`JWT_SECRET` 好像消失了？**  
  建议将 `JWT_SECRET` 配置为 **Secret**，而不是普通的明文变量。`JWT_SECRET` 属于敏感的运行时凭据，也不应该出现在代码仓库中。  
  如果部署流程会重新生成或覆盖 Worker 的变量配置，普通变量可能受到影响；使用 Secret 更适合保存这类需要在多次部署之间持续存在的敏感配置。重新部署后如果仍提示缺失，请检查当前 Worker 的 **Variables and Secrets** 中是否仍存在该 Secret。

---

## 更新方法：
- 手动：打开你 Fork 的 GitHub 仓库，看到顶部同步提示后，点击 `Sync fork` ➜ `Update branch`




## CLI 部署

```powershell
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

npm install
npx wrangler login

# 默认：R2 模式
npm run deploy

# 可选：KV 模式
npm run deploy:kv

# 本地开发
npm run dev
npm run dev:kv
```

---


## 开源协议

LGPL-3.0 License

---

## 致谢

- [Bitwarden](https://bitwarden.com/) - 原始设计与客户端
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - 服务端实现参考
- [Cloudflare Workers](https://workers.cloudflare.com/) - 无服务器平台

---

## 贡献者

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
