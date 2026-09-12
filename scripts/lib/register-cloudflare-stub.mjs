// 注册模块解析钩子：把 `cloudflare:workers` 重定向到本地桩。
//
// 用法（必须用 --import 预加载，早于任何被测模块的解析）：
//   NODE_OPTIONS="--import=./scripts/lib/register-cloudflare-stub.mjs" npx tsx --test ...
//
// 为什么需要它：`src/durable/notifications-hub.ts` 从 `cloudflare:workers` 导入
// `DurableObject` / `waitUntil`，而 Node 不支持该协议 —— 报
// `ERR_UNSUPPORTED_ESM_URL_SCHEME: Received protocol 'cloudflare:'`。
// 没有这个钩子，所有间接引用通知模块的 handler（ciphers、folders、sends、identity…）
// 都无法在 Node 测试里被导入。
//
// 本文件刻意写成 .mjs：由 Node 直接加载，不经过 tsx 转译。
import { registerHooks } from 'node:module';

const STUB_URL = new URL('./cloudflare-workers-stub.mjs', import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') {
      return { url: STUB_URL, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});
