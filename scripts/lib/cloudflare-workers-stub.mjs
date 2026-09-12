// `cloudflare:workers` 的本地桩（测试专用）
//
// 背景：`src/durable/notifications-hub.ts` 从 `cloudflare:workers` 导入 `DurableObject`
// 与 `waitUntil`。这是 Workers 运行时的虚拟模块，**Node 无法解析**
// （报 `ERR_UNSUPPORTED_ESM_URL_SCHEME`），于是任何间接引用该模块的 handler 都无法在
// Node 测试里被导入。
//
// 本文件配合 `register-cloudflare-stub.mjs` 使用：由 Node 的模块解析钩子把
// `cloudflare:workers` 重定向到这里。
//
// 刻意保持最小：只提供被实际导入的两个符号，避免"看起来很真但行为不同"的假象。

/** 仅满足 `class X extends DurableObject` 的语法需求；测试不实例化 DO */
export class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
}

/**
 * Workers 的 `ctx.waitUntil`：把 promise 的生命周期延到请求之后，且**不会**把
 * rejection 抛回请求。测试里顺应同一语义 —— 只吞掉错误，绝不让它变成 unhandled rejection
 * 把测试搞挂。（实际发送通知需要真实 DO，测试环境没有，因此这里只做安全兜底。）
 */
export function waitUntil(promise) {
  void Promise.resolve(promise).catch(() => {});
}
