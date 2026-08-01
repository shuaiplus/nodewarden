#!/usr/bin/env node
/**
 * Make `deploy:kv` idempotent across repeated builds.
 *
 * KV namespaces are referenced in wrangler config by account-scoped `id`, not
 * by name. The template ships without an id so fresh accounts can provision one
 * on first deploy. In non-interactive builds, wrangler may try to create the
 * same namespace again on later builds and fail with code 10014.
 */
const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const CONFIG = path.resolve(__dirname, '..', 'wrangler.kv.toml');
const BINDING = 'ATTACHMENTS_KV';

const wrangler = (args) =>
  execSync(`npx wrangler ${args}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });

function bindingBlockHasId(toml) {
  const blocks = toml.match(/\[\[kv_namespaces\]\][^[]*/g) || [];
  const block = blocks.find((entry) => new RegExp(`binding\\s*=\\s*"${BINDING}"`).test(entry));
  return block ? /^\s*id\s*=/m.test(block) : false;
}

function expectedTitle(toml) {
  const name = (toml.match(/^\s*name\s*=\s*"([^"]+)"/m) || [])[1] || 'worker';
  return `${name}-${BINDING.toLowerCase().replace(/_/g, '-')}`;
}

function resolveId(title) {
  const list = JSON.parse(wrangler('kv namespace list'));
  const hit =
    list.find((namespace) => namespace.title === title) ||
    list.find((namespace) => typeof namespace.title === 'string' && namespace.title.endsWith('attachments-kv'));
  if (hit) {
    console.log(`[ensure-kv] reusing existing namespace "${hit.title}" (${hit.id})`);
    return hit.id;
  }

  const out = wrangler(`kv namespace create "${title}"`);
  const id = (out.match(/id\s*=\s*"([0-9a-fA-F]{32})"/) || [])[1];
  if (!id) throw new Error(`[ensure-kv] could not parse new namespace id from:\n${out}`);
  console.log(`[ensure-kv] created namespace "${title}" (${id})`);
  return id;
}

function main() {
  let toml = fs.readFileSync(CONFIG, 'utf8');
  if (bindingBlockHasId(toml)) {
    console.log(`[ensure-kv] ${BINDING} already pinned in wrangler.kv.toml; nothing to do`);
    return;
  }

  const id = resolveId(expectedTitle(toml));
  toml = toml.replace(
    new RegExp(`(\\[\\[kv_namespaces\\]\\]\\s*\\n\\s*binding\\s*=\\s*"${BINDING}")`),
    `$1\nid = "${id}"`
  );
  fs.writeFileSync(CONFIG, toml);
  console.log('[ensure-kv] pinned id into wrangler.kv.toml for this build');
}

main();
