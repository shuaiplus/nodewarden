#!/usr/bin/env node

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_REF = 'main';
const OUTPUT_DIR = path.join(process.cwd(), 'src', 'static');
const OUT_FILE = path.join(OUTPUT_DIR, 'global_domains.bitwarden.json');
const META_FILE = path.join(OUTPUT_DIR, 'global_domains.bitwarden.meta.json');
const ENUM_PATH = 'src/Core/Enums/GlobalEquivalentDomainsType.cs';
const STATIC_STORE_PATH = 'src/Core/Utilities/StaticStore.cs';

function rawUrl(ref, filePath) {
  return `https://raw.githubusercontent.com/bitwarden/server/${encodeURIComponent(ref)}/${filePath}`;
}

async function fetchText(url) {
  const response = await fetch(url, {
    headers: {
      'User-Agent': 'NodeWarden global domains sync',
      Accept: 'text/plain',
    },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: HTTP ${response.status}`);
  }
  return response.text();
}

// The last --ref wins; a bare --ref only consumes the next argument when it is non-empty.
const cliArgs = process.argv.slice(2);
let ref = process.env.BITWARDEN_SERVER_REF || DEFAULT_REF;
for (let argIndex = 0; argIndex < cliArgs.length; argIndex += 1) {
  const arg = cliArgs[argIndex];
  if (arg === '--ref' && cliArgs[argIndex + 1]) {
    ref = cliArgs[argIndex + 1];
    argIndex += 1;
  } else if (arg.startsWith('--ref=')) {
    ref = arg.slice('--ref='.length);
  }
}
const enumUrl = rawUrl(ref, ENUM_PATH);
const staticStoreUrl = rawUrl(ref, STATIC_STORE_PATH);

const [enumSource, staticStoreSource] = await Promise.all([
  fetchText(enumUrl),
  fetchText(staticStoreUrl),
]);

const enumMatch = enumSource.match(/enum\s+GlobalEquivalentDomainsType\b[\s\S]*?\{([\s\S]*?)\}/);
if (!enumMatch) {
  throw new Error('GlobalEquivalentDomainsType enum was not found');
}
const enumTypes = new Map(Array.from(
  enumMatch[1].replace(/\/\/.*$/gm, '').matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\b/g),
  ([, name, value]) => [name, Number(value)],
));
if (!enumTypes.size) {
  throw new Error('No enum values were parsed from GlobalEquivalentDomainsType');
}

const rules = Array.from(
  staticStoreSource.matchAll(/GlobalDomains\.Add\s*\(\s*GlobalEquivalentDomainsType\.([A-Za-z_][A-Za-z0-9_]*)\s*,\s*new\s+List(?:<\s*string\s*>)?\s*\{([\s\S]*?)\}\s*\)\s*;/g),
  ([, name, domainList]) => {
    const type = enumTypes.get(name);
    if (!Number.isInteger(type)) {
      throw new Error(`GlobalDomains references unknown enum value ${name}`);
    }

    // Each C# string literal in the list, unescaped and lowercased, deduplicated in source order.
    const domains = Array.from(new Set(Array.from(
      domainList.matchAll(/"((?:\\.|[^"\\])*)"/g),
      ([, domain]) => domain.replace(/\\"/g, '"').trim().toLowerCase(),
    ).filter(Boolean)));
    if (domains.length < 2) {
      throw new Error(`GlobalDomains.${name} has fewer than two domains`);
    }

    return {
      type,
      domains,
      excluded: false,
    };
  },
);
if (!rules.length) {
  throw new Error('No GlobalDomains.Add(...) rules were parsed from StaticStore.cs');
}
const domainsCount = rules.reduce((sum, rule) => sum + rule.domains.length, 0);
const rulesJson = `[\n${rules.map((rule) => `  ${JSON.stringify(rule)}`).join(',\n')}\n]`;

async function readJsonFile(filePath) {
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch {
    return null;
  }
}

const existingRules = await readJsonFile(OUT_FILE);
const existingMeta = await readJsonFile(META_FILE);
const unchangedRules = JSON.stringify(existingRules) === JSON.stringify(rules);
const unchangedRef = existingMeta?.ref === ref;

const meta = {
  source: 'https://github.com/bitwarden/server',
  ref,
  generatedAt: unchangedRules && unchangedRef && existingMeta?.generatedAt
    ? existingMeta.generatedAt
    : new Date().toISOString(),
  rulesCount: rules.length,
  domainsCount,
  sourceFiles: [
    ENUM_PATH,
    STATIC_STORE_PATH,
  ],
  sourceUrls: [
    enumUrl,
    staticStoreUrl,
  ],
};

await mkdir(OUTPUT_DIR, { recursive: true });
await writeFile(OUT_FILE, `${rulesJson}\n`, 'utf8');
await writeFile(META_FILE, `${JSON.stringify(meta, null, 2)}\n`, 'utf8');

console.log(`Wrote ${rules.length} global domain rules (${domainsCount} domains) from bitwarden/server@${ref}.`);
