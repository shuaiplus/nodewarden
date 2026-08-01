#!/usr/bin/env node

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_REF = 'main';
const OUTPUT_DIR = path.join(process.cwd(), 'src', 'static');
const OUT_FILE = path.join(OUTPUT_DIR, 'global_domains.bitwarden.json');
const META_FILE = path.join(OUTPUT_DIR, 'global_domains.bitwarden.meta.json');
const ENUM_PATH = 'src/Core/Enums/GlobalEquivalentDomainsType.cs';
const STATIC_STORE_PATH = 'src/Core/Utilities/StaticStore.cs';

function parseArgs(argv) {
  const args = { ref: process.env.BITWARDEN_SERVER_REF || DEFAULT_REF };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--ref' && argv[i + 1]) {
      args.ref = argv[i + 1];
      i += 1;
    } else if (arg.startsWith('--ref=')) {
      args.ref = arg.slice('--ref='.length);
    }
  }
  return args;
}

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

function parseEnumTypes(source) {
  const map = new Map();
  const enumMatch = source.match(/enum\s+GlobalEquivalentDomainsType\b[\s\S]*?\{([\s\S]*?)\}/);
  if (!enumMatch) {
    throw new Error('GlobalEquivalentDomainsType enum was not found');
  }

  const body = enumMatch[1].replace(/\/\/.*$/gm, '');
  const entryRe = /\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\b/g;
  let match;
  while ((match = entryRe.exec(body)) !== null) {
    map.set(match[1], Number(match[2]));
  }

  if (!map.size) {
    throw new Error('No enum values were parsed from GlobalEquivalentDomainsType');
  }
  return map;
}

function parseStringList(source) {
  const domains = [];
  const stringRe = /"((?:\\.|[^"\\])*)"/g;
  let match;
  while ((match = stringRe.exec(source)) !== null) {
    domains.push(match[1].replace(/\\"/g, '"').trim().toLowerCase());
  }
  return Array.from(new Set(domains.filter(Boolean)));
}

function parseGlobalDomains(source, enumTypes) {
  const out = [];
  const addRe = /GlobalDomains\.Add\s*\(\s*GlobalEquivalentDomainsType\.([A-Za-z_][A-Za-z0-9_]*)\s*,\s*new\s+List(?:<\s*string\s*>)?\s*\{([\s\S]*?)\}\s*\)\s*;/g;
  let match;
  while ((match = addRe.exec(source)) !== null) {
    const name = match[1];
    const type = enumTypes.get(name);
    if (!Number.isInteger(type)) {
      throw new Error(`GlobalDomains references unknown enum value ${name}`);
    }

    const domains = parseStringList(match[2]);
    if (domains.length < 2) {
      throw new Error(`GlobalDomains.${name} has fewer than two domains`);
    }

    out.push({
      type,
      domains,
      excluded: false,
    });
  }

  if (!out.length) {
    throw new Error('No GlobalDomains.Add(...) rules were parsed from StaticStore.cs');
  }
  return out;
}

function formatRulesJson(rules) {
  return `[\n${rules.map((rule) => `  ${JSON.stringify(rule)}`).join(',\n')}\n]`;
}

function formatMetaJson(meta) {
  return JSON.stringify(meta, null, 2);
}

const { ref } = parseArgs(process.argv.slice(2));
const enumUrl = rawUrl(ref, ENUM_PATH);
const staticStoreUrl = rawUrl(ref, STATIC_STORE_PATH);

const [enumSource, staticStoreSource] = await Promise.all([
  fetchText(enumUrl),
  fetchText(staticStoreUrl),
]);

const enumTypes = parseEnumTypes(enumSource);
const rules = parseGlobalDomains(staticStoreSource, enumTypes);
const domainsCount = rules.reduce((sum, rule) => sum + rule.domains.length, 0);
const rulesJson = formatRulesJson(rules);

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
await writeFile(META_FILE, `${formatMetaJson(meta)}\n`, 'utf8');

console.log(`Wrote ${rules.length} global domain rules (${domainsCount} domains) from bitwarden/server@${ref}.`);
