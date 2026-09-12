const fs = require('node:fs');
const path = require('node:path');

const { localeFiles, readLocale, localeDir } = require('./i18n-utils.cjs');

// i18n.ts 的 localeLoaders 是语言集合的权威来源；i18n-utils.cjs 里手写的列表
// 只描述「每个语言对应哪个文件」。两者必须一致，见下方的显式比对。
const i18nEntry = path.join(__dirname, '..', 'webapp', 'src', 'lib', 'i18n.ts');

// CONTRACT:
// This is the authoritative locale consistency gate. It checks key parity,
// placeholder parity, and accidental mostly-English locale files. Run after any
// user-facing text or locale-file change.
const locales = Object.fromEntries(
  localeFiles.map(([locale, fileName, variableName]) => [locale, readLocale(fileName, variableName)])
);
const base = locales.en;
const baseKeys = Object.keys(base).sort();
const placeholderRe = /\{\w+\}/g;
const errors = [];

// 读取 i18n.ts 中的 localeLoaders，返回 Map<locale, fileName|null>。
// fileName 为 null 表示该 loader 不是动态 import（例如 en 走静态导入）。
// 按行解析而非正则跨行匹配：声明行含有 `=>`，正则会被类型里的等号干扰。
function readI18nLoaderLocales() {
  const lines = fs.readFileSync(i18nEntry, 'utf8').split('\n');
  const start = lines.findIndex((line) => line.includes('localeLoaders') && line.includes('= {'));
  if (start === -1) return null;

  const entries = new Map();
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '};') break;
    const match = line.match(/^\s*(?:'([^']+)'|([A-Za-z][\w-]*))\s*:\s*(.+?),?\s*$/);
    if (!match) continue;
    const locale = match[1] || match[2];
    const importMatch = match[3].match(/import\('\.\/i18n\/locales\/([^']+)'\)/);
    entries.set(locale, importMatch ? `${importMatch[1]}.ts` : null);
  }
  return entries;
}

// 语种集合必须与 i18n.ts 一致。若只改了 i18n.ts 而漏改 i18n-utils.cjs，新语言会被
// 本脚本静默跳过（不报错、假绿），因此这里显式报错。
const loaderLocales = readI18nLoaderLocales();
if (!loaderLocales || loaderLocales.size === 0) {
  errors.push({ locale: 'i18n.ts', problem: 'could not read localeLoaders', file: i18nEntry });
} else {
  const declared = localeFiles.map(([locale]) => locale);
  const missingInUtils = [...loaderLocales.keys()].filter((locale) => !declared.includes(locale));
  const extraInUtils = declared.filter((locale) => !loaderLocales.has(locale));
  if (missingInUtils.length || extraInUtils.length) {
    errors.push({
      locale: 'i18n.ts',
      problem: 'locale list out of sync with scripts/i18n-utils.cjs',
      missingInUtils,
      extraInUtils,
    });
  }
  for (const [locale, fileName] of loaderLocales) {
    if (fileName && !fs.existsSync(path.join(localeDir, fileName))) {
      errors.push({ locale, problem: `locale file not found: ${fileName}` });
    }
  }
}
const intentionallyEnglishKeys = new Set([
  'txt_backup_destination_detail_note',
  'txt_backup_protocol_webdav',
  'txt_backup_protocol_s3',
  'txt_backup_recommend_group_webdav',
  'txt_backup_recommend_group_s3',
  'txt_backup_destination_name_default_webdav',
  'txt_backup_destination_name_default_s3',
  'txt_dash',
  'txt_text_3',
]);
const intentionallyEnglishPrefixes = [
  'txt_log_action_',
  'txt_log_meta_',
  'txt_log_reason_',
  'txt_log_target_type_',
  'txt_log_trigger_',
];

function isIntentionallyEnglishKey(key) {
  return intentionallyEnglishKeys.has(key) || intentionallyEnglishPrefixes.some((prefix) => key.startsWith(prefix));
}

for (const [locale, table] of Object.entries(locales)) {
  const keys = Object.keys(table).sort();
  const missing = baseKeys.filter((key) => !(key in table));
  const extra = keys.filter((key) => !baseKeys.includes(key));
  if (missing.length || extra.length) {
    errors.push({ locale, missing, extra });
  }

  for (const key of baseKeys) {
    const basePlaceholders = Array.from(String(base[key]).matchAll(placeholderRe), (match) => match[0]).sort().join('|');
    const localePlaceholders = Array.from(String(table[key]).matchAll(placeholderRe), (match) => match[0]).sort().join('|');
    if (basePlaceholders !== localePlaceholders) {
      errors.push({ locale, key, basePlaceholders, localePlaceholders });
    }
  }

  if (locale !== 'en') {
    const sameAsEnglish = baseKeys.filter((key) => table[key] === base[key] && !isIntentionallyEnglishKey(key));
    if (sameAsEnglish.length > 40) {
      errors.push({
        locale,
        sameAsEnglishCount: sameAsEnglish.length,
        sameAsEnglishSample: sameAsEnglish.slice(0, 25),
      });
    }
  }
}

console.log(JSON.stringify({
  counts: Object.fromEntries(Object.entries(locales).map(([locale, table]) => [locale, Object.keys(table).length])),
  errors,
}, null, 2));

if (errors.length) {
  process.exit(1);
}
