const { localeFiles, readLocale } = require('./i18n-utils.cjs');

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
