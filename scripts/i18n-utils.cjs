const fs = require('fs');
const path = require('path');
const vm = require('vm');

// CONTRACT:
// This list is the script-side locale source of truth. Keep it in sync with
// webapp/src/lib/i18n.ts whenever adding/removing a locale. Each locale has a
// base bundle (locales/) and an organizations-feature bundle (org/) that the
// webapp merges at runtime; validators check the merged key set.
const localeDir = path.join(__dirname, '..', 'webapp', 'src', 'lib', 'i18n', 'locales');
const orgLocaleDir = path.join(__dirname, '..', 'webapp', 'src', 'lib', 'i18n', 'org');

const localeFiles = [
  ['en', 'en.ts', 'en', 'English'],
  ['zh-CN', 'zh-CN.ts', 'zhCN', 'Simplified Chinese'],
  ['zh-TW', 'zh-TW.ts', 'zhTW', 'Traditional Chinese'],
  ['ru', 'ru.ts', 'ru', 'Russian'],
  ['es', 'es.ts', 'es', 'Spanish'],
  ['fi', 'fi.ts', 'fi', 'Finnish'],
  ['de', 'de.ts', 'de', 'German'],
  ['fr', 'fr.ts', 'fr', 'French'],
  ['it', 'it.ts', 'it', 'Italian'],
  ['sv', 'sv.ts', 'sv', 'Swedish'],
];

// Same order as localeFiles; variable names match the org bundle files.
const orgLocaleFiles = [
  ['en', 'en.ts', 'orgEn'],
  ['zh-CN', 'zh-CN.ts', 'orgZhCN'],
  ['zh-TW', 'zh-TW.ts', 'orgZhTW'],
  ['ru', 'ru.ts', 'orgRu'],
  ['es', 'es.ts', 'orgEs'],
  ['fi', 'fi.ts', 'orgFi'],
  ['de', 'de.ts', 'orgDe'],
  ['fr', 'fr.ts', 'orgFr'],
  ['it', 'it.ts', 'orgIt'],
  ['sv', 'sv.ts', 'orgSv'],
];

function readTable(dir, fileName, variableName) {
  let code = fs.readFileSync(path.join(dir, fileName), 'utf8');
  code = code
    .replace(/const (\w+): Record<string, string> =/g, 'const $1 =')
    .replace(/export default \w+;\s*$/m, '');
  code += `\nresult = ${variableName};`;
  const sandbox = { result: null };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: fileName });
  return sandbox.result;
}

function readLocale(fileName, variableName) {
  return readTable(localeDir, fileName, variableName);
}

function readOrgLocale(fileName, variableName) {
  return readTable(orgLocaleDir, fileName, variableName);
}

// The effective key set the webapp serves for a locale index into localeFiles.
function readMergedLocale(index) {
  const [, fileName, variableName] = localeFiles[index];
  const [, orgFileName, orgVariableName] = orgLocaleFiles[index];
  return { ...readLocale(fileName, variableName), ...readOrgLocale(orgFileName, orgVariableName) };
}

function writeLocale(fileName, variableName, table, header) {
  const body = JSON.stringify(table, null, 2);
  fs.writeFileSync(
    path.join(localeDir, fileName),
    `${header}\nconst ${variableName}: Record<string, string> = ${body};\n\nexport default ${variableName};\n`,
    'utf8'
  );
}

module.exports = {
  localeFiles,
  orgLocaleFiles,
  localeDir,
  orgLocaleDir,
  readLocale,
  readOrgLocale,
  readMergedLocale,
  writeLocale,
};
