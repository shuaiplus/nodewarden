const fs = require('fs');
const path = require('path');
const vm = require('vm');

// CONTRACT:
// This list is the script-side locale source of truth. Keep it in sync with
// webapp/src/lib/i18n.ts whenever adding/removing a locale.
const localeDir = path.join(__dirname, '..', 'webapp', 'src', 'lib', 'i18n', 'locales');

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

function readLocale(fileName, variableName) {
  let code = fs.readFileSync(path.join(localeDir, fileName), 'utf8');
  code = code
    .replace(/const (\w+): Record<string, string> =/g, 'const $1 =')
    .replace(/export default \w+;\s*$/m, '');
  code += `\nresult = ${variableName};`;
  const sandbox = { result: null };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: fileName });
  return sandbox.result;
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
  localeDir,
  readLocale,
  writeLocale,
};
