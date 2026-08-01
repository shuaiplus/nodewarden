import type { CiphersImportPayload } from '@/lib/api/vault';
import { addFolder, cardBrand, makeLoginCipher, nameFromUrl, normalizeUri, parseCsv, parseSerializedUris, processKvp, txt, val } from '@/lib/import-format-shared';

type BitwardenCsvFieldLine = {
  key: string;
  value: string;
};

const NODEWARDEN_CSV_TYPE_FIELD = 'nodewardenType';
const NODEWARDEN_CSV_PREFIX_TYPES: Record<string, number> = {
  card: 3,
  identity: 4,
  sshkey: 5,
};
const NODEWARDEN_CSV_TYPE_PREFIXES: Record<number, 'card' | 'identity' | 'sshKey'> = {
  3: 'card',
  4: 'identity',
  5: 'sshKey',
};
const NODEWARDEN_CSV_OBJECT_FIELDS: Record<'card' | 'identity' | 'sshKey', readonly string[]> = {
  card: ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'],
  identity: [
    'title',
    'firstName',
    'middleName',
    'lastName',
    'username',
    'company',
    'ssn',
    'passportNumber',
    'licenseNumber',
    'email',
    'phone',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
  ],
  sshKey: ['privateKey', 'publicKey', 'keyFingerprint', 'fingerprint'],
};

// Parse the `fields` CSV column into key-value pairs.
// Lines without a `: ` delimiter are treated as continuations of the previous
// line's value, preserving multiline content such as SSH private keys.
function parseBitwardenCsvFieldLines(rawFields: unknown): BitwardenCsvFieldLine[] {
  return String(rawFields || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .reduce<BitwardenCsvFieldLine[]>((acc, line) => {
      const delim = line.lastIndexOf(': ');
      if (delim < 0) {
        // Continuation line — append to the previous entry's value.
        if (acc.length > 0) {
          acc[acc.length - 1].value += '\n' + line;
        }
        return acc;
      }
      // New key-value line.
      const key = txt(line.slice(0, delim));
      const value = txt(line.slice(delim + 2));
      if (key && value) {
        acc.push({ key, value });
      }
      return acc;
    }, []);
}

function getNodeWardenCsvType(lines: BitwardenCsvFieldLine[]): number | null {
  const typeLine = lines.find((line) => line.key === NODEWARDEN_CSV_TYPE_FIELD);
  const normalized = txt(typeLine?.value).toLowerCase().replace(/[\s_-]+/g, '');
  const type = NODEWARDEN_CSV_PREFIX_TYPES[normalized] ?? null;
  if (!type) return null;
  const prefix = NODEWARDEN_CSV_TYPE_PREFIXES[type];
  return lines.some((line) => line.key.startsWith(`${prefix}.`)) ? type : null;
}

function applyBitwardenCustomFields(cipher: Record<string, unknown>, lines: BitwardenCsvFieldLine[]): void {
  for (const line of lines) {
    processKvp(cipher, line.key, line.value, false);
  }
}

function restoreNodeWardenObject(lines: BitwardenCsvFieldLine[], prefix: 'card' | 'identity' | 'sshKey'): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const fieldPrefix = `${prefix}.`;
  const allowedKeys = new Set(NODEWARDEN_CSV_OBJECT_FIELDS[prefix]);
  for (const line of lines) {
    if (!line.key.startsWith(fieldPrefix)) continue;
    const key = line.key.slice(fieldPrefix.length);
    if (!allowedKeys.has(key)) continue;
    out[key] = line.value;
  }
  return out;
}

function nodeWardenMetadataLines(lines: BitwardenCsvFieldLine[]): Set<BitwardenCsvFieldLine> {
  return new Set(
    lines.filter(
      (line) =>
        line.key === NODEWARDEN_CSV_TYPE_FIELD ||
        line.key.startsWith('card.') ||
        line.key.startsWith('identity.') ||
        line.key.startsWith('sshKey.')
    )
  );
}

export function parseChromeCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const cipher = makeLoginCipher();
    const m = txt(row.url).match(/^android:\/\/.*@([^/]+)\//);
    const uri = m ? `androidapp://${m[1]}` : normalizeUri(row.url || '');
    cipher.name = val(row.name, m?.[1] || '--');
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.username);
    login.password = val(row.password);
    login.uris = uri ? [{ uri, match: null }] : null;
    cipher.notes = val(row.note);
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseFirefoxCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw).filter((r) => txt(r.url) !== 'chrome://FirefoxAccounts');
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const cipher = makeLoginCipher();
    const raw = val(row.url, val(row.hostname, '') || '') || '';
    let name: string | null = null;
    try {
      const host = new URL(normalizeUri(raw) || '').hostname || '';
      name = host.startsWith('www.') ? host.slice(4) : host || null;
    } catch {}
    cipher.name = val(name, '--');
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.username);
    login.password = val(row.password);
    const uri = normalizeUri(raw);
    login.uris = uri ? [{ uri, match: null }] : null;
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseSafariCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const cipher = makeLoginCipher();
    cipher.name = val(row.Title, '--');
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.Username);
    login.password = val(row.Password);
    const uri = normalizeUri(row.Url || row.URL || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    login.totp = val(row.OTPAuth);
    cipher.notes = val(row.Notes);
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseBitwardenCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const type = txt(row.type).toLowerCase() || 'login';
    const fieldLines = parseBitwardenCsvFieldLines(row.fields);
    const restoredNodeWardenType = type === 'note' ? getNodeWardenCsvType(fieldLines) : null;
    if (restoredNodeWardenType === 3 || restoredNodeWardenType === 4 || restoredNodeWardenType === 5) {
      const metadataLines = nodeWardenMetadataLines(fieldLines);
      const customLines = fieldLines.filter((line) => !metadataLines.has(line));
      const cipher: Record<string, unknown> = {
        type: restoredNodeWardenType,
        name: val(row.name, '--'),
        notes: val(row.notes),
        favorite: txt(row.favorite) === '1',
        reprompt: Number(row.reprompt ?? 0) || 0,
        key: null,
        login: null,
        card: restoredNodeWardenType === 3 ? restoreNodeWardenObject(fieldLines, 'card') : null,
        identity: restoredNodeWardenType === 4 ? restoreNodeWardenObject(fieldLines, 'identity') : null,
        secureNote: null,
        fields: [],
        passwordHistory: null,
        sshKey: restoredNodeWardenType === 5 ? restoreNodeWardenObject(fieldLines, 'sshKey') : null,
      };
      applyBitwardenCustomFields(cipher, customLines);
      const idx = result.ciphers.push(cipher) - 1;
      addFolder(result, row.folder, idx);
      continue;
    }
    if (type === 'note' || type === 'secure note' || type === 'securenote') {
      const cipher = {
        type: 2,
        name: val(row.name, '--'),
        notes: val(row.notes),
        favorite: txt(row.favorite) === '1',
        reprompt: Number(row.reprompt ?? 0) || 0,
        key: null,
        login: null,
        card: null,
        identity: null,
        secureNote: { type: 0 },
        fields: [],
        passwordHistory: null,
        sshKey: null,
      };
      applyBitwardenCustomFields(cipher, fieldLines);
      const idx = result.ciphers.push(cipher) - 1;
      addFolder(result, row.folder, idx);
      continue;
    }
    const cipher = makeLoginCipher();
    cipher.name = val(row.name, '--');
    cipher.notes = val(row.notes);
    cipher.favorite = txt(row.favorite) === '1';
    cipher.reprompt = Number(row.reprompt ?? 0) || 0;
    applyBitwardenCustomFields(cipher, fieldLines);
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.login_username, val(row.username));
    login.password = val(row.login_password, val(row.password));
    login.totp = val(row.login_totp, val(row.totp));
    const uris = parseSerializedUris(row.login_uri || row.uri || '');
    login.uris = uris.length ? uris.map((uri) => ({ uri, match: null })) : null;
    const idx = result.ciphers.push(cipher) - 1;
    addFolder(result, row.folder, idx);
  }
  return result;
}

export function parseAviraCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const cipher = makeLoginCipher();
    cipher.name = val(row.name, val(nameFromUrl(row.website), '--'));
    const login = cipher.login as Record<string, unknown>;
    login.uris = normalizeUri(row.website || '') ? [{ uri: normalizeUri(row.website || ''), match: null }] : null;
    login.password = val(row.password);
    if (!txt(row.username) && txt(row.secondary_username)) {
      login.username = val(row.secondary_username);
    } else {
      login.username = val(row.username);
      cipher.notes = val(row.secondary_username);
    }
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseAvastCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const cipher = makeLoginCipher();
    cipher.name = val(row.name, '--');
    const login = cipher.login as Record<string, unknown>;
    login.uris = normalizeUri(row.web || '') ? [{ uri: normalizeUri(row.web || ''), match: null }] : null;
    login.password = val(row.password);
    login.username = val(row.login);
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseAvastJson(textRaw: string): CiphersImportPayload {
  const parsed = JSON.parse(textRaw) as { logins?: any[]; notes?: any[]; cards?: any[] };
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const value of parsed.logins || []) {
    const cipher = makeLoginCipher();
    cipher.name = val(value?.custName, '--');
    cipher.notes = val(value?.note);
    const login = cipher.login as Record<string, unknown>;
    const uri = normalizeUri(value?.url || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    login.password = val(value?.pwd);
    login.username = val(value?.loginName);
    result.ciphers.push(cipher);
  }
  for (const value of parsed.notes || []) {
    result.ciphers.push({
      type: 2,
      name: val(value?.label, '--'),
      notes: val(value?.text),
      favorite: false,
      reprompt: 0,
      key: null,
      login: null,
      card: null,
      identity: null,
      secureNote: { type: 0 },
      fields: null,
      passwordHistory: null,
      sshKey: null,
    });
  }
  for (const value of parsed.cards || []) {
    result.ciphers.push({
      type: 3,
      name: val(value?.custName, '--'),
      notes: val(value?.note),
      favorite: false,
      reprompt: 0,
      key: null,
      login: null,
      card: {
        cardholderName: val(value?.holderName),
        number: val(value?.cardNumber),
        code: val(value?.cvv),
        brand: cardBrand(val(value?.cardNumber)),
        expMonth: val(value?.expirationDate?.month),
        expYear: val(value?.expirationDate?.year),
      },
      identity: null,
      secureNote: null,
      fields: null,
      passwordHistory: null,
      sshKey: null,
    });
  }
  return result;
}
