import type { CiphersImportPayload } from '@/lib/api/vault';
import {
  addFolder,
  cardBrand,
  convertToNoteIfNeeded,
  makeLoginCipher,
  nameFromUrl,
  normalizeUri,
  parseCsv,
  parseCsvRows,
  processKvp,
  txt,
  val,
} from '@/lib/import-format-shared';

export function parseArcCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const cipher = makeLoginCipher();
    cipher.name = val(nameFromUrl(row.url), '--');
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.username);
    login.password = val(row.password);
    const uri = normalizeUri(row.url || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    cipher.notes = val(row.note);
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseAscendoCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsvRows(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    if (row.length < 2) continue;
    const cipher = makeLoginCipher();
    cipher.name = val(row[0], '--');
    cipher.notes = val(row[row.length - 1]);
    if (row.length > 2 && row.length % 2 === 0) {
      for (let i = 0; i < row.length - 2; i += 2) {
        const field = txt(row[i + 1]);
        const fieldValue = txt(row[i + 2]);
        if (!field || !fieldValue) continue;
        const low = field.toLowerCase();
        const login = cipher.login as Record<string, unknown>;
        if (!txt(login.password) && ['password', 'pass', 'passwd'].includes(low)) login.password = fieldValue;
        else if (!txt(login.username) && ['username', 'user', 'email', 'login', 'id'].includes(low)) login.username = fieldValue;
        else if ((!Array.isArray(login.uris) || !login.uris.length) && ['url', 'uri', 'website', 'web site', 'host', 'hostname'].includes(low)) {
          const uri = normalizeUri(fieldValue);
          login.uris = uri ? [{ uri, match: null }] : null;
        } else processKvp(cipher, field, fieldValue, false);
      }
    }
    convertToNoteIfNeeded(cipher);
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseBlackberryCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    if (txt(row.grouping) === 'list') continue;
    const cipher = makeLoginCipher();
    cipher.favorite = txt(row.fav) === '1';
    cipher.name = val(row.name, '--');
    cipher.notes = val(row.extra);
    if (txt(row.grouping) !== 'note') {
      const login = cipher.login as Record<string, unknown>;
      const uri = normalizeUri(row.url || '');
      login.uris = uri ? [{ uri, match: null }] : null;
      login.password = val(row.password);
      login.username = val(row.username);
    }
    convertToNoteIfNeeded(cipher);
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseBlurCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const label = txt(row.label) === 'null' ? '' : txt(row.label);
    const cipher = makeLoginCipher();
    cipher.name = val(label, val(nameFromUrl(row.domain), '--'));
    const login = cipher.login as Record<string, unknown>;
    const uri = normalizeUri(row.domain || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    login.password = val(row.password);
    if (!txt(row.email) && txt(row.username)) login.username = val(row.username);
    else {
      login.username = val(row.email);
      cipher.notes = val(row.username);
    }
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseButtercupCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  const official = new Set(['!group_id', '!group_name', '!type', 'title', 'username', 'password', 'url', 'note', 'id']);
  for (const row of rows) {
    const cipher = makeLoginCipher();
    cipher.name = val(row.title, '--');
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.username);
    login.password = val(row.password);
    const uri = normalizeUri(row.URL || row.url || row.Url || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    cipher.notes = val(row.note || row.Note || row.notes || row.Notes);

    for (const key of Object.keys(row)) {
      if (official.has(key.toLowerCase())) continue;
      processKvp(cipher, key, row[key], false);
    }
    const idx = result.ciphers.push(cipher) - 1;
    addFolder(result, row['!group_name'], idx);
  }
  return result;
}

export function parseCodebookCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const cipher = makeLoginCipher();
    cipher.favorite = txt(row.Favorite).toLowerCase() === 'true';
    cipher.name = val(row.Entry, '--');
    cipher.notes = val(row.Note);
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.Username, val(row.Email));
    login.password = val(row.Password);
    login.totp = val(row.TOTP);
    const uri = normalizeUri(row.Website || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    if (txt(row.Username)) processKvp(cipher, 'Email', row.Email || '', false);
    processKvp(cipher, 'Phone', row.Phone || '', false);
    processKvp(cipher, 'PIN', row.PIN || '', false);
    processKvp(cipher, 'Account', row.Account || '', false);
    processKvp(cipher, 'Date', row.Date || '', false);
    convertToNoteIfNeeded(cipher);
    const idx = result.ciphers.push(cipher) - 1;
    addFolder(result, row.Category, idx);
  }
  return result;
}

export function parseEncryptrCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const cipher = makeLoginCipher();
    cipher.name = val(row.Label, '--');
    cipher.notes = val(row.Notes);
    const text = val(row.Text);
    if (text) cipher.notes = txt(cipher.notes) ? `${txt(cipher.notes)}\n\n${text}` : text;
    const type = txt(row['Entry Type']);
    if (type === 'Password') {
      const login = cipher.login as Record<string, unknown>;
      login.username = val(row.Username);
      login.password = val(row.Password);
      const uri = normalizeUri(row['Site URL'] || '');
      login.uris = uri ? [{ uri, match: null }] : null;
    } else if (type === 'Credit Card') {
      const expiry = txt(row.Expiry);
      let expMonth: string | null = null;
      let expYear: string | null = null;
      const parts = expiry.split('/');
      if (parts.length > 1) {
        expMonth = txt(parts[0]);
        const y = txt(parts[1]);
        expYear = y.length === 2 ? `20${y}` : y || null;
      }
      cipher.type = 3;
      cipher.login = null;
      cipher.card = {
        cardholderName: val(row['Name on card']),
        number: val(row['Card Number']),
        brand: cardBrand(val(row['Card Number'])),
        code: val(row.CVV),
        expMonth,
        expYear,
      };
    }
    convertToNoteIfNeeded(cipher);
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseKeePassXCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  const standardColumns = new Set(['Group', 'Title', 'Username', 'Password', 'URL', 'Notes', 'TOTP']);
  for (const row of rows) {
    if (!txt(row.Title)) continue;
    const cipher = makeLoginCipher();
    cipher.notes = val(row.Notes);
    cipher.name = val(row.Title, '--');
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.Username);
    login.password = val(row.Password);
    login.totp = val(row.TOTP);
    const uri = normalizeUri(row.URL || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    for (const [key, value] of Object.entries(row)) {
      if (standardColumns.has(key)) continue;
      processKvp(cipher, key, value, false);
    }
    const idx = result.ciphers.push(cipher) - 1;
    addFolder(result, txt(row.Group).replace(/^Root\//, ''), idx);
  }
  return result;
}

export function parseKeePassCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    if (!txt(row.Account)) continue;
    const cipher = makeLoginCipher();
    cipher.name = val(row.Account, '--');
    cipher.notes = val(row.Comments);
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row['Login Name']);
    login.password = val(row.Password);
    const uri = normalizeUri(row['Web Site'] || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    result.ciphers.push(cipher);
  }
  return result;
}

export function parseLastPassCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const isSecureNote = txt(row.url) === 'http://sn';
    if (isSecureNote) {
      const idx =
        result.ciphers.push({
          type: 2,
          name: val(row.name, '--'),
          notes: val(row.extra),
          favorite: txt(row.fav) === '1',
          reprompt: 0,
          key: null,
          login: null,
          card: null,
          identity: null,
          secureNote: { type: 0 },
          fields: null,
          passwordHistory: null,
          sshKey: null,
        }) - 1;
      addFolder(result, txt(row.grouping).replace(/[\x00-\x1F\x7F-\x9F]/g, ''), idx);
      continue;
    }
    const cipher = makeLoginCipher();
    cipher.name = val(row.name, '--');
    cipher.favorite = txt(row.fav) === '1';
    cipher.notes = val(row.extra);
    const login = cipher.login as Record<string, unknown>;
    login.username = val(row.username);
    login.password = val(row.password);
    login.totp = val(row.totp);
    const uri = normalizeUri(row.url || '');
    login.uris = uri ? [{ uri, match: null }] : null;
    const idx = result.ciphers.push(cipher) - 1;
    addFolder(result, txt(row.grouping).replace(/[\x00-\x1F\x7F-\x9F]/g, ''), idx);
  }
  return result;
}

export function parseDashlaneCsv(textRaw: string): CiphersImportPayload {
  const rows = parseCsv(textRaw);
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  for (const row of rows) {
    const keys = Object.keys(row);
    if (keys[0] === 'username') {
      const cipher = makeLoginCipher();
      cipher.name = val(row.title, '--');
      const login = cipher.login as Record<string, unknown>;
      login.username = val(row.username);
      login.password = val(row.password);
      login.totp = val(row.otpUrl || row.otpSecret);
      const uri = normalizeUri(row.url || '');
      login.uris = uri ? [{ uri, match: null }] : null;
      cipher.notes = val(row.note);
      const idx = result.ciphers.push(cipher) - 1;
      addFolder(result, row.category, idx);
      continue;
    }
    if (keys[0] === 'title' && keys[1] === 'note') {
      result.ciphers.push({
        type: 2,
        name: val(row.title, '--'),
        notes: val(row.note),
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
  }
  return result;
}

export function parseDashlaneJson(textRaw: string): CiphersImportPayload {
  const data = JSON.parse(textRaw) as Record<string, unknown>;
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  const auth = data.AUTHENTIFIANT;
  if (Array.isArray(auth)) {
    for (const item of auth) {
      if (!item || typeof item !== 'object') continue;
      const row = item as Record<string, unknown>;
      const cipher = makeLoginCipher();
      cipher.name = val(row.title, '--');
      const login = cipher.login as Record<string, unknown>;
      login.username = val(row.login, val(row.secondaryLogin, val(row.email)));
      login.password = val(row.password);
      const uri = normalizeUri(String(row.domain ?? ''));
      login.uris = uri ? [{ uri, match: null }] : null;
      cipher.notes = val(row.note);
      result.ciphers.push(cipher);
    }
  }
  return result;
}

export function parseKeePassXml(textRaw: string): CiphersImportPayload {
  const doc = new DOMParser().parseFromString(textRaw, 'application/xml');
  if (doc.querySelector('parsererror')) throw new Error('Invalid XML file');
  const rootGroup = doc.querySelector('KeePassFile > Root > Group');
  if (!rootGroup) throw new Error('Invalid KeePass XML structure');
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };

  function qd(parent: Element, selector: string): Element[] {
    return Array.from(parent.querySelectorAll(selector)).filter((x) => x.parentNode === parent);
  }

  function ensureFolder(path: string): number {
    let i = result.folders.findIndex((f) => f.name === path);
    if (i < 0) {
      i = result.folders.length;
      result.folders.push({ name: path });
    }
    return i;
  }

  function walk(group: Element, isRoot: boolean, prefix: string): void {
    let current = prefix;
    let folder = -1;
    if (!isRoot) {
      const name = txt(qd(group, 'Name')[0]?.textContent) || '-';
      current = current ? `${current}/${name}` : name;
      folder = ensureFolder(current);
    }
    for (const entry of qd(group, 'Entry')) {
      const cipher = makeLoginCipher();
      for (const s of qd(entry, 'String')) {
        const key = txt(qd(s, 'Key')[0]?.textContent);
        const valueNode = qd(s, 'Value')[0];
        const value = txt(valueNode?.textContent);
        if (!value) continue;
        const login = cipher.login as Record<string, unknown>;
        if (key === 'Title') cipher.name = value;
        else if (key === 'UserName') login.username = value;
        else if (key === 'Password') login.password = value;
        else if (key === 'URL') {
          const uri = normalizeUri(value);
          login.uris = uri ? [{ uri, match: null }] : null;
        } else if (key === 'otp') login.totp = value.replace('key=', '');
        else if (key === 'Notes') cipher.notes = `${txt(cipher.notes)}${txt(cipher.notes) ? '\n' : ''}${value}`;
        else {
          const hidden = ['True', 'true', '1'].includes(valueNode?.getAttribute('ProtectInMemory') || '')
            || ['True', 'true', '1'].includes(valueNode?.getAttribute('Protected') || '');
          processKvp(cipher, key, value, hidden);
        }
      }
      const idx = result.ciphers.push(cipher) - 1;
      if (!isRoot && folder >= 0) result.folderRelationships.push({ key: idx, value: folder });
    }
    for (const child of qd(group, 'Group')) walk(child, false, current);
  }

  walk(rootGroup, true, '');
  return result;
}
