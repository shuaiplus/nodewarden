type ImportSourceEntry = { id: string; label: string };

export const IMPORT_SOURCES = [
  { id: 'bitwarden_json', label: 'Bitwarden (json)' },
  { id: 'bitwarden_csv', label: 'Bitwarden (csv)' },
  { id: 'bitwarden_zip', label: 'Bitwarden (zip)' },
  { id: 'nodewarden_json', label: 'NodeWarden (json)' },
  { id: 'onepassword_1pux', label: '1Password (1pux/json)' },
  { id: 'onepassword_1pif', label: '1Password (1pif)' },
  { id: 'onepassword_mac_csv', label: '1Password 6 and 7 Mac (csv)' },
  { id: 'onepassword_win_csv', label: '1Password 6 and 7 Windows (csv)' },
  { id: 'protonpass_json', label: 'ProtonPass (json/zip)' },
  { id: 'avira_csv', label: 'Avira (csv)' },
  { id: 'avast_csv', label: 'Avast Passwords (csv)' },
  { id: 'avast_json', label: 'Avast Passwords (json)' },
  { id: 'chrome', label: 'Chrome' },
  { id: 'edge', label: 'Edge' },
  { id: 'brave', label: 'Brave' },
  { id: 'opera', label: 'Opera' },
  { id: 'vivaldi', label: 'Vivaldi' },
  { id: 'firefox_csv', label: 'Firefox (csv)' },
  { id: 'safari_csv', label: 'Safari and macOS (csv)' },
  { id: 'lastpass', label: 'LastPass (csv)' },
  { id: 'dashlane_csv', label: 'Dashlane (csv)' },
  { id: 'dashlane_json', label: 'Dashlane (json)' },
  { id: 'keepass_csv', label: 'KeePass 1.x (csv)' },
  { id: 'keepass_xml', label: 'KeePass 2 (xml)' },
  { id: 'keepassx_csv', label: 'KeePassX (csv)' },
  { id: 'arc_csv', label: 'Arc (csv)' },
  { id: 'ascendo_csv', label: 'Ascendo DataVault (csv)' },
  { id: 'blackberry_csv', label: 'BlackBerry Password Keeper (csv)' },
  { id: 'blur_csv', label: 'Blur (csv)' },
  { id: 'buttercup_csv', label: 'Buttercup (csv)' },
  { id: 'codebook_csv', label: 'Codebook (csv)' },
  { id: 'encryptr_csv', label: 'Encryptr (csv)' },
  { id: 'enpass_csv', label: 'Enpass (csv)' },
  { id: 'enpass_json', label: 'Enpass (json)' },
  { id: 'keeper_csv', label: 'Keeper (csv)' },
  { id: 'keeper_json', label: 'Keeper (json)' },
  { id: 'logmeonce_csv', label: 'LogMeOnce (csv)' },
  { id: 'meldium_csv', label: 'Meldium (csv)' },
  { id: 'msecure_csv', label: 'mSecure (csv)' },
  { id: 'myki_csv', label: 'Myki (csv)' },
  { id: 'netwrix_csv', label: 'Netwrix Password Secure (csv)' },
  { id: 'nordpass_csv', label: 'NordPass (csv)' },
  { id: 'roboform_csv', label: 'RoboForm (csv)' },
  { id: 'zohovault_csv', label: 'Zoho Vault (csv)' },
  { id: 'passman_json', label: 'Passman (json)' },
  { id: 'passky_json', label: 'Passky (json)' },
  { id: 'psono_json', label: 'Psono (json)' },
  { id: 'passwordboss_json', label: 'Password Boss (json)' },
] as const satisfies readonly ImportSourceEntry[];

export type ImportSourceId = (typeof IMPORT_SOURCES)[number]['id'];

export function getFileAcceptBySource(source: ImportSourceId): string {
  if (source === 'bitwarden_zip') return '.zip,application/zip,application/x-zip-compressed';
  if (
    source === 'bitwarden_json' ||
    source === 'nodewarden_json' ||
    source === 'onepassword_1pux' ||
    source === 'protonpass_json' ||
    source === 'avast_json' ||
    source === 'dashlane_json' ||
    source === 'enpass_json' ||
    source === 'keeper_json' ||
    source === 'passman_json' ||
    source === 'passky_json' ||
    source === 'psono_json' ||
    source === 'passwordboss_json'
  ) {
    if (source === 'onepassword_1pux') return '.1pux,.zip,.json,application/zip,application/json';
    if (source === 'protonpass_json') return '.zip,.json,application/zip,application/json';
    return '.json,application/json';
  }
  if (source === 'onepassword_1pif') return '.1pif,.txt,.json,text/plain,application/json';
  if (source === 'keepass_xml') return '.xml,text/xml,application/xml';
  return '.csv,text/csv';
}
