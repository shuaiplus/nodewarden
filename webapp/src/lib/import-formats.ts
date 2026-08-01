import type { CiphersImportPayload } from '@/lib/api/vault';
import type { ImportSourceId } from '@/lib/import-format-sources';
import {
  parseArcCsv,
  parseAscendoCsv,
  parseBlackberryCsv,
  parseBlurCsv,
  parseButtercupCsv,
  parseCodebookCsv,
  parseDashlaneCsv,
  parseDashlaneJson,
  parseEncryptrCsv,
  parseKeePassCsv,
  parseKeePassXCsv,
  parseKeePassXml,
  parseLastPassCsv,
} from '@/lib/import-formats-csv-misc';
import {
  parseAvastCsv,
  parseAvastJson,
  parseAviraCsv,
  parseBitwardenCsv,
  parseChromeCsv,
  parseFirefoxCsv,
  parseSafariCsv,
} from '@/lib/import-formats-browser';
import {
  parseMSecureCsv,
  parseMykiCsv,
  parseNetwrixCsv,
  parseNordpassCsv,
  parsePasskyJson,
  parsePassmanJson,
  parsePasswordBossJson,
  parsePsonoJson,
  parseRoboFormCsv,
  parseZohoVaultCsv,
} from '@/lib/import-formats-advanced';
import { parseOnePassword1Pif, parseOnePassword1PuxJson, parseOnePasswordCsv } from '@/lib/import-formats-onepassword';
import {
  parseEnpassCsv,
  parseEnpassJson,
  parseKeeperCsv,
  parseKeeperJson,
  parseLogMeOnceCsv,
  parseMeldiumCsv,
  parseProtonPassJson,
} from '@/lib/import-formats-password-managers';

const IMPORT_SOURCE_PARSERS: Record<ImportSourceId, (textRaw: string) => CiphersImportPayload> = {
  bitwarden_json: () => {
    throw new Error('bitwarden_json is handled by dedicated JSON flow');
  },
  bitwarden_zip: () => {
    throw new Error('bitwarden_zip is handled by dedicated zip flow');
  },
  nodewarden_json: () => {
    throw new Error('nodewarden_json is handled by dedicated JSON flow');
  },
  bitwarden_csv: parseBitwardenCsv,
  onepassword_1pux: parseOnePassword1PuxJson,
  onepassword_1pif: parseOnePassword1Pif,
  onepassword_mac_csv: (textRaw) => parseOnePasswordCsv(textRaw, true),
  onepassword_win_csv: (textRaw) => parseOnePasswordCsv(textRaw, false),
  protonpass_json: parseProtonPassJson,
  avira_csv: parseAviraCsv,
  avast_csv: parseAvastCsv,
  avast_json: parseAvastJson,
  chrome: parseChromeCsv,
  edge: parseChromeCsv,
  brave: parseChromeCsv,
  opera: parseChromeCsv,
  vivaldi: parseChromeCsv,
  firefox_csv: parseFirefoxCsv,
  safari_csv: parseSafariCsv,
  lastpass: parseLastPassCsv,
  dashlane_csv: parseDashlaneCsv,
  dashlane_json: parseDashlaneJson,
  keepass_csv: parseKeePassCsv,
  keepass_xml: parseKeePassXml,
  keepassx_csv: parseKeePassXCsv,
  arc_csv: parseArcCsv,
  ascendo_csv: parseAscendoCsv,
  blackberry_csv: parseBlackberryCsv,
  blur_csv: parseBlurCsv,
  buttercup_csv: parseButtercupCsv,
  codebook_csv: parseCodebookCsv,
  encryptr_csv: parseEncryptrCsv,
  enpass_csv: parseEnpassCsv,
  enpass_json: parseEnpassJson,
  keeper_csv: parseKeeperCsv,
  keeper_json: parseKeeperJson,
  logmeonce_csv: parseLogMeOnceCsv,
  meldium_csv: parseMeldiumCsv,
  msecure_csv: parseMSecureCsv,
  myki_csv: parseMykiCsv,
  netwrix_csv: parseNetwrixCsv,
  nordpass_csv: parseNordpassCsv,
  roboform_csv: parseRoboFormCsv,
  zohovault_csv: parseZohoVaultCsv,
  passman_json: parsePassmanJson,
  passky_json: parsePasskyJson,
  psono_json: parsePsonoJson,
  passwordboss_json: parsePasswordBossJson,
};

export function parseImportPayloadBySource(source: ImportSourceId, textRaw: string): CiphersImportPayload {
  return IMPORT_SOURCE_PARSERS[source](textRaw);
}
