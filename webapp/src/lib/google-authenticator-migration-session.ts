import type { CiphersImportPayload } from '@/lib/api/vault';
import type {
  GoogleAuthenticatorMigrationAcceptedAccount,
  GoogleAuthenticatorMigrationExcludedAccount,
  GoogleAuthenticatorMigrationPage,
} from '@/lib/google-authenticator-migration';

export type MigrationSessionStatus =
  | { phase: 'collecting' }
  | { phase: 'ready' }
  | { phase: 'blocked'; reason: MigrationSessionError };

export type MigrationSessionError =
  | 'batch-conflict'
  | 'conflicting-page'
  | 'empty-selection'
  | 'incomplete-batch'
  | 'invalid-page'
  | 'over-limit';

export interface MigrationReviewAccepted {
  id: string;
  kind: 'accepted';
  pageIndex: number;
  issuer: string;
  name: string;
  algorithm: GoogleAuthenticatorMigrationAcceptedAccount['algorithm'];
  digits: GoogleAuthenticatorMigrationAcceptedAccount['digits'];
  period: 30;
  selected: boolean;
}

export interface MigrationReviewExcluded {
  id: string;
  kind: 'excluded';
  pageIndex: number;
  reason: GoogleAuthenticatorMigrationExcludedAccount['reason'];
}

export type MigrationReviewItem = MigrationReviewAccepted | MigrationReviewExcluded;

export interface MigrationSessionSnapshot {
  status: MigrationSessionStatus;
  batchId: number | null;
  batchSize: number | null;
  version: number | null;
  receivedIndexes: number[];
  missingIndexes: number[];
  reviewItems: MigrationReviewItem[];
  selectedCount: number;
}

interface StoredPage {
  fingerprint: string;
  accounts: GoogleAuthenticatorMigrationPage['accounts'];
}

interface CandidateSecret {
  totp: string;
}

const MAX_IMPORT_SELECTION = 500;
const FALLBACK_LOGIN_NAME = 'Authenticator';

function pageFingerprint(page: GoogleAuthenticatorMigrationPage): string {
  return JSON.stringify({
    batchId: page.batchId,
    batchSize: page.batchSize,
    batchIndex: page.batchIndex,
    version: page.version,
    accounts: page.accounts,
  });
}

export function loginNameForMigrationAccount(
  account: Pick<GoogleAuthenticatorMigrationAcceptedAccount, 'issuer' | 'name'>
): string {
  const issuer = String(account.issuer || '').trim();
  const name = String(account.name || '').trim();
  if (issuer && name) return `${issuer}: ${name}`;
  if (issuer) return issuer;
  if (name) return name;
  return FALLBACK_LOGIN_NAME;
}

export class GoogleAuthenticatorMigrationSession {
  private pages = new Map<number, StoredPage>();
  private batchId: number | null = null;
  private batchSize: number | null = null;
  private version: number | null = null;
  private blocked: MigrationSessionError | null = null;
  private secrets = new Map<string, CandidateSecret>();
  private selected = new Set<string>();
  private reviewOrder: string[] = [];
  private reviewMeta = new Map<string, MigrationReviewItem>();

  clear(): void {
    this.pages.clear();
    this.batchId = null;
    this.batchSize = null;
    this.version = null;
    this.blocked = null;
    this.secrets.clear();
    this.selected.clear();
    this.reviewOrder = [];
    this.reviewMeta.clear();
  }

  addPage(page: GoogleAuthenticatorMigrationPage):
    | { ok: true; duplicate: boolean }
    | { ok: false; reason: MigrationSessionError } {
    if (this.blocked) return { ok: false, reason: this.blocked };

    if (
      !Number.isInteger(page.batchSize)
      || page.batchSize < 1
      || page.batchIndex < 0
      || page.batchIndex >= page.batchSize
      || page.version !== 1
    ) {
      return { ok: false, reason: 'invalid-page' };
    }

    if (this.batchId == null) {
      this.batchId = page.batchId;
      this.batchSize = page.batchSize;
      this.version = page.version;
    } else if (
      this.batchId !== page.batchId
      || this.batchSize !== page.batchSize
      || this.version !== page.version
    ) {
      return { ok: false, reason: 'batch-conflict' };
    }

    const fingerprint = pageFingerprint(page);
    const existing = this.pages.get(page.batchIndex);
    if (existing) {
      if (existing.fingerprint === fingerprint) return { ok: true, duplicate: true };
      this.blocked = 'conflicting-page';
      return { ok: false, reason: 'conflicting-page' };
    }

    if (this.pages.size >= (this.batchSize || 0)) {
      return { ok: false, reason: 'over-limit' };
    }

    this.pages.set(page.batchIndex, { fingerprint, accounts: page.accounts });
    if (this.isComplete()) this.rebuildReview();
    return { ok: true, duplicate: false };
  }

  setSelected(id: string, selected: boolean): void {
    const item = this.reviewMeta.get(id);
    if (!item || item.kind !== 'accepted') return;
    if (selected) this.selected.add(id);
    else this.selected.delete(id);
    item.selected = selected;
  }

  clearSecrets(): void {
    this.secrets.clear();
  }

  snapshot(): MigrationSessionSnapshot {
    const receivedIndexes = [...this.pages.keys()].sort((a, b) => a - b);
    const missingIndexes: number[] = [];
    if (this.batchSize != null) {
      for (let index = 0; index < this.batchSize; index += 1) {
        if (!this.pages.has(index)) missingIndexes.push(index);
      }
    }

    let status: MigrationSessionStatus = { phase: 'collecting' };
    if (this.blocked) status = { phase: 'blocked', reason: this.blocked };
    else if (this.isComplete()) status = { phase: 'ready' };

    const reviewItems = this.reviewOrder
      .map((id) => this.reviewMeta.get(id))
      .filter((item): item is MigrationReviewItem => !!item);

    return {
      status,
      batchId: this.batchId,
      batchSize: this.batchSize,
      version: this.version,
      receivedIndexes,
      missingIndexes,
      reviewItems,
      selectedCount: this.selected.size,
    };
  }

  buildImportPayload():
    | { ok: true; payload: CiphersImportPayload }
    | { ok: false; reason: MigrationSessionError } {
    if (this.blocked) return { ok: false, reason: this.blocked };
    if (!this.isComplete()) return { ok: false, reason: 'incomplete-batch' };

    const selectedIds = this.reviewOrder.filter((id) => this.selected.has(id));
    if (!selectedIds.length) return { ok: false, reason: 'empty-selection' };
    if (selectedIds.length > MAX_IMPORT_SELECTION) return { ok: false, reason: 'over-limit' };

    const ciphers: Array<Record<string, unknown>> = [];
    for (const id of selectedIds) {
      const meta = this.reviewMeta.get(id);
      const secret = this.secrets.get(id);
      if (!meta || meta.kind !== 'accepted' || !secret?.totp) {
        return { ok: false, reason: 'invalid-page' };
      }
      ciphers.push({
        type: 1,
        name: loginNameForMigrationAccount(meta),
        notes: '',
        favorite: false,
        reprompt: 0,
        login: {
          username: '',
          password: '',
          totp: secret.totp,
          uris: [],
        },
        fields: [],
      });
    }

    return {
      ok: true,
      payload: {
        ciphers,
        folders: [],
        folderRelationships: [],
      },
    };
  }

  private isComplete(): boolean {
    return this.batchSize != null && this.pages.size === this.batchSize;
  }

  private rebuildReview(): void {
    this.secrets.clear();
    this.selected.clear();
    this.reviewOrder = [];
    this.reviewMeta.clear();

    const indexes = [...this.pages.keys()].sort((a, b) => a - b);
    let acceptedCount = 0;
    for (const pageIndex of indexes) {
      const page = this.pages.get(pageIndex);
      if (!page) continue;
      page.accounts.forEach((account, accountIndex) => {
        const id = `p${pageIndex}-a${accountIndex}`;
        this.reviewOrder.push(id);
        if (account.kind === 'accepted') {
          acceptedCount += 1;
          if (acceptedCount > MAX_IMPORT_SELECTION) {
            this.blocked = 'over-limit';
            return;
          }
          this.secrets.set(id, { totp: account.totp });
          this.selected.add(id);
          this.reviewMeta.set(id, {
            id,
            kind: 'accepted',
            pageIndex,
            issuer: account.issuer,
            name: account.name,
            algorithm: account.algorithm,
            digits: account.digits,
            period: account.period,
            selected: true,
          });
        } else {
          this.reviewMeta.set(id, {
            id,
            kind: 'excluded',
            pageIndex,
            reason: account.reason,
          });
        }
      });
      if (this.blocked) break;
    }
  }
}
