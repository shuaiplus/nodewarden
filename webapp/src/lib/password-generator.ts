import { EFFLongWordList } from '@/lib/eff-word-list';

export type GeneratorMode = 'password' | 'passphrase' | 'pin' | 'username' | 'email' | 'sshKey';
export type EmailMode = 'plusAddressed' | 'catchAll' | 'subdomain';

export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  special: boolean;
  minUppercase: number;
  minLowercase: number;
  minNumbers: number;
  minSpecial: number;
  avoidAmbiguous: boolean;
}

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
  wordList: 'eff' | 'custom';
  customWords: string;
}

export interface PinOptions { length: number }

export interface UsernameOptions {
  words: number;
  delimiter: string;
  capitalize: boolean;
  includeNumber: boolean;
  customWord: string;
  wordList: 'eff' | 'custom';
  customWords: string;
}

export interface EmailOptions {
  type: EmailMode;
  email: string;
  domain: string;
}

export interface SshKeyOptions {
  type: 'ed25519' | 'rsa';
  rsaLength: 2048 | 3072 | 4096;
  comment: string;
}

export interface GeneratorSettings {
  mode: GeneratorMode;
  password: PasswordOptions;
  passphrase: PassphraseOptions;
  pin: PinOptions;
  username: UsernameOptions;
  email: EmailOptions;
  sshKey: SshKeyOptions;
}

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SPECIAL = '!@#$%^&*_-+=:;,.?~';
const AMBIGUOUS = new Set(['I', 'L', 'O', 'l', 'o', '0', '1', '|']);

export const defaultGeneratorSettings: GeneratorSettings = {
  mode: 'password',
  password: {
    length: 16,
    uppercase: true,
    lowercase: true,
    numbers: true,
    special: false,
    minUppercase: 1,
    minLowercase: 1,
    minNumbers: 1,
    minSpecial: 1,
    avoidAmbiguous: false,
  },
  passphrase: { words: 6, separator: '-', capitalize: false, includeNumber: false, wordList: 'eff', customWords: '' },
  pin: { length: 6 },
  username: { words: 2, delimiter: '', capitalize: true, includeNumber: true, customWord: '', wordList: 'eff', customWords: '' },
  email: { type: 'plusAddressed', email: '', domain: '' },
  sshKey: { type: 'ed25519', rsaLength: 4096, comment: '' },
};

export function clampInteger(value: unknown, minimum: number, maximum: number, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(maximum, Math.max(minimum, Math.round(parsed))) : fallback;
}

export function normalizeGeneratorSettings(value: unknown): GeneratorSettings {
  const stored = value && typeof value === 'object' ? value as Partial<GeneratorSettings> : {};
  const password: Partial<PasswordOptions> = stored.password && typeof stored.password === 'object' ? stored.password : {};
  const passphrase: Partial<PassphraseOptions> = stored.passphrase && typeof stored.passphrase === 'object' ? stored.passphrase : {};
  const pin: Partial<PinOptions> = stored.pin && typeof stored.pin === 'object' ? stored.pin : {};
  const username: Partial<UsernameOptions> = stored.username && typeof stored.username === 'object' ? stored.username : {};
  const legacyUsername = stored.username && typeof stored.username === 'object' ? stored.username as Partial<UsernameOptions> & Partial<EmailOptions> : {};
  const email: Partial<EmailOptions> = stored.email && typeof stored.email === 'object' ? stored.email : legacyUsername;
  const sshKey: Partial<SshKeyOptions> = stored.sshKey && typeof stored.sshKey === 'object' ? stored.sshKey : {};
  const modes: GeneratorMode[] = ['password', 'passphrase', 'pin', 'username', 'email', 'sshKey'];
  const emailModes: EmailMode[] = ['plusAddressed', 'catchAll', 'subdomain'];
  const rsaLengths: SshKeyOptions['rsaLength'][] = [2048, 3072, 4096];
  const mode = stored.mode === 'username' && emailModes.includes(legacyUsername.type as EmailMode)
    ? 'email'
    : modes.includes(stored.mode as GeneratorMode) ? stored.mode as GeneratorMode : defaultGeneratorSettings.mode;

  return {
    mode,
    password: {
      ...defaultGeneratorSettings.password,
      ...password,
      length: clampInteger(password.length, 5, 128, defaultGeneratorSettings.password.length),
      minUppercase: clampInteger(password.minUppercase, 0, 9, defaultGeneratorSettings.password.minUppercase),
      minLowercase: clampInteger(password.minLowercase, 0, 9, defaultGeneratorSettings.password.minLowercase),
      minNumbers: clampInteger(password.minNumbers, 0, 9, defaultGeneratorSettings.password.minNumbers),
      minSpecial: clampInteger(password.minSpecial, 0, 9, defaultGeneratorSettings.password.minSpecial),
    },
    passphrase: {
      ...defaultGeneratorSettings.passphrase,
      ...passphrase,
      words: clampInteger(passphrase.words, 3, 20, defaultGeneratorSettings.passphrase.words),
      separator: String(passphrase.separator ?? defaultGeneratorSettings.passphrase.separator).slice(0, 1),
      wordList: passphrase.wordList === 'custom' ? 'custom' : 'eff',
      customWords: String(passphrase.customWords ?? '').slice(0, 50_000),
    },
    pin: { length: clampInteger(pin.length, 3, 64, defaultGeneratorSettings.pin.length) },
    username: {
      ...defaultGeneratorSettings.username,
      ...username,
      words: clampInteger(username.words, 1, 10, defaultGeneratorSettings.username.words),
      delimiter: String(username.delimiter ?? defaultGeneratorSettings.username.delimiter).slice(0, 8),
      customWord: String(username.customWord ?? '').trim().slice(0, 128),
      wordList: username.wordList === 'custom' ? 'custom' : 'eff',
      customWords: String(username.customWords ?? '').slice(0, 50_000),
    },
    email: {
      type: emailModes.includes(email.type as EmailMode) ? email.type as EmailMode : defaultGeneratorSettings.email.type,
      email: String(email.email ?? '').trim().slice(0, 254),
      domain: String(email.domain ?? '').trim().slice(0, 253),
    },
    sshKey: {
      type: sshKey.type === 'rsa' ? 'rsa' : 'ed25519',
      rsaLength: rsaLengths.includes(sshKey.rsaLength as SshKeyOptions['rsaLength']) ? sshKey.rsaLength as SshKeyOptions['rsaLength'] : defaultGeneratorSettings.sshKey.rsaLength,
      comment: String(sshKey.comment ?? '').replace(/[\r\n]+/g, ' ').trim().slice(0, 256),
    },
  };
}

function randomIndex(length: number): number {
  if (!Number.isSafeInteger(length) || length < 1) throw new RangeError('Random source must not be empty');
  const range = 0x1_0000_0000;
  const upperBound = Math.floor(range / length) * length;
  const buffer = new Uint32Array(1);
  do crypto.getRandomValues(buffer); while (buffer[0] >= upperBound);
  return buffer[0] % length;
}

function pick(characters: string): string { return characters[randomIndex(characters.length)]; }

function shuffle(value: string[]): string[] {
  for (let index = value.length - 1; index > 0; index -= 1) {
    const next = randomIndex(index + 1);
    [value[index], value[next]] = [value[next], value[index]];
  }
  return value;
}

function filtered(characters: string, avoidAmbiguous: boolean): string {
  return avoidAmbiguous ? [...characters].filter((character) => !AMBIGUOUS.has(character)).join('') : characters;
}

export function generatePassword(options: PasswordOptions): string {
  const sets: Array<{ chars: string; minimum: number }> = [];
  if (options.uppercase) sets.push({ chars: filtered(UPPERCASE, options.avoidAmbiguous), minimum: options.minUppercase });
  if (options.lowercase) sets.push({ chars: filtered(LOWERCASE, options.avoidAmbiguous), minimum: options.minLowercase });
  if (options.numbers) sets.push({ chars: filtered(DIGITS, options.avoidAmbiguous), minimum: options.minNumbers });
  if (options.special) sets.push({ chars: SPECIAL, minimum: options.minSpecial });
  if (!sets.length) sets.push({ chars: LOWERCASE, minimum: 1 });

  const required = sets.reduce((total, set) => total + set.minimum, 0);
  const length = Math.max(options.length, required, 5);
  const allCharacters = sets.map((set) => set.chars).join('');
  const result = sets.flatMap((set) => Array.from({ length: set.minimum }, () => pick(set.chars)));
  while (result.length < length) result.push(pick(allCharacters));
  return shuffle(result).join('');
}

export function generatePassphrase(options: PassphraseOptions): string {
  const customWords = [...new Set(options.customWords.split(/[\s,;]+/).map((word) => word.trim()).filter(Boolean))];
  const wordList = options.wordList === 'custom' && customWords.length >= 2 ? customWords : EFFLongWordList;
  const words = Array.from({ length: options.words }, () => wordList[randomIndex(wordList.length)]);
  if (options.capitalize) {
    for (let index = 0; index < words.length; index += 1) words[index] = words[index][0].toUpperCase() + words[index].slice(1);
  }
  if (options.includeNumber) words[randomIndex(words.length)] += String(randomIndex(10));
  return words.join(options.separator);
}

export function generatePin(options: PinOptions): string {
  return Array.from({ length: options.length }, () => pick(DIGITS)).join('');
}

function randomWord(options: Pick<UsernameOptions, 'words' | 'delimiter' | 'capitalize' | 'includeNumber' | 'customWord' | 'wordList' | 'customWords'>): string {
  const customWords = [...new Set(options.customWords.split(/[\s,;]+/).map((word) => word.trim()).filter(Boolean))];
  const wordList = options.wordList === 'custom' && customWords.length >= 2 ? customWords : EFFLongWordList;
  const words = Array.from({ length: options.words }, () => wordList[randomIndex(wordList.length)]);
  if (options.customWord) words[randomIndex(words.length)] = options.customWord;
  if (options.capitalize) {
    for (let index = 0; index < words.length; index += 1) words[index] = words[index][0].toUpperCase() + words[index].slice(1);
  }
  if (options.includeNumber) {
    const digits = options.words === 1 ? 4 : options.words === 2 ? 3 : 2;
    const minimum = 10 ** (digits - 1);
    words[randomIndex(words.length)] += String(minimum + randomIndex(9 * minimum));
  }
  return words.join(options.delimiter);
}

function normalizeDomain(value: string): string {
  return value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^@/, '');
}

export function generateUsername(options: UsernameOptions): string {
  return randomWord(options);
}

function validDomain(value: string): string | null {
  const domain = normalizeDomain(value);
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain) ? domain : null;
}

function validEmail(value: string): { local: string; domain: string } | null {
  const match = value.trim().match(/^([^\s@+]+)(?:\+[^\s@]*)?@([^\s@]+)$/);
  const domain = match ? validDomain(match[2]) : null;
  return match && domain ? { local: match[1], domain } : null;
}

export function generateEmail(options: EmailOptions): string {
  const suffix = randomWord({ ...defaultGeneratorSettings.username, words: 1, capitalize: false, includeNumber: true });
  if (options.type === 'catchAll') {
    const domain = validDomain(options.domain);
    return domain ? `${suffix}@${domain}` : '';
  }
  const email = validEmail(options.email);
  if (!email) return '';
  return options.type === 'subdomain'
    ? `${email.local}@${suffix}.${email.domain}`
    : `${email.local}+${suffix}@${email.domain}`;
}

export function generateValue(settings: GeneratorSettings): string {
  if (settings.mode === 'passphrase') return generatePassphrase(settings.passphrase);
  if (settings.mode === 'pin') return generatePin(settings.pin);
  if (settings.mode === 'username') return generateUsername(settings.username);
  if (settings.mode === 'email') return generateEmail(settings.email);
  if (settings.mode === 'sshKey') return '';
  return generatePassword(settings.password);
}

export function estimateStrength(mode: GeneratorMode, value: string, passphraseWordCount?: number): number {
  if (mode === 'username' || mode === 'email' || mode === 'sshKey') return 0;
  if (mode === 'pin') return value.length >= 10 ? 4 : value.length >= 8 ? 3 : value.length >= 6 ? 2 : 1;
  if (mode === 'passphrase') {
    const words = passphraseWordCount ?? value.split(/[-_. ]/).filter(Boolean).length;
    return Math.min(4, Math.max(1, Math.floor(words / 2)));
  }
  return Math.min(4, Math.max(1, Math.floor(value.length / 5)));
}
