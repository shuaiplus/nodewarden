import { useEffect, useMemo, useState } from 'preact/hooks';
import { Check, Copy, Minus, Plus, RefreshCw, ShieldCheck } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import { EFFLongWordList } from '@/lib/eff-word-list';
import { t } from '@/lib/i18n';

type GeneratorMode = 'password' | 'passphrase';

interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  special: boolean;
  minNumbers: number;
  minSpecial: number;
  avoidAmbiguous: boolean;
}

interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

const SETTINGS_KEY = 'nodewarden.passwordGenerator.settings.v1';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SPECIAL = '!@#$%^&*';
const AMBIGUOUS = new Set(['I', 'L', 'O', 'l', 'o', '0', '1']);

const defaultPasswordOptions: PasswordOptions = {
  length: 14,
  uppercase: true,
  lowercase: true,
  numbers: true,
  special: false,
  minNumbers: 1,
  minSpecial: 1,
  avoidAmbiguous: false,
};

const defaultPassphraseOptions: PassphraseOptions = {
  words: 6,
  separator: '-',
  capitalize: false,
  includeNumber: false,
};

function clamp(value: unknown, minimum: number, maximum: number, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(maximum, Math.max(minimum, Math.round(parsed))) : fallback;
}

function readSettings(): { mode: GeneratorMode; password: PasswordOptions; passphrase: PassphraseOptions } {
  try {
    const stored = JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') as Partial<{ mode: GeneratorMode; password: Partial<PasswordOptions>; passphrase: Partial<PassphraseOptions> }>;
    return {
      mode: stored.mode === 'passphrase' ? 'passphrase' : 'password',
      password: {
        ...defaultPasswordOptions,
        ...stored.password,
        length: clamp(stored.password?.length, 5, 128, defaultPasswordOptions.length),
        minNumbers: clamp(stored.password?.minNumbers, 0, 9, defaultPasswordOptions.minNumbers),
        minSpecial: clamp(stored.password?.minSpecial, 0, 9, defaultPasswordOptions.minSpecial),
      },
      passphrase: {
        ...defaultPassphraseOptions,
        ...stored.passphrase,
        words: clamp(stored.passphrase?.words, 3, 20, defaultPassphraseOptions.words),
        separator: String(stored.passphrase?.separator ?? defaultPassphraseOptions.separator).slice(0, 1),
      },
    };
  } catch {
    return { mode: 'password', password: defaultPasswordOptions, passphrase: defaultPassphraseOptions };
  }
}

function randomIndex(length: number): number {
  const range = 0x1_0000_0000;
  const upperBound = Math.floor(range / length) * length;
  const buffer = new Uint32Array(1);
  do crypto.getRandomValues(buffer); while (buffer[0] >= upperBound);
  return buffer[0] % length;
}

function pick(characters: string): string {
  return characters[randomIndex(characters.length)];
}

function shuffle(value: string[]): string[] {
  for (let index = value.length - 1; index > 0; index -= 1) {
    const next = randomIndex(index + 1);
    [value[index], value[next]] = [value[next], value[index]];
  }
  return value;
}

function filtered(characters: string, avoidAmbiguous: boolean): string {
  return avoidAmbiguous ? characters.split('').filter((character) => !AMBIGUOUS.has(character)).join('') : characters;
}

function generatePassword(options: PasswordOptions): string {
  const sets: Array<{ chars: string; minimum: number }> = [];
  if (options.uppercase) sets.push({ chars: filtered(UPPERCASE, options.avoidAmbiguous), minimum: 1 });
  if (options.lowercase) sets.push({ chars: filtered(LOWERCASE, options.avoidAmbiguous), minimum: 1 });
  if (options.numbers) sets.push({ chars: filtered(DIGITS, options.avoidAmbiguous), minimum: options.minNumbers });
  if (options.special) sets.push({ chars: SPECIAL, minimum: options.minSpecial });
  if (!sets.length) sets.push({ chars: filtered(LOWERCASE, options.avoidAmbiguous), minimum: 1 });

  const minimumLength = sets.reduce((total, set) => total + set.minimum, 0);
  const length = Math.max(options.length, minimumLength, 5);
  const allCharacters = sets.map((set) => set.chars).join('');
  const characters = sets.flatMap((set) => Array.from({ length: set.minimum }, () => pick(set.chars)));
  while (characters.length < length) characters.push(pick(allCharacters));
  return shuffle(characters).join('');
}

function generatePassphrase(options: PassphraseOptions): string {
  const words = Array.from({ length: options.words }, () => EFFLongWordList[randomIndex(EFFLongWordList.length)]);
  if (options.capitalize) {
    for (let index = 0; index < words.length; index += 1) words[index] = words[index][0].toUpperCase() + words[index].slice(1);
  }
  if (options.includeNumber) words[randomIndex(words.length)] += String(randomIndex(10));
  return words.join(options.separator);
}

function strengthLabel(mode: GeneratorMode, value: string): { label: string; score: number } {
  const score = mode === 'password' ? Math.min(4, Math.max(1, Math.floor(value.length / 5))) : Math.min(4, Math.max(1, Math.floor(value.split(/[-_. ]/).filter(Boolean).length / 2)));
  return { score, label: t(['txt_password_strength_weak', 'txt_password_strength_fair', 'txt_password_strength_good', 'txt_password_strength_strong'][score - 1]) };
}

export default function PasswordGeneratorPage() {
  const initial = useMemo(readSettings, []);
  const [mode, setMode] = useState<GeneratorMode>(initial.mode);
  const [passwordOptions, setPasswordOptions] = useState<PasswordOptions>(initial.password);
  const [passphraseOptions, setPassphraseOptions] = useState<PassphraseOptions>(initial.passphrase);
  const [seed, setSeed] = useState(0);
  const [copied, setCopied] = useState(false);

  const generated = useMemo(
    () => (mode === 'password' ? generatePassword(passwordOptions) : generatePassphrase(passphraseOptions)),
    [mode, passwordOptions, passphraseOptions, seed]
  );
  const strength = useMemo(() => strengthLabel(mode, generated), [generated, mode]);

  useEffect(() => {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify({ mode, password: passwordOptions, passphrase: passphraseOptions }));
    } catch {
      // The generator remains fully usable when browser storage is unavailable.
    }
  }, [mode, passwordOptions, passphraseOptions]);

  const regenerate = () => {
    setCopied(false);
    setSeed((value) => value + 1);
  };

  const copy = async () => {
    await copyTextToClipboard(generated, { onSuccess: () => setCopied(true), onError: () => setCopied(false) });
    window.setTimeout(() => setCopied(false), 1600);
  };

  const changePasswordOption = <K extends keyof PasswordOptions>(key: K, value: PasswordOptions[K]) => {
    setPasswordOptions((current) => ({ ...current, [key]: value }));
    setCopied(false);
  };

  const changePassphraseOption = <K extends keyof PassphraseOptions>(key: K, value: PassphraseOptions[K]) => {
    setPassphraseOptions((current) => ({ ...current, [key]: value }));
    setCopied(false);
  };

  return (
    <section className="generator-page" aria-label={t('txt_password_generator')}>
      <div className="generator-layout">
        <section className="generator-output-card" aria-live="polite">
          <div className="settings-category-tabs" role="tablist" aria-label={t('txt_generator_type')}>
            <button type="button" role="tab" aria-selected={mode === 'password'} className={`settings-category-tab ${mode === 'password' ? 'active' : ''}`} onClick={() => setMode('password')}>{t('txt_password')}</button>
            <button type="button" role="tab" aria-selected={mode === 'passphrase'} className={`settings-category-tab ${mode === 'passphrase' ? 'active' : ''}`} onClick={() => setMode('passphrase')}>{t('txt_passphrase')}</button>
          </div>
          <output className="generator-value" aria-label={t('txt_generated_password')}>{generated}</output>
          <div className="generator-strength-row">
            <div className="generator-strength" aria-label={`${t('txt_password_strength')}: ${strength.label}`}>
              {[1, 2, 3, 4].map((level) => <span key={level} className={level <= strength.score ? `active level-${strength.score}` : ''} />)}
            </div>
            <span><ShieldCheck size={15} /> {strength.label}</span>
          </div>
          <div className="actions generator-actions">
            <button type="button" className="btn btn-primary" onClick={regenerate}><RefreshCw size={16} className="btn-icon" />{t('txt_regenerate')}</button>
            <button type="button" className="btn btn-secondary" onClick={() => void copy()}><Copy size={16} className="btn-icon" />{copied ? t('txt_copied') : t('txt_copy')}</button>
          </div>
          <p className="generator-security-note"><Check size={15} />{t('txt_generator_security_note')}</p>
        </section>

        <section className="generator-options-card" aria-labelledby="generator-options-title">
          <h2 id="generator-options-title">{t('txt_options')}</h2>
          {mode === 'password' ? (
            <>
              <GeneratorNumberStepper id="length" label={t('txt_generator_length')} value={passwordOptions.length} minimum={5} maximum={128} fallback={14} onChange={(value) => changePasswordOption('length', value)} />
              <fieldset className="generator-option-group"><legend>{t('txt_generator_character_types')}</legend>
                <GeneratorToggle checked={passwordOptions.uppercase} onChange={(checked) => changePasswordOption('uppercase', checked)} label={t('txt_generator_uppercase')} />
                <GeneratorToggle checked={passwordOptions.lowercase} onChange={(checked) => changePasswordOption('lowercase', checked)} label={t('txt_generator_lowercase')} />
                <GeneratorToggle checked={passwordOptions.numbers} onChange={(checked) => changePasswordOption('numbers', checked)} label={t('txt_generator_numbers')} />
                {passwordOptions.numbers && <GeneratorNumberStepper id="min-numbers" compact label={t('txt_generator_minimum')} value={passwordOptions.minNumbers} minimum={0} maximum={9} fallback={1} onChange={(value) => changePasswordOption('minNumbers', value)} />}
                <GeneratorToggle checked={passwordOptions.special} onChange={(checked) => changePasswordOption('special', checked)} label={t('txt_generator_special')} />
                {passwordOptions.special && <GeneratorNumberStepper id="min-special" compact label={t('txt_generator_minimum')} value={passwordOptions.minSpecial} minimum={0} maximum={9} fallback={1} onChange={(value) => changePasswordOption('minSpecial', value)} />}
              </fieldset>
              <GeneratorToggle checked={passwordOptions.avoidAmbiguous} onChange={(checked) => changePasswordOption('avoidAmbiguous', checked)} label={t('txt_generator_avoid_ambiguous')} />
            </>
          ) : (
            <>
              <GeneratorNumberStepper id="words" label={t('txt_generator_words')} value={passphraseOptions.words} minimum={3} maximum={20} fallback={6} onChange={(value) => changePassphraseOption('words', value)} />
              <label className="generator-number-field" htmlFor="generator-separator"><span>{t('txt_generator_separator')}</span><input id="generator-separator" className="input" type="text" maxLength={1} value={passphraseOptions.separator} onInput={(event) => changePassphraseOption('separator', event.currentTarget.value.slice(0, 1))} /></label>
              <div className="generator-option-group">
                <GeneratorToggle checked={passphraseOptions.capitalize} onChange={(checked) => changePassphraseOption('capitalize', checked)} label={t('txt_generator_capitalize')} />
                <GeneratorToggle checked={passphraseOptions.includeNumber} onChange={(checked) => changePassphraseOption('includeNumber', checked)} label={t('txt_generator_include_number')} />
              </div>
            </>
          )}
        </section>
      </div>
    </section>
  );
}

function GeneratorToggle(props: { checked: boolean; label: string; onChange: (checked: boolean) => void }) {
  return <label className="generator-toggle"><input type="checkbox" checked={props.checked} onChange={(event) => props.onChange(event.currentTarget.checked)} /><span aria-hidden="true" /><strong>{props.label}</strong></label>;
}

function GeneratorNumberStepper(props: { id: string; label: string; value: number; minimum: number; maximum: number; fallback: number; compact?: boolean; onChange: (value: number) => void }) {
  const id = `generator-stepper-${props.id}`;
  const setValue = (value: number) => props.onChange(clamp(value, props.minimum, props.maximum, props.fallback));
  return (
    <div className={`generator-number-field ${props.compact ? 'compact' : ''}`}>
      <label htmlFor={id}>{props.label}</label>
      <div className="generator-stepper">
        <button type="button" aria-label={`${props.label} -`} disabled={props.value <= props.minimum} onClick={() => setValue(props.value - 1)}><Minus size={15} /></button>
        <input id={id} className="input" type="text" inputMode="numeric" pattern="[0-9]*" value={props.value} onInput={(event) => setValue(Number(event.currentTarget.value))} />
        <button type="button" aria-label={`${props.label} +`} disabled={props.value >= props.maximum} onClick={() => setValue(props.value + 1)}><Plus size={15} /></button>
      </div>
    </div>
  );
}
