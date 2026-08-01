import { useEffect, useMemo, useState } from 'preact/hooks';
import { Check, Copy, Download, LoaderCircle, Minus, Plus, RefreshCw, ShieldCheck } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import { t } from '@/lib/i18n';
import {
  clampInteger,
  defaultGeneratorSettings,
  estimateStrength,
  generateValue,
  normalizeGeneratorSettings,
  type EmailMode,
  type EmailOptions,
  type GeneratorMode,
  type GeneratorSettings,
  type PassphraseOptions,
  type PasswordOptions,
  type PinOptions,
  type SshKeyOptions,
  type UsernameOptions,
} from '@/lib/password-generator';
import { generateSshKey, type GeneratedSshKey } from '@/lib/ssh-key-generator';

const SETTINGS_KEY = 'nodewarden.passwordGenerator.settings.v2';

function readSettings(): GeneratorSettings {
  try {
    const current = localStorage.getItem(SETTINGS_KEY);
    if (current) return normalizeGeneratorSettings(JSON.parse(current));

    // Preserve compatible options for users upgrading from the original generator.
    const legacy = JSON.parse(localStorage.getItem('nodewarden.passwordGenerator.settings.v1') || '{}');
    return normalizeGeneratorSettings(legacy);
  } catch {
    return defaultGeneratorSettings;
  }
}

export default function PasswordGeneratorPage() {
  const initial = useMemo(readSettings, []);
  const [settings, setSettings] = useState<GeneratorSettings>(initial);
  const [seed, setSeed] = useState(0);
  const [copied, setCopied] = useState(false);
  const [sshKey, setSshKey] = useState<GeneratedSshKey | null>(null);
  const [sshKeyError, setSshKeyError] = useState('');
  const [sshKeyLoading, setSshKeyLoading] = useState(false);

  const generated = useMemo(() => settings.mode === 'sshKey' ? sshKey?.fingerprint || '' : generateValue(settings), [settings, seed, sshKey]);
  const strength = useMemo(
    () => estimateStrength(settings.mode, generated, settings.mode === 'passphrase' ? settings.passphrase.words : undefined),
    [generated, settings.mode, settings.passphrase.words],
  );
  const strengthLabel = strength
    ? t(['txt_password_strength_weak', 'txt_password_strength_fair', 'txt_password_strength_good', 'txt_password_strength_strong'][strength - 1])
    : '';

  useEffect(() => {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    } catch {
      // The generator remains fully usable when browser storage is unavailable.
    }
  }, [settings]);

  useEffect(() => {
    if (settings.mode !== 'sshKey') return;
    let cancelled = false;
    setSshKeyLoading(true);
    setSshKeyError('');
    void generateSshKey({ ...settings.sshKey, comment: '' })
      .then((value) => { if (!cancelled) setSshKey(value); })
      .catch(() => { if (!cancelled) { setSshKey(null); setSshKeyError(t('txt_generator_ssh_error')); } })
      .finally(() => { if (!cancelled) setSshKeyLoading(false); });
    return () => { cancelled = true; };
  }, [settings.mode, settings.sshKey.type, settings.sshKey.rsaLength, seed]);

  const regenerate = () => {
    setCopied(false);
    setSeed((value) => value + 1);
  };

  const copy = async () => {
    const value = settings.mode === 'sshKey' && sshKey ? publicKeyWithComment(sshKey.publicKey, settings.sshKey.comment) : generated;
    await copyTextToClipboard(value, { onSuccess: () => setCopied(true), onError: () => setCopied(false) });
    window.setTimeout(() => setCopied(false), 1600);
  };

  const changeMode = (mode: GeneratorMode) => {
    setSettings((current) => ({ ...current, mode }));
    setCopied(false);
  };

  const changePasswordOption = <K extends keyof PasswordOptions>(key: K, value: PasswordOptions[K]) => {
    setSettings((current) => ({ ...current, password: { ...current.password, [key]: value } }));
    setCopied(false);
  };

  const changeCharacterType = (key: 'uppercase' | 'lowercase' | 'numbers' | 'special', checked: boolean) => {
    const enabled = ['uppercase', 'lowercase', 'numbers', 'special'].filter((item) => settings.password[item as 'uppercase']);
    if (!checked && enabled.length === 1 && enabled[0] === key) return;
    changePasswordOption(key, checked);
  };

  const changePassphraseOption = <K extends keyof PassphraseOptions>(key: K, value: PassphraseOptions[K]) => {
    setSettings((current) => ({ ...current, passphrase: { ...current.passphrase, [key]: value } }));
    setCopied(false);
  };

  const changePinOption = <K extends keyof PinOptions>(key: K, value: PinOptions[K]) => {
    setSettings((current) => ({ ...current, pin: { ...current.pin, [key]: value } }));
    setCopied(false);
  };

  const changeUsernameOption = <K extends keyof UsernameOptions>(key: K, value: UsernameOptions[K]) => {
    setSettings((current) => ({ ...current, username: { ...current.username, [key]: value } }));
    setCopied(false);
  };

  const changeEmailOption = <K extends keyof EmailOptions>(key: K, value: EmailOptions[K]) => {
    setSettings((current) => ({ ...current, email: { ...current.email, [key]: value } }));
    setCopied(false);
  };

  const changeSshKeyOption = <K extends keyof SshKeyOptions>(key: K, value: SshKeyOptions[K]) => {
    setSettings((current) => ({ ...current, sshKey: { ...current.sshKey, [key]: value } }));
    setCopied(false);
  };

  return (
    <section className="generator-page" aria-label={t('txt_password_generator')}>
      <div className="generator-layout">
        <section className="generator-output-card" aria-live="polite">
          <div className="settings-category-tabs generator-mode-tabs" role="tablist" aria-label={t('txt_generator_type')}>
            {([
              ['password', 'txt_password'],
              ['passphrase', 'txt_passphrase'],
              ['pin', 'txt_generator_pin'],
              ['username', 'txt_generator_username'],
              ['email', 'txt_generator_email_alias'],
              ['sshKey', 'txt_generator_ssh_key'],
            ] as const).map(([mode, label]) => (
              <button key={mode} type="button" role="tab" aria-selected={settings.mode === mode} className={`settings-category-tab ${settings.mode === mode ? 'active' : ''}`} onClick={() => changeMode(mode)}>{t(label)}</button>
            ))}
          </div>
          {settings.mode === 'sshKey' ? (
            <SshKeyOutput value={sshKey} loading={sshKeyLoading} error={sshKeyError} comment={settings.sshKey.comment} />
          ) : <output className={`generator-value ${generated ? '' : 'empty'}`} aria-label={t('txt_generated_value')}>{generated || t('txt_generator_email_required_hint')}</output>}
          {settings.mode !== 'sshKey' && <div className="generator-meta-row">
            {strength > 0 ? (
              <>
                <div className="generator-strength" aria-label={`${t('txt_password_strength')}: ${strengthLabel}`}>
                  {[1, 2, 3, 4].map((level) => <span key={level} className={level <= strength ? `active level-${strength}` : ''} />)}
                </div>
                <span><ShieldCheck size={15} /> {strengthLabel}</span>
              </>
            ) : <span />}
            <span>{t('txt_generator_character_count', { count: generated.length })}</span>
          </div>}
          <div className="actions generator-actions">
            <button type="button" className="btn btn-primary" disabled={sshKeyLoading} onClick={regenerate}>{sshKeyLoading ? <LoaderCircle size={16} className="btn-icon generator-spinner" /> : <RefreshCw size={16} className="btn-icon" />}{t('txt_regenerate')}</button>
            <button type="button" className="btn btn-secondary" disabled={(settings.mode === 'sshKey' && !sshKey) || !generated} onClick={() => void copy()}><Copy size={16} className="btn-icon" />{copied ? t('txt_copied') : settings.mode === 'sshKey' ? t('txt_generator_copy_public_key') : t('txt_copy')}</button>
          </div>
          <p className="generator-security-note"><Check size={15} />{t(settings.mode === 'sshKey' ? 'txt_generator_ssh_security_note' : 'txt_generator_security_note')}</p>
        </section>

        <section className="generator-options-card" aria-labelledby="generator-options-title">
          <h2 id="generator-options-title">{t('txt_options')}</h2>
          {settings.mode === 'password' && (
            <PasswordOptionFields options={settings.password} onChange={changePasswordOption} onCharacterTypeChange={changeCharacterType} />
          )}
          {settings.mode === 'passphrase' && (
            <>
              <GeneratorNumberStepper id="words" label={t('txt_generator_words')} value={settings.passphrase.words} minimum={3} maximum={20} fallback={6} onChange={(value) => changePassphraseOption('words', value)} />
              <label className="generator-select-field" htmlFor="generator-word-list"><span>{t('txt_generator_word_list')}</span><select id="generator-word-list" className="input" value={settings.passphrase.wordList} onChange={(event) => changePassphraseOption('wordList', event.currentTarget.value as 'eff' | 'custom')}><option value="eff">{t('txt_generator_eff_word_list')}</option><option value="custom">{t('txt_generator_custom_word_list')}</option></select></label>
              {settings.passphrase.wordList === 'custom' && <label className="generator-text-field" htmlFor="generator-custom-words"><span>{t('txt_generator_custom_words')}</span><textarea id="generator-custom-words" className="input generator-word-list-input" rows={6} spellcheck={false} placeholder={t('txt_generator_custom_words_placeholder')} value={settings.passphrase.customWords} onInput={(event) => changePassphraseOption('customWords', event.currentTarget.value)} /></label>}
              <label className="generator-number-field" htmlFor="generator-separator"><span>{t('txt_generator_separator')}</span><input id="generator-separator" className="input" type="text" maxLength={1} value={settings.passphrase.separator} onInput={(event) => changePassphraseOption('separator', event.currentTarget.value.slice(0, 1))} /></label>
              <div className="generator-option-group">
                <GeneratorToggle checked={settings.passphrase.capitalize} onChange={(checked) => changePassphraseOption('capitalize', checked)} label={t('txt_generator_capitalize')} />
                <GeneratorToggle checked={settings.passphrase.includeNumber} onChange={(checked) => changePassphraseOption('includeNumber', checked)} label={t('txt_generator_include_number')} />
              </div>
            </>
          )}
          {settings.mode === 'pin' && (
            <>
              <GeneratorNumberStepper id="pin-length" label={t('txt_generator_length')} value={settings.pin.length} minimum={3} maximum={64} fallback={6} onChange={(value) => changePinOption('length', value)} />
              <p className="generator-options-note">{t('txt_generator_pin_description')}</p>
            </>
          )}
          {settings.mode === 'username' && (
            <UsernameOptionFields options={settings.username} onChange={changeUsernameOption} />
          )}
          {settings.mode === 'email' && (
            <EmailOptionFields options={settings.email} onChange={changeEmailOption} />
          )}
          {settings.mode === 'sshKey' && (
            <SshKeyOptionFields options={settings.sshKey} onChange={changeSshKeyOption} />
          )}
        </section>
      </div>
    </section>
  );
}

function PasswordOptionFields(props: { options: PasswordOptions; onChange: <K extends keyof PasswordOptions>(key: K, value: PasswordOptions[K]) => void; onCharacterTypeChange: (key: 'uppercase' | 'lowercase' | 'numbers' | 'special', checked: boolean) => void }) {
  const { options } = props;
  return (
    <>
      <GeneratorNumberStepper id="length" label={t('txt_generator_length')} value={options.length} minimum={5} maximum={128} fallback={16} onChange={(value) => props.onChange('length', value)} />
      <fieldset className="generator-option-group"><legend>{t('txt_generator_character_types')}</legend>
        <GeneratorToggle checked={options.uppercase} onChange={(checked) => props.onCharacterTypeChange('uppercase', checked)} label={t('txt_generator_uppercase')} />
        {options.uppercase && <GeneratorNumberStepper id="min-uppercase" compact label={t('txt_generator_minimum')} value={options.minUppercase} minimum={0} maximum={9} fallback={1} onChange={(value) => props.onChange('minUppercase', value)} />}
        <GeneratorToggle checked={options.lowercase} onChange={(checked) => props.onCharacterTypeChange('lowercase', checked)} label={t('txt_generator_lowercase')} />
        {options.lowercase && <GeneratorNumberStepper id="min-lowercase" compact label={t('txt_generator_minimum')} value={options.minLowercase} minimum={0} maximum={9} fallback={1} onChange={(value) => props.onChange('minLowercase', value)} />}
        <GeneratorToggle checked={options.numbers} onChange={(checked) => props.onCharacterTypeChange('numbers', checked)} label={t('txt_generator_numbers')} />
        {options.numbers && <GeneratorNumberStepper id="min-numbers" compact label={t('txt_generator_minimum')} value={options.minNumbers} minimum={0} maximum={9} fallback={1} onChange={(value) => props.onChange('minNumbers', value)} />}
        <GeneratorToggle checked={options.special} onChange={(checked) => props.onCharacterTypeChange('special', checked)} label={t('txt_generator_special')} />
        {options.special && <GeneratorNumberStepper id="min-special" compact label={t('txt_generator_minimum')} value={options.minSpecial} minimum={0} maximum={9} fallback={1} onChange={(value) => props.onChange('minSpecial', value)} />}
      </fieldset>
      <GeneratorToggle checked={options.avoidAmbiguous} onChange={(checked) => props.onChange('avoidAmbiguous', checked)} label={t('txt_generator_avoid_ambiguous')} />
    </>
  );
}

function UsernameOptionFields(props: { options: UsernameOptions; onChange: <K extends keyof UsernameOptions>(key: K, value: UsernameOptions[K]) => void }) {
  return (
    <>
      <GeneratorNumberStepper id="username-words" label={t('txt_generator_words')} value={props.options.words} minimum={1} maximum={10} fallback={2} onChange={(value) => props.onChange('words', value)} />
      <div className="generator-option-group">
        <GeneratorToggle checked={props.options.capitalize} onChange={(checked) => props.onChange('capitalize', checked)} label={t('txt_generator_capitalize')} />
        <GeneratorToggle checked={props.options.includeNumber} onChange={(checked) => props.onChange('includeNumber', checked)} label={t('txt_generator_include_number')} />
      </div>
      <label className="generator-select-field" htmlFor="generator-username-word-list"><span>{t('txt_generator_word_list')}</span><select id="generator-username-word-list" className="input" value={props.options.wordList} onChange={(event) => props.onChange('wordList', event.currentTarget.value as 'eff' | 'custom')}><option value="eff">{t('txt_generator_eff_word_list')}</option><option value="custom">{t('txt_generator_custom_word_list')}</option></select></label>
      {props.options.wordList === 'custom' && <label className="generator-text-field" htmlFor="generator-username-custom-words"><span>{t('txt_generator_custom_words')}</span><textarea id="generator-username-custom-words" className="input generator-word-list-input" rows={6} spellcheck={false} placeholder={t('txt_generator_custom_words_placeholder')} value={props.options.customWords} onInput={(event) => props.onChange('customWords', event.currentTarget.value)} /></label>}
      <label className="generator-text-field" htmlFor="generator-username-custom-word"><span>{t('txt_generator_custom_word')}</span><input id="generator-username-custom-word" className="input" type="text" autocomplete="off" maxLength={128} value={props.options.customWord} onInput={(event) => props.onChange('customWord', event.currentTarget.value)} /></label>
      <label className="generator-text-field" htmlFor="generator-username-delimiter"><span>{t('txt_generator_separator')}</span><input id="generator-username-delimiter" className="input" type="text" autocomplete="off" maxLength={8} value={props.options.delimiter} onInput={(event) => props.onChange('delimiter', event.currentTarget.value.slice(0, 8))} /></label>
      <p className="generator-options-note">{t('txt_generator_long_word_username_description')}</p>
    </>
  );
}

function EmailOptionFields(props: { options: EmailOptions; onChange: <K extends keyof EmailOptions>(key: K, value: EmailOptions[K]) => void }) {
  const types: Array<[EmailMode, string]> = [
    ['plusAddressed', 'txt_generator_plus_addressed_email'],
    ['catchAll', 'txt_generator_catch_all_email'],
    ['subdomain', 'txt_generator_subdomain_email'],
  ];
  return (
    <>
      <label className="generator-select-field" htmlFor="generator-email-type"><span>{t('txt_generator_email_type')}</span><select id="generator-email-type" className="input" value={props.options.type} onChange={(event) => props.onChange('type', event.currentTarget.value as EmailMode)}>{types.map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}</select></label>
      {props.options.type === 'catchAll'
        ? <label className="generator-text-field" htmlFor="generator-domain"><span>{t('txt_generator_domain')}</span><input id="generator-domain" className="input" type="text" autocomplete="off" value={props.options.domain} onInput={(event) => props.onChange('domain', event.currentTarget.value)} /></label>
        : <label className="generator-text-field" htmlFor="generator-email"><span>{t('txt_generator_email')}</span><input id="generator-email" className="input" type="email" autocomplete="off" value={props.options.email} onInput={(event) => props.onChange('email', event.currentTarget.value)} /></label>}
      <p className="generator-options-note">{t('txt_generator_email_description')}</p>
    </>
  );
}

function publicKeyWithComment(publicKey: string, comment: string): string {
  const base = publicKey.trim().split(/\s+/).slice(0, 2).join(' ');
  const safeComment = comment.replace(/[\r\n]+/g, ' ').trim();
  return safeComment ? `${base} ${safeComment}` : base;
}

function downloadText(filename: string, value: string): void {
  const url = URL.createObjectURL(new Blob([value], { type: 'text/plain;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function SshKeyOutput(props: { value: GeneratedSshKey | null; loading: boolean; error: string; comment: string }) {
  if (props.loading) return <div className="generator-key-status"><LoaderCircle size={24} className="generator-spinner" /><span>{t('txt_generator_ssh_generating')}</span></div>;
  if (props.error) return <div className="generator-key-status error">{props.error}</div>;
  if (!props.value) return null;
  const publicKey = publicKeyWithComment(props.value.publicKey, props.comment);
  const copyField = (value: string) => void copyTextToClipboard(value);
  return (
    <div className="generator-key-output">
      <div className="generator-key-summary"><strong>{props.value.type}{props.value.type === 'RSA' ? ` ${props.value.bits}` : ''}</strong><code>{props.value.fingerprint}</code></div>
      <div className="generator-key-field"><span>{t('txt_generator_public_key')}</span><code>{publicKey}</code><div className="generator-key-field-actions"><button type="button" className="btn btn-secondary small" onClick={() => copyField(publicKey)}><Copy size={14} />{t('txt_copy')}</button><button type="button" className="btn btn-secondary small" onClick={() => downloadText('id_nodewarden.pub', `${publicKey}\n`)}><Download size={14} />{t('txt_download')}</button></div></div>
      <details className="generator-private-key"><summary>{t('txt_generator_private_key')}</summary><code>{props.value.privateKey}</code><div className="generator-key-field-actions"><button type="button" className="btn btn-secondary small" onClick={() => copyField(props.value!.privateKey)}><Copy size={14} />{t('txt_copy')}</button><button type="button" className="btn btn-secondary small" onClick={() => downloadText('id_nodewarden', props.value!.privateKey)}><Download size={14} />{t('txt_download')}</button></div></details>
    </div>
  );
}

function SshKeyOptionFields(props: { options: SshKeyOptions; onChange: <K extends keyof SshKeyOptions>(key: K, value: SshKeyOptions[K]) => void }) {
  return (
    <>
      <label className="generator-select-field" htmlFor="generator-ssh-type"><span>{t('txt_generator_ssh_algorithm')}</span><select id="generator-ssh-type" className="input" value={props.options.type} onChange={(event) => props.onChange('type', event.currentTarget.value as SshKeyOptions['type'])}><option value="ed25519">Ed25519</option><option value="rsa">RSA</option></select></label>
      {props.options.type === 'rsa' && <label className="generator-select-field" htmlFor="generator-rsa-length"><span>{t('txt_generator_key_length')}</span><select id="generator-rsa-length" className="input" value={props.options.rsaLength} onChange={(event) => props.onChange('rsaLength', Number(event.currentTarget.value) as SshKeyOptions['rsaLength'])}><option value={2048}>2048</option><option value={3072}>3072</option><option value={4096}>4096</option></select></label>}
      <label className="generator-text-field" htmlFor="generator-ssh-comment"><span>{t('txt_generator_ssh_comment')}</span><input id="generator-ssh-comment" className="input" type="text" autocomplete="off" maxLength={256} placeholder="user@example.com" value={props.options.comment} onInput={(event) => props.onChange('comment', event.currentTarget.value)} /></label>
      <p className="generator-options-note">{t(props.options.type === 'rsa' ? 'txt_generator_ssh_rsa_description' : 'txt_generator_ssh_ed25519_description')}</p>
    </>
  );
}

function GeneratorToggle(props: { checked: boolean; label: string; onChange: (checked: boolean) => void }) {
  return <label className="generator-toggle"><input type="checkbox" checked={props.checked} onChange={(event) => props.onChange(event.currentTarget.checked)} /><span aria-hidden="true" /><strong>{props.label}</strong></label>;
}

function GeneratorNumberStepper(props: { id: string; label: string; value: number; minimum: number; maximum: number; fallback: number; compact?: boolean; onChange: (value: number) => void }) {
  const id = `generator-stepper-${props.id}`;
  const setValue = (value: number) => props.onChange(clampInteger(value, props.minimum, props.maximum, props.fallback));
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
