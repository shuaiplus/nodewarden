import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Check, ChevronDown, ChevronUp, ExternalLink, Pencil, Plus, RefreshCw, Save, Trash2, X } from 'lucide-preact';
import LoadingState from '@/components/LoadingState';
import { t } from '@/lib/i18n';
import type { CustomEquivalentDomain, DomainRules } from '@/lib/types';
import { normalizeEquivalentDomain } from '@shared/domain-normalize';

const CUSTOM_GLOBAL_DOMAINS_PR_URL = 'https://github.com/shuaiplus/nodewarden/edit/main/src/static/global_domains.custom.json';

interface DomainRulesPageProps {
  rules: DomainRules | null;
  loading: boolean;
  error: string;
  onRefresh: () => void;
  onSave: (customEquivalentDomains: CustomEquivalentDomain[], excludedGlobalEquivalentDomains: number[]) => Promise<void>;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
}

interface DomainRuleSummaryProps {
  text: string;
  expanded: boolean;
  onToggle: () => void;
}

function normalizeDomain(value: string): string {
  return normalizeEquivalentDomain(value);
}

function normalizeDomainList(domains: string[]): string[] {
  return Array.from(new Set(domains.map(normalizeDomain).filter(Boolean)));
}

function isValidDomainName(value: string): boolean {
  return !!normalizeEquivalentDomain(value);
}

function getInvalidDomainIndexes(domains: string[]): Set<number> {
  const invalid = new Set<number>();
  domains.forEach((domain, index) => {
    if (!isValidDomainName(domain)) invalid.add(index);
  });
  return invalid;
}

function createDraftId(): string {
  return `custom-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function createEmptyDomains(): string[] {
  return ['', ''];
}

function DomainRuleSummary(props: DomainRuleSummaryProps) {
  const textRef = useRef<HTMLSpanElement>(null);
  const [canExpand, setCanExpand] = useState(false);

  useEffect(() => {
    const node = textRef.current;
    if (!node) return undefined;

    const measure = () => {
      const width = node.getBoundingClientRect().width;
      if (!width || typeof document === 'undefined') {
        setCanExpand(false);
        return;
      }

      const probe = document.createElement('span');
      const styles = window.getComputedStyle(node);
      probe.textContent = props.text;
      probe.style.position = 'absolute';
      probe.style.visibility = 'hidden';
      probe.style.whiteSpace = 'nowrap';
      probe.style.font = styles.font;
      probe.style.letterSpacing = styles.letterSpacing;
      probe.style.left = '-9999px';
      probe.style.top = '-9999px';
      document.body.appendChild(probe);
      const fullWidth = probe.getBoundingClientRect().width;
      probe.remove();
      setCanExpand(fullWidth > width + 1);
    };

    measure();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', measure);
      return () => window.removeEventListener('resize', measure);
    }

    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, [props.text]);

  return (
    <>
      <span
        ref={textRef}
        className={`domain-rule-domains${props.expanded ? ' domain-rule-domains-expanded' : ''}`}
      >
        {props.text}
      </span>
      {canExpand && (
        <button
          type="button"
          className="domain-rule-expand-btn"
          title={props.expanded ? t('txt_collapse') : t('txt_expand')}
          aria-label={props.expanded ? t('txt_collapse') : t('txt_expand')}
          onClick={props.onToggle}
        >
          {props.expanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
        </button>
      )}
    </>
  );
}

function toEditableCustomRules(rules: DomainRules | null): CustomEquivalentDomain[] {
  const source = rules?.customEquivalentDomains?.length
    ? rules.customEquivalentDomains
    : (rules?.equivalentDomains || []).map((domains, index) => ({
        id: `custom-${index}`,
        domains,
        excluded: false,
      }));
  return source.map((rule, index) => ({
    id: String(rule.id || `custom-${index}`),
    domains: rule.domains.length >= 2 ? [...rule.domains] : createEmptyDomains(),
    excluded: !!rule.excluded,
  }));
}

export default function DomainRulesPage(props: DomainRulesPageProps) {
  const [customRules, setCustomRules] = useState<CustomEquivalentDomain[]>([]);
  const [newRuleDomains, setNewRuleDomains] = useState<string[] | null>(null);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [editingDomains, setEditingDomains] = useState<string[]>(createEmptyDomains);
  const [newRuleInvalidIndexes, setNewRuleInvalidIndexes] = useState<Set<number>>(new Set());
  const [editingInvalidIndexes, setEditingInvalidIndexes] = useState<Set<number>>(new Set());
  const [excludedTypes, setExcludedTypes] = useState<Set<number>>(new Set());
  const [expandedCustomRules, setExpandedCustomRules] = useState<Set<string>>(new Set());
  const [expandedGlobalRules, setExpandedGlobalRules] = useState<Set<number>>(new Set());
  const [saving, setSaving] = useState(false);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    setCustomRules(toEditableCustomRules(props.rules));
    setNewRuleDomains(null);
    setEditingRuleId(null);
    setEditingDomains(createEmptyDomains());
    setNewRuleInvalidIndexes(new Set());
    setEditingInvalidIndexes(new Set());
    setExpandedCustomRules(new Set());
    setExpandedGlobalRules(new Set());
    setExcludedTypes(new Set((props.rules?.globalEquivalentDomains || []).filter((entry) => entry.excluded).map((entry) => entry.type)));
  }, [props.rules]);

  const sortedGlobals = useMemo(() => {
    return [...(props.rules?.globalEquivalentDomains || [])].sort((a, b) => {
      const aKey = a.domains[0] || '';
      const bKey = b.domains[0] || '';
      return aKey.localeCompare(bKey, undefined, { sensitivity: 'base' });
    });
  }, [props.rules]);

  const filteredGlobals = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return sortedGlobals;
    return sortedGlobals.filter((entry) => entry.domains.some((domain) => domain.includes(needle)));
  }, [filter, sortedGlobals]);

  function setCustomRuleEnabled(index: number, enabled: boolean): void {
    setCustomRules((rules) => rules.map((rule, ruleIndex) => ruleIndex === index ? { ...rule, excluded: !enabled } : rule));
  }

  function beginEditCustomRule(rule: CustomEquivalentDomain): void {
    setNewRuleDomains(null);
    setEditingRuleId(rule.id);
    setEditingDomains(rule.domains.length >= 2 ? [...rule.domains] : createEmptyDomains());
    setEditingInvalidIndexes(new Set());
  }

  function confirmEditCustomRule(): void {
    if (!editingRuleId) return;
    const invalidIndexes = getInvalidDomainIndexes(editingDomains);
    setEditingInvalidIndexes(invalidIndexes);
    if (invalidIndexes.size) {
      props.onNotify('warning', t('txt_domain_rule_invalid_domains'));
      return;
    }
    const domains = normalizeDomainList(editingDomains);
    if (domains.length < 2) {
      props.onNotify('warning', t('txt_domain_rule_needs_two_domains'));
      return;
    }
    setCustomRules((rules) => rules.map((rule) => rule.id === editingRuleId ? { ...rule, domains } : rule));
    setEditingRuleId(null);
    setEditingDomains(createEmptyDomains());
  }

  function cancelEditCustomRule(): void {
    setEditingRuleId(null);
    setEditingDomains(createEmptyDomains());
    setEditingInvalidIndexes(new Set());
  }

  function addNewRule(): void {
    const invalidIndexes = getInvalidDomainIndexes(newRuleDomains || []);
    setNewRuleInvalidIndexes(invalidIndexes);
    if (invalidIndexes.size) {
      props.onNotify('warning', t('txt_domain_rule_invalid_domains'));
      return;
    }
    const domains = normalizeDomainList(newRuleDomains || []);
    if (domains.length < 2) {
      props.onNotify('warning', t('txt_domain_rule_needs_two_domains'));
      return;
    }
    setCustomRules((rules) => [
      {
        id: createDraftId(),
        domains,
        excluded: false,
      },
      ...rules,
    ]);
    setNewRuleDomains(null);
    setNewRuleInvalidIndexes(new Set());
  }

  function removeCustomRule(index: number): void {
    setCustomRules((rules) => rules.filter((_, currentIndex) => currentIndex !== index));
  }

  function toggleGlobal(type: number): void {
    setExcludedTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  }

  function toggleExpandedCustomRule(id: string): void {
    setExpandedCustomRules((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleExpandedGlobalRule(type: number): void {
    setExpandedGlobalRules((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  async function save(): Promise<void> {
    const normalizedCustomRules = customRules.map((rule) => ({
      ...rule,
      domains: normalizeDomainList(rule.domains),
    }));
    if (normalizedCustomRules.some((rule) => rule.domains.some((domain) => !isValidDomainName(domain)))) {
      props.onNotify('warning', t('txt_domain_rule_invalid_domains'));
      return;
    }
    if (normalizedCustomRules.some((rule) => rule.domains.length < 2)) {
      props.onNotify('warning', t('txt_domain_rule_needs_two_domains'));
      return;
    }

    const excludedGlobalEquivalentDomains = (props.rules?.globalEquivalentDomains || [])
      .filter((entry) => excludedTypes.has(entry.type))
      .map((entry) => entry.type);

    setSaving(true);
    try {
      await props.onSave(normalizedCustomRules, excludedGlobalEquivalentDomains);
      props.onNotify('success', t('txt_domain_rules_saved'));
    } catch (error) {
      props.onNotify('error', error instanceof Error ? error.message : t('txt_domain_rules_save_failed'));
    } finally {
      setSaving(false);
    }
  }

  function renderDomainInputs(domains: string[], invalidIndexes: Set<number>, onChange: (index: number, value: string) => void, onAdd: () => void, onRemove?: (index: number) => void) {
    return (
      <div className="domain-rule-inputs">
        {domains.map((domain, index) => (
          <div key={index} className="domain-rule-input-piece">
            <input
              className={`input domain-rule-inline-input${invalidIndexes.has(index) ? ' domain-rule-input-invalid' : ''}`}
              value={domain}
              placeholder="example.com"
              aria-invalid={invalidIndexes.has(index)}
              onInput={(event) => onChange(index, (event.currentTarget as HTMLInputElement).value)}
            />
            {domains.length > 2 && onRemove && (
              <button
                type="button"
                className="domain-rule-input-remove"
                title={t('txt_remove_domain')}
                aria-label={t('txt_remove_domain')}
                onClick={() => onRemove(index)}
              >
                <X size={13} />
              </button>
            )}
            {index < domains.length - 1 && <span className="domain-rule-operator">,</span>}
          </div>
        ))}
        <button
          type="button"
          className="btn btn-secondary small domain-rule-mini-btn"
          title={t('txt_add_domain')}
          aria-label={t('txt_add_domain')}
          onClick={onAdd}
        >
          <Plus size={14} />
        </button>
      </div>
    );
  }

  if (props.loading && !props.rules) {
    return <LoadingState card lines={6} />;
  }

  return (
    <div className="domain-rules-page">
      <div className="domain-rules-toolbar">
        <div className="domain-rules-toolbar-copy">
          <div className="domain-rules-toolbar-title">{t('nav_domain_rules')}</div>
          <p>{t('txt_domain_rules_description')}</p>
        </div>
        <div className="actions">
          <button type="button" className="btn btn-primary" disabled={saving} onClick={() => void save()}>
            <Save size={14} className="btn-icon" />
            {saving ? t('txt_saving') : t('txt_save')}
          </button>
          <button type="button" className="btn btn-secondary" disabled={props.loading} onClick={props.onRefresh}>
            <RefreshCw size={14} className="btn-icon" />
            {t('txt_sync')}
          </button>
          <a className="btn btn-secondary" href={CUSTOM_GLOBAL_DOMAINS_PR_URL} target="_blank" rel="noreferrer">
            <ExternalLink size={14} className="btn-icon" />
            {t('txt_submit_pr')}
          </a>
        </div>
      </div>

      <div className="settings-modules-grid domain-rules-grid">
        <section className="card settings-module domain-rules-custom">
          <div className="section-heading-row">
            <h3>{t('txt_custom_equivalent_domains')}</h3>
            <button type="button" className="btn btn-secondary small" onClick={() => {
              setEditingRuleId(null);
              setEditingInvalidIndexes(new Set());
              setNewRuleDomains((current) => current || createEmptyDomains());
              setNewRuleInvalidIndexes(new Set());
            }}>
              <Plus size={14} className="btn-icon" />
              {t('txt_add')}
            </button>
          </div>

          {props.error && <div className="status-error">{props.error}</div>}

          {newRuleDomains && (
            <div className="domain-rule-row domain-rule-editing-row domain-rule-new-row">
              <div className="domain-rule-main">
                {renderDomainInputs(
                  newRuleDomains,
                  newRuleInvalidIndexes,
                  (index, value) => {
                    setNewRuleDomains((domains) => (domains || createEmptyDomains()).map((domain, currentIndex) => currentIndex === index ? value : domain));
                    setNewRuleInvalidIndexes((current) => {
                      const next = new Set(current);
                      next.delete(index);
                      return next;
                    });
                  },
                  () => {
                    setNewRuleDomains((domains) => [...(domains || createEmptyDomains()), '']);
                    setNewRuleInvalidIndexes(new Set());
                  },
                  (index) => setNewRuleDomains((domains) => {
                    const current = domains || createEmptyDomains();
                    setNewRuleInvalidIndexes(new Set());
                    return current.length > 2 ? current.filter((_, currentIndex) => currentIndex !== index) : current;
                  })
                )}
              </div>
              <div className="domain-rule-row-actions">
                <button type="button" className="btn btn-primary small" onClick={addNewRule}>
                  <Check size={14} className="btn-icon" />
                  {t('txt_confirm')}
                </button>
                <button type="button" className="btn btn-secondary small" onClick={() => {
                  setNewRuleDomains(null);
                  setNewRuleInvalidIndexes(new Set());
                }}>
                  <X size={14} className="btn-icon" />
                  {t('txt_cancel')}
                </button>
              </div>
            </div>
          )}

          <div className="domain-rules-table">
            {customRules.map((rule, ruleIndex) => (
              editingRuleId === rule.id ? (
                <div key={rule.id} className="domain-rule-row domain-rule-editing-row">
                  <div className="domain-rule-main">
                    {renderDomainInputs(
                      editingDomains,
                      editingInvalidIndexes,
                      (domainIndex, value) => {
                        setEditingDomains((domains) => domains.map((domain, currentIndex) => currentIndex === domainIndex ? value : domain));
                        setEditingInvalidIndexes((current) => {
                          const next = new Set(current);
                          next.delete(domainIndex);
                          return next;
                        });
                      },
                      () => {
                        setEditingDomains((domains) => [...domains, '']);
                        setEditingInvalidIndexes(new Set());
                      },
                      (domainIndex) => {
                        setEditingInvalidIndexes(new Set());
                        setEditingDomains((domains) => domains.length > 2 ? domains.filter((_, currentIndex) => currentIndex !== domainIndex) : domains);
                      }
                    )}
                  </div>
                  <div className="domain-rule-row-actions">
                    <button type="button" className="btn btn-primary small" onClick={confirmEditCustomRule}>
                      <Check size={14} className="btn-icon" />
                      {t('txt_confirm')}
                    </button>
                    <button type="button" className="btn btn-secondary small" onClick={cancelEditCustomRule}>
                      <X size={14} className="btn-icon" />
                      {t('txt_cancel')}
                    </button>
                  </div>
                </div>
              ) : (
                <div key={rule.id} className={`domain-rule-row${expandedCustomRules.has(rule.id) ? ' domain-rule-row-expanded' : ''}`}>
                  <input
                    type="checkbox"
                    checked={!rule.excluded}
                    aria-label={t('txt_enabled')}
                    onChange={(event) => setCustomRuleEnabled(ruleIndex, (event.currentTarget as HTMLInputElement).checked)}
                  />
                  <DomainRuleSummary
                    text={rule.domains.join(', ')}
                    expanded={expandedCustomRules.has(rule.id)}
                    onToggle={() => toggleExpandedCustomRule(rule.id)}
                  />
                  <div className="domain-rule-row-actions">
                    <button
                      type="button"
                      className="btn btn-secondary small domain-rule-icon-btn"
                      title={t('txt_edit')}
                      aria-label={t('txt_edit')}
                      onClick={() => beginEditCustomRule(rule)}
                    >
                      <Pencil size={14} />
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary small domain-rule-icon-btn"
                      title={t('txt_delete')}
                      aria-label={t('txt_delete')}
                      onClick={() => removeCustomRule(ruleIndex)}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              )
            ))}
            {!customRules.length && !newRuleDomains && <div className="empty empty-comfortable">{t('txt_no_custom_domain_rules')}</div>}
          </div>
        </section>

        <section className="card settings-module domain-rules-global">
          <div className="section-heading-row">
            <h3>{t('txt_global_equivalent_domains')}</h3>
            <div className="domain-rules-heading-actions">
              <input
                className="input domain-rules-filter"
                value={filter}
                placeholder={t('txt_search_domains')}
                onInput={(event) => setFilter((event.currentTarget as HTMLInputElement).value)}
              />
            </div>
          </div>

          <div className="domain-rules-table">
            {filteredGlobals.map((entry) => (
              <div key={entry.type} className={`domain-rule-row domain-rule-readonly-row${expandedGlobalRules.has(entry.type) ? ' domain-rule-row-expanded' : ''}`}>
                <input
                  type="checkbox"
                  checked={!excludedTypes.has(entry.type)}
                  onChange={() => toggleGlobal(entry.type)}
                />
                <DomainRuleSummary
                  text={entry.domains.join(', ')}
                  expanded={expandedGlobalRules.has(entry.type)}
                  onToggle={() => toggleExpandedGlobalRule(entry.type)}
                />
              </div>
            ))}
            {!filteredGlobals.length && <div className="empty empty-comfortable">{t('txt_no_domain_rules_found')}</div>}
          </div>
        </section>
      </div>
    </div>
  );
}
