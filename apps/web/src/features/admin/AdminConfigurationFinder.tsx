/**
 * "Encontrar uma configuração" — the admin surface's full-text configuration search.
 *
 * The corpus, the key→destination mapping, the value allow-list and the matcher all live in
 * {@link ./adminConfigurationIndex}, which is pure and has no React state so any wider search
 * surface can reuse the same permission-aware index. This file is the control: input, listbox,
 * keyboard model, and the rendering of WHY each result matched.
 *
 * **Data.** Two caches the admin surface already holds are read for current values: the settings
 * document (loaded once at app start and shared) and the server-env registry. Neither is fetched
 * per keystroke — the index is built once per locale/permission/data generation and the query
 * only filters it. The env query is declared inline rather than through `useServerEnv()` so it can
 * be gated on the settings permissions: a principal who reaches this control through
 * `signing.configure` alone would otherwise fire a request the server is bound to refuse. It
 * shares the pane's query key, so visiting the Ambiente pane afterwards costs nothing.
 */
import { useId, useMemo, useRef, useState, useSyncExternalStore, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { i18nStore, useActiveLocale, useT, type MessageKey } from '../../i18n';
import { useAdminT } from '../../i18n/adminFallback';
import { api } from '../../api/client';
import { keys, useSettings } from '../../api/hooks';
import { Icon } from '../../ui';
import { usePermissions } from '../session/permissions';
import {
  ADMIN_CONFIGURATION_AREAS,
  adminConfigurationCopyResolvers,
  buildAdminConfigurationSearchEntries,
  matchAdminConfigurationEntries,
  serverEnvValueEntries,
  settingsValueEntries,
  type AdminConfigurationAreaDefinition,
  type AdminConfigurationMatch,
  type AdminConfigurationMatchKind,
  type AdminConfigurationTitle,
} from './adminConfigurationIndex';
import './AdminConfigurationFinder.css';

export {
  ADMIN_CONFIGURATION_AREAS,
  buildAdminConfigurationSearchEntries,
  matchAdminConfigurationEntries,
  normalizeAdminConfigurationSearch,
  type AdminConfigurationAreaDefinition,
  type AdminConfigurationKeywordKey,
  type AdminConfigurationSearchEntry,
  type AdminConfigurationTitle,
} from './adminConfigurationIndex';

/**
 * What a hit landed on, named for the operator. A value hit and a label hit are different claims
 * about why a destination is being suggested, and a result that does not explain itself is worse
 * than no result on a configuration screen. A `title` hit needs no name: the title IS the row.
 */
const MATCH_KIND_LABELS = {
  keywords: 'settings.finder.match.keywords',
  label: 'settings.finder.match.label',
  value: 'settings.finder.match.value',
} as const satisfies Record<Exclude<AdminConfigurationMatchKind, 'title'>, MessageKey>;

/** A hint or tooltip can be a paragraph; a menu row is one line. */
const REASON_MAX_CHARS = 96;

function shorten(value: string): string {
  return value.length <= REASON_MAX_CHARS
    ? value
    : `${value.slice(0, REASON_MAX_CHARS).trimEnd()}…`;
}

interface AdminConfigurationFinderProps {
  areas?: readonly AdminConfigurationAreaDefinition[];
}

export function AdminConfigurationFinder({
  areas = ADMIN_CONFIGURATION_AREAS,
}: AdminConfigurationFinderProps) {
  const t = useT();
  const at = useAdminT();
  const locale = useActiveLocale();
  // Bumps on a locale flip AND on a late async catalog landing, so the memoised index is rebuilt
  // when the corpus it was resolved from actually changes.
  const catalogVersion = useSyncExternalStore(
    i18nStore.subscribe,
    i18nStore.getVersion,
    i18nStore.getVersion,
  );
  const { canAny } = usePermissions();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const resultsId = useId();
  const [query, setQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);

  const canReadSettings = canAny('settings.read') || canAny('settings.manage');
  const settings = useSettings(canReadSettings).data;
  const serverEnv = useQuery({
    queryKey: keys.serverEnv,
    queryFn: () => api.getServerEnv(),
    staleTime: 15_000,
    retry: false,
    enabled: canReadSettings,
  }).data;

  const entries = useMemo(() => {
    const copy = adminConfigurationCopyResolvers(locale, (key) => i18nStore.message(locale, key));
    return buildAdminConfigurationSearchEntries({
      areas,
      resolveTitle: (title: AdminConfigurationTitle) =>
        title.source === 'admin' ? at(title.key) : i18nStore.message(locale, title.key),
      resolveKeywords: at,
      canAny,
      copy,
      values: [...settingsValueEntries(settings, copy), ...serverEnvValueEntries(serverEnv)],
    });
    // `catalogVersion` is a dependency of `i18nStore.message`, which is not itself reactive.
  }, [areas, at, canAny, locale, catalogVersion, settings, serverEnv]);

  const matches = matchAdminConfigurationEntries(entries, query);
  const expanded = isOpen && query.trim().length > 0;
  const selectedIndex = matches.length > 0 ? Math.min(activeIndex, matches.length - 1) : -1;
  const activeId =
    expanded && selectedIndex >= 0
      ? `${resultsId}-option-${matches[selectedIndex].entry.id}`
      : undefined;

  const clear = () => {
    setQuery('');
    setIsOpen(false);
    setActiveIndex(0);
  };

  const openArea = (match: AdminConfigurationMatch) => {
    clear();
    void navigate(match.entry.path);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      if (query.length > 0 || isOpen) {
        event.preventDefault();
        clear();
      }
      return;
    }

    if (matches.length === 0) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setIsOpen(true);
      setActiveIndex((current) => (Math.min(current, matches.length - 1) + 1) % matches.length);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setIsOpen(true);
      setActiveIndex((current) => {
        const bounded = Math.min(current, matches.length - 1);
        return (bounded - 1 + matches.length) % matches.length;
      });
    } else if (event.key === 'Home') {
      event.preventDefault();
      setActiveIndex(0);
    } else if (event.key === 'End') {
      event.preventDefault();
      setActiveIndex(matches.length - 1);
    } else if (event.key === 'Enter' && expanded && selectedIndex >= 0) {
      event.preventDefault();
      openArea(matches[selectedIndex]);
    }
  };

  return (
    <div
      className="admin-config-finder"
      role="search"
      aria-label={at('admin.finder.label')}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setIsOpen(false);
      }}
    >
      <label className="sr-only" htmlFor={inputId}>
        {at('admin.finder.label')}
      </label>
      <div className="admin-config-finder__control">
        <span className="admin-config-finder__search-icon">
          <Icon.Search />
        </span>
        <input
          ref={inputRef}
          id={inputId}
          className="control admin-config-finder__input"
          type="search"
          role="combobox"
          autoComplete="off"
          spellCheck={false}
          value={query}
          placeholder={at('admin.finder.placeholder')}
          aria-autocomplete="list"
          aria-controls={resultsId}
          aria-expanded={expanded}
          aria-activedescendant={activeId}
          onFocus={() => {
            if (query.trim().length > 0) setIsOpen(true);
          }}
          onChange={(event) => {
            setQuery(event.target.value);
            setIsOpen(event.target.value.trim().length > 0);
            setActiveIndex(0);
          }}
          onKeyDown={handleKeyDown}
        />
        {query.length > 0 ? (
          <button
            className="admin-config-finder__clear"
            type="button"
            aria-label={at('admin.finder.clear')}
            onClick={() => {
              clear();
              inputRef.current?.focus();
            }}
          >
            <Icon.Close />
          </button>
        ) : null}
      </div>

      <span className="sr-only" aria-live="polite">
        {expanded ? at('admin.finder.results', { count: matches.length }) : ''}
      </span>

      {expanded ? (
        matches.length > 0 ? (
          <div className="admin-config-finder__results" id={resultsId} role="listbox">
            {matches.map((match, index) => {
              const selected = index === selectedIndex;
              const optionId = `${resultsId}-option-${match.entry.id}`;
              const reasonsId = `${optionId}-why`;
              return (
                <button
                  className="menu-item admin-config-finder__result"
                  id={optionId}
                  key={match.entry.id}
                  type="button"
                  role="option"
                  tabIndex={-1}
                  aria-label={at('admin.finder.open', { title: match.entry.titleText })}
                  aria-selected={selected}
                  aria-describedby={match.reasons.length > 0 ? reasonsId : undefined}
                  data-match-kinds={match.kinds.join(' ')}
                  onMouseDown={(event) => event.preventDefault()}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => openArea(match)}
                >
                  <span className="admin-config-finder__result-text">
                    <span>{match.entry.titleText}</span>
                    {match.reasons.length > 0 ? (
                      <span className="admin-config-finder__result-why" id={reasonsId}>
                        {match.reasons.map((reason) => (
                          <span
                            className="admin-config-finder__result-reason"
                            key={`${reason.kind} ${reason.text}`}
                            data-match-kind={reason.kind}
                          >
                            {/* The separator is a real character, not a CSS gap: a screen reader
                                and find-in-page both read the row's text content, and adjacent
                                spans with no character between them read fused. */}
                            {t(MATCH_KIND_LABELS[reason.kind])}
                            {' · '}
                            {shorten(reason.text)}
                          </span>
                        ))}
                      </span>
                    ) : null}
                  </span>
                  <Icon.ArrowRight />
                </button>
              );
            })}
          </div>
        ) : (
          <div className="admin-config-finder__results admin-config-finder__empty" id={resultsId}>
            <span role="status">{at('admin.finder.noResults')}</span>
          </div>
        )
      ) : null}
    </div>
  );
}
