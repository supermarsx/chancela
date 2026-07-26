import { useId, useRef, useState, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useT, type MessageKey } from '../../i18n';
import { type AdminCopyKey, useAdminT } from '../../i18n/adminFallback';
import { type ServerEnvCopyKey, useServerEnvT } from '../../i18n/serverEnvFallback';
import { Icon } from '../../ui';
import { usePermissions } from '../session/permissions';
import './AdminConfigurationFinder.css';

export type AdminConfigurationTitle =
  | { source: 'catalog'; key: MessageKey }
  | { source: 'admin'; key: AdminCopyKey }
  | { source: 'serverEnv'; key: ServerEnvCopyKey };

export type AdminConfigurationKeywordKey = Extract<AdminCopyKey, `admin.finder.keywords.${string}`>;

/**
 * One searchable admin destination. This deliberately contains no rendered React state, so the
 * forthcoming full-search service can reuse and extend the same permission-aware index rather
 * than maintaining a second list of admin routes.
 */
export interface AdminConfigurationAreaDefinition {
  id: string;
  path: string;
  title: AdminConfigurationTitle;
  keywords: AdminConfigurationKeywordKey;
  permissions: readonly string[];
}

const SETTINGS_PERMISSIONS = ['settings.read', 'settings.manage'] as const;

/**
 * Canonical admin configuration index. Keep additions here declarative: the finder, tests and any
 * wider search surface can consume the same definitions and automatically inherit route,
 * localisation and permission filtering.
 */
export const ADMIN_CONFIGURATION_AREAS = [
  {
    id: 'services',
    path: '/admin',
    title: { source: 'catalog', key: 'settings.platform.tab.services' },
    keywords: 'admin.finder.keywords.services',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'logs',
    path: '/admin/logs',
    title: { source: 'catalog', key: 'settings.platform.tab.logs' },
    keywords: 'admin.finder.keywords.logs',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'search',
    path: '/admin/search',
    title: { source: 'admin', key: 'admin.search.title' },
    keywords: 'admin.finder.keywords.search',
    permissions: ['search.manage'],
  },
  {
    id: 'template-preview',
    path: '/admin/template-preview',
    title: { source: 'admin', key: 'admin.templatePreview.title' },
    keywords: 'admin.finder.keywords.templatePreview',
    permissions: ['settings.read'],
  },
  {
    id: 'api',
    path: '/admin/api',
    title: { source: 'catalog', key: 'settings.subnav.api' },
    keywords: 'admin.finder.keywords.api',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'api-keys',
    path: '/admin/api-keys',
    title: { source: 'catalog', key: 'settings.apiKeys.cardTitle' },
    keywords: 'admin.finder.keywords.apiKeys',
    permissions: ['user.manage'],
  },
  {
    id: 'database',
    path: '/admin/database',
    title: { source: 'catalog', key: 'settings.database.cardTitle' },
    keywords: 'admin.finder.keywords.database',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'cache',
    path: '/admin/cache',
    title: { source: 'catalog', key: 'settings.cache.cardTitle' },
    keywords: 'admin.finder.keywords.cache',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'storage',
    path: '/admin/storage',
    title: { source: 'catalog', key: 'data.status.tab.storage' },
    keywords: 'admin.finder.keywords.storage',
    permissions: ['data.manage', ...SETTINGS_PERMISSIONS],
  },
  {
    id: 'backups',
    path: '/admin/backups',
    title: { source: 'catalog', key: 'data.status.tab.backup' },
    keywords: 'admin.finder.keywords.backups',
    permissions: ['backup.manage', ...SETTINGS_PERMISSIONS],
  },
  {
    id: 'keys',
    path: '/admin/keys',
    title: { source: 'catalog', key: 'data.status.tab.keys' },
    keywords: 'admin.finder.keywords.keys',
    permissions: ['data.manage', ...SETTINGS_PERMISSIONS],
  },
  {
    id: 'mcp',
    path: '/admin/mcp',
    title: { source: 'catalog', key: 'settings.subnav.mcp' },
    keywords: 'admin.finder.keywords.mcp',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'email',
    path: '/admin/email',
    title: { source: 'catalog', key: 'settings.email.cardTitle' },
    keywords: 'admin.finder.keywords.email',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'env',
    path: '/admin/env',
    title: { source: 'serverEnv', key: 'settings.serverEnv.title' },
    keywords: 'admin.finder.keywords.env',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'groups',
    path: '/admin/groups',
    title: { source: 'catalog', key: 'operations.tabs.groups' },
    keywords: 'admin.finder.keywords.groups',
    permissions: ['entity.create', 'entity.update', 'template.manage'],
  },
  {
    id: 'connectors',
    path: '/admin/connectors',
    title: { source: 'catalog', key: 'operations.tabs.connectors' },
    keywords: 'admin.finder.keywords.connectors',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'repositories',
    path: '/admin/repositories',
    title: { source: 'catalog', key: 'operations.tabs.repositories' },
    keywords: 'admin.finder.keywords.repositories',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'providers',
    path: '/admin/signing',
    title: { source: 'catalog', key: 'settings.providerCredentials.cardTitle' },
    keywords: 'admin.finder.keywords.providers',
    permissions: ['signing.configure'],
  },
  {
    id: 'policy',
    path: '/admin/signing/policy',
    title: { source: 'catalog', key: 'settings.signing.policy.cardTitle' },
    keywords: 'admin.finder.keywords.policy',
    permissions: ['signing.configure'],
  },
  {
    id: 'tsl',
    path: '/admin/signing/tsl',
    title: { source: 'catalog', key: 'settings.signing.tslSources.title' },
    keywords: 'admin.finder.keywords.tsl',
    permissions: ['signing.configure'],
  },
  {
    id: 'tsa',
    path: '/admin/signing/tsa',
    title: { source: 'catalog', key: 'settings.signing.tsaProviders.title' },
    keywords: 'admin.finder.keywords.tsa',
    permissions: ['signing.configure'],
  },
  {
    id: 'trust-services',
    path: '/admin/signing/trust-services',
    title: { source: 'catalog', key: 'settings.signing.providers.title' },
    keywords: 'admin.finder.keywords.trustServices',
    permissions: ['signing.configure'],
  },
  {
    id: 'cmd',
    path: '/admin/signing/cmd',
    title: { source: 'catalog', key: 'settings.signing.cmd.title' },
    keywords: 'admin.finder.keywords.cmd',
    permissions: ['signing.configure'],
  },
] as const satisfies readonly AdminConfigurationAreaDefinition[];

export interface AdminConfigurationSearchEntry extends AdminConfigurationAreaDefinition {
  titleText: string;
  searchText: string;
}

export function normalizeAdminConfigurationSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLocaleLowerCase()
    .trim();
}

/** Resolve and permission-filter definitions before any query matching, preventing hidden areas
 * from leaking through result counts, labels, keywords or timing-dependent intermediate state. */
export function buildAdminConfigurationSearchEntries(
  definitions: readonly AdminConfigurationAreaDefinition[],
  resolveTitle: (title: AdminConfigurationTitle) => string,
  resolveKeywords: (key: AdminConfigurationKeywordKey) => string,
  canAny: (permission: string) => boolean,
): AdminConfigurationSearchEntry[] {
  return definitions
    .filter((area) => area.permissions.some((permission) => canAny(permission)))
    .map((area) => {
      const titleText = resolveTitle(area.title);
      return {
        ...area,
        titleText,
        searchText: normalizeAdminConfigurationSearch(
          `${titleText} ${resolveKeywords(area.keywords)} ${area.id} ${area.path}`,
        ),
      };
    });
}

export function filterAdminConfigurationSearchEntries(
  entries: readonly AdminConfigurationSearchEntry[],
  query: string,
): AdminConfigurationSearchEntry[] {
  const tokens = normalizeAdminConfigurationSearch(query).split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return [];
  return entries.filter((entry) => tokens.every((token) => entry.searchText.includes(token)));
}

interface AdminConfigurationFinderProps {
  areas?: readonly AdminConfigurationAreaDefinition[];
}

export function AdminConfigurationFinder({
  areas = ADMIN_CONFIGURATION_AREAS,
}: AdminConfigurationFinderProps) {
  const t = useT();
  const at = useAdminT();
  const st = useServerEnvT();
  const { canAny } = usePermissions();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const resultsId = useId();
  const [query, setQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);

  const resolveTitle = (title: AdminConfigurationTitle): string => {
    if (title.source === 'admin') return at(title.key);
    if (title.source === 'serverEnv') return st(title.key);
    return t(title.key);
  };
  const entries = buildAdminConfigurationSearchEntries(areas, resolveTitle, at, canAny);
  const matches = filterAdminConfigurationSearchEntries(entries, query);
  const expanded = isOpen && query.trim().length > 0;
  const selectedIndex = matches.length > 0 ? Math.min(activeIndex, matches.length - 1) : -1;
  const activeId =
    expanded && selectedIndex >= 0 ? `${resultsId}-option-${matches[selectedIndex].id}` : undefined;

  const clear = () => {
    setQuery('');
    setIsOpen(false);
    setActiveIndex(0);
  };

  const openArea = (area: AdminConfigurationSearchEntry) => {
    clear();
    void navigate(area.path);
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
            {matches.map((area, index) => {
              const selected = index === selectedIndex;
              return (
                <button
                  className="admin-config-finder__result"
                  id={`${resultsId}-option-${area.id}`}
                  key={area.id}
                  type="button"
                  role="option"
                  tabIndex={-1}
                  aria-label={at('admin.finder.open', { title: area.titleText })}
                  aria-selected={selected}
                  onMouseDown={(event) => event.preventDefault()}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => openArea(area)}
                >
                  <span>{area.titleText}</span>
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
