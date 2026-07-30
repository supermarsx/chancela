/**
 * Utilizadores — the roster (plan t14 §2.8, t44 §5), hosted as the Configurações →
 * Utilizadores sub-tab. It lists the accounts that attribute every ledger mutation: username,
 * display name, active state, and at-a-glance access indicators (whether a sign-in password, an
 * audit-attestation key and a recovery phrase are provisioned).
 *
 * The roster LISTS; it does not create or edit. Both of those are their own screens —
 * `/users/new` (t71) and `/users/:id` (t89) — because each hands out or changes
 * authority and credentials. Row actions navigate there; nothing expands in place.
 *
 * Row actions are icon-only {@link IconButton}s with gilt tooltips (t50 item 6): **Editar**
 * (→ the edit screen), **Ativar/Desativar** (the in-place `PATCH` — users are never deleted,
 * so attribution history stays intact), and **Acesso e auditoria** (the edit screen's access
 * section, via its `#acesso` anchor). Activate/deactivate keeps its distinct success toast (t44
 * retrofit-b).
 *
 * ## Filters (t89), in the Arquivo idiom
 * The same `role="search"` filter bar every list page uses (`.filter` + a `*-filterbar`), with a
 * result count and a clear affordance, and the same debounced box → `?q=` mirroring the
 * Legislação reader established.
 *
 * **Filter state lives in the URL, not in component state**, which is what makes a filtered
 * roster linkable and what makes it survive a reload and a Back out of the edit screen. Writes
 * use `replace`, so typing never piles up history entries and Back leaves the tab rather than
 * un-typing a query one character at a time.
 *
 * **What is filterable is bounded by what `GET /v1/users` returns.** Every filter here is
 * answered from a field the list payload already carries, so filtering costs no request per row
 * and cannot become an N+1. Seven of them, split two ways (t103) in the Entidades idiom — a bar
 * of three, and a `<details>` disclosure for the rest, because fifteen controls on screen at once
 * is not "extensive", it is unreadable:
 *
 * **In the bar** — the questions asked daily:
 *
 *  - **texto** (`?q`) — username, display name and e-mail, accent- and case-folded. The only
 *    filter that scales past a screenful, and it searches the e-mail the table does not render.
 *  - **estado** (`?status`) — ativo / inativo, i.e. "who can still sign in".
 *  - **função** (`?role`) — see below. Also answers "who holds **no** role" (`?role=none`), which
 *    is an anomaly worth finding: t71 went to some trouble so an account never lands roleless.
 *
 * **Behind "filtros avançados"** — real questions, asked rarely:
 *
 *  - **acesso** (`?access`) — the credential facts the Acesso column renders: an audit key, a
 *    sign-in password, a recovery phrase. "Who has no password" is the one that matters.
 *  - **âmbito** (`?scope`) — global authority vs authority confined to named resources. Two
 *    buckets, not the ten `ScopeView` kinds: "who can act instance-wide" is the security question.
 *  - **e-mail** (`?email`) — an account with no e-mail address is unreachable by every
 *    notification the platform sends.
 *  - **criado** (`?created`) — accounts created in the last 7 / 30 / 90 days, for an access review.
 *
 * ## função, and why it is keyed on the id
 *
 * This filter was **refused** by t89 and is shippable now only because `UserView` gained
 * `role_assignments` (t103, authorized; see the field's doc comment in
 * `crates/chancela-api/src/users.rs` for the ledger-digest consequence). The options come from
 * `GET /v1/roles` — one cached read of a small list, not a read per row.
 *
 * Matching is on the role **id**, never the rendered name: names are translatable, an
 * operator-authored role may collide with a seeded name, and the `roleNameLabels.ts` slug
 * (`owner`, …) is a client-side i18n key that never crosses the wire and is free to be renamed
 * (t87). Labels are produced by `roleNameLabel(id, name)`; the value is always the id.
 *
 * A **retired** role id can only arrive from an address — the migration reassigns every holder to
 * a successor and drops the id from `GET /v1/roles`, so it is never offered as an option. It
 * matches nobody, correctly, and gets its own empty state saying the role was merged. It is
 * deliberately not degraded to "no filter" the way a malformed value is: showing the entire roster
 * would imply the filter had been applied.
 *
 * ## Still NOT shipped, and still an API gap rather than a fake
 *
 *  - **última sessão** — `UserView` carries no last-sign-in timestamp. "Who has not signed in for
 *    90 days" is the access-review question this screen most wants and still cannot answer.
 *    Reported, not faked: there is no per-row read that would answer it either.
 *  - **idioma** — answerable (`user.language`), deliberately omitted. t89's reasoning stands: it
 *    is a personal preference with no operational consequence and it is not a column, so a filter
 *    over it reads as noise. A filter nobody asks for is worse than no filter.
 */
import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useRoles, useUpdateUser, useUsersPage } from '../../api/hooks';
import { roleNameLabel } from '../../api/labels';
import { useT } from '../../i18n';
import {
  Badge,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  Input,
  Select,
  SkeletonRegion,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { GateButtonLink, GateIconButton } from '../session/permissions';
import {
  CollectionPageCount,
  CollectionPager,
  useCollectionNavigation,
} from '../common/CollectionPager';
import { useDeactivateUserGuard } from './DeactivateUserGuard';
import { editUserPath, editUserSectionPath, NEW_USER_PATH, USERS_LIST_PATH } from './paths';

/** The edit screen's access tab (t103). Was the '#acesso' anchor before the screen was tabbed. */
const USER_ACCESS_SECTION = 'access';
import type { UserView } from '../../api/types';

export { NEW_USER_PATH, USERS_LIST_PATH };

const STATUS_FILTERS = ['all', 'active', 'inactive'] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];

/** The credential facts the Acesso column shows — the only ones the list payload can answer. */
const ACCESS_FILTERS = ['all', 'key', 'no-key', 'no-password', 'recovery'] as const;
type AccessFilter = (typeof ACCESS_FILTERS)[number];

function isStatusFilter(value: string | null): value is StatusFilter {
  return value !== null && (STATUS_FILTERS as readonly string[]).includes(value);
}

function isAccessFilter(value: string | null): value is AccessFilter {
  return value !== null && (ACCESS_FILTERS as readonly string[]).includes(value);
}

/**
 * Breadth of authority, not which role (t103). Deliberately **two** buckets rather than a select
 * listing all ten `ScopeView` kinds: the operational question is "who can act instance-wide", and
 * a ten-option control would answer a question nobody asks while burying the one they do.
 */
const SCOPE_FILTERS = ['all', 'global', 'scoped'] as const;
type ScopeFilter = (typeof SCOPE_FILTERS)[number];

const EMAIL_FILTERS = ['all', 'with', 'without'] as const;
type EmailFilter = (typeof EMAIL_FILTERS)[number];

/** Account-age windows, in days. */
const CREATED_FILTERS = ['all', '7', '30', '90'] as const;
type CreatedFilter = (typeof CREATED_FILTERS)[number];

/** The two non-id role values: no filter, and "holds no role at all". */
const ROLE_FILTER_ALL = 'all';
const ROLE_FILTER_NONE = 'none';

function isScopeFilter(value: string | null): value is ScopeFilter {
  return value !== null && (SCOPE_FILTERS as readonly string[]).includes(value);
}

function isEmailFilter(value: string | null): value is EmailFilter {
  return value !== null && (EMAIL_FILTERS as readonly string[]).includes(value);
}

function isCreatedFilter(value: string | null): value is CreatedFilter {
  return value !== null && (CREATED_FILTERS as readonly string[]).includes(value);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * A role value read off an address. Anything that is neither `none` nor a **UUID** degrades to
 * `all` — the same "a stale link must never read as an empty roster" rule the other filters obey.
 *
 * A well-formed id that names no *live* role is deliberately NOT degraded. That is a **retired**
 * role: t87's migration reassigns every holder to a successor and drops the id from
 * `GET /v1/roles`, so it genuinely matches nobody. Silently ignoring it would show the whole
 * roster and imply the filter had been applied; it gets its own empty state instead.
 */
export function readRoleFilter(value: string | null): string {
  if (value === null) return ROLE_FILTER_ALL;
  const raw = value.trim();
  if (raw === ROLE_FILTER_NONE) return ROLE_FILTER_NONE;
  return UUID_RE.test(raw) ? raw.toLowerCase() : ROLE_FILTER_ALL;
}

interface Filters {
  q: string;
  status: StatusFilter;
  role: string;
  access: AccessFilter;
  scope: ScopeFilter;
  email: EmailFilter;
  created: CreatedFilter;
}

const NO_FILTERS: Filters = {
  q: '',
  status: 'all',
  role: ROLE_FILTER_ALL,
  access: 'all',
  scope: 'all',
  email: 'all',
  created: 'all',
};

/**
 * The params the filters own, in address order. **One** list, so the reader, the writer and the
 * change-detection signature cannot drift apart as filters are added — the failure mode t89
 * documented (a second `setParams` writer silently discarding another's edit) is the same class
 * of bug as a param that one of the three forgets about.
 */
const FILTER_PARAMS = ['q', 'status', 'role', 'access', 'scope', 'email', 'created'] as const;
type FilterParam = (typeof FILTER_PARAMS)[number];

/** Whether a filter lives behind the "filtros avançados" disclosure rather than in the bar. */
const ADVANCED_PARAMS: readonly FilterParam[] = ['access', 'scope', 'email', 'created'];

/** Seed the filters from an address. An unknown value degrades to "no filter" rather than to an
 *  empty roster, so a hand-edited or stale link never reads as "there are no users". */
function readFilters(params: URLSearchParams): Filters {
  const status = params.get('status');
  const access = params.get('access');
  const scope = params.get('scope');
  const email = params.get('email');
  const created = params.get('created');
  return {
    q: params.get('q') ?? '',
    status: isStatusFilter(status) ? status : 'all',
    role: readRoleFilter(params.get('role')),
    access: isAccessFilter(access) ? access : 'all',
    scope: isScopeFilter(scope) ? scope : 'all',
    email: isEmailFilter(email) ? email : 'all',
    created: isCreatedFilter(created) ? created : 'all',
  };
}

/** The filter half of the address: the value each param should hold (`''` ⇒ absent), plus a
 *  comparable signature so the mirror effect can tell "already correct" from "needs a write". */
function filterParams(filters: Filters): {
  values: Record<FilterParam, string>;
  signature: string;
} {
  const values: Record<FilterParam, string> = {
    q: filters.q.trim(),
    status: filters.status === 'all' ? '' : filters.status,
    role: filters.role === ROLE_FILTER_ALL ? '' : filters.role,
    access: filters.access === 'all' ? '' : filters.access,
    scope: filters.scope === 'all' ? '' : filters.scope,
    email: filters.email === 'all' ? '' : filters.email,
    created: filters.created === 'all' ? '' : filters.created,
  };
  // Joined on a plain space. The previous separator was a literal NUL byte (U+0000), which
  // worked as a delimiter but made the whole file read as binary to grep, diff and review
  // tooling. Nothing depends on the separator beyond it not occurring inside a value.
  return { values, signature: FILTER_PARAMS.map((name) => values[name]).join(' ') };
}

/** The same signature, read off an address — including the normalisation, so an unknown value
 *  in the URL is seen as the "no filter" it is treated as and gets rewritten out. */
function paramsSignature(params: URLSearchParams): string {
  return filterParams(readFilters(params)).signature;
}

/**
 * Match on the role **id** (t103). Never on the rendered name: names are translatable, an
 * operator-authored role may share a name with a seeded one, and a retired id still resolves to a
 * label. The id is what the server issues, what an assignment stores and what the ledger records.
 */
export function matchesRole(user: UserView, filter: string): boolean {
  if (filter === ROLE_FILTER_ALL) return true;
  if (filter === ROLE_FILTER_NONE) return user.role_assignments.length === 0;
  return user.role_assignments.some((a) => a.role_id.toLowerCase() === filter);
}

/** Global authority vs authority confined to named resources. An account holding *any* global
 *  assignment counts as global — that is the reach that matters for the question being asked. */
export function matchesScope(user: UserView, filter: ScopeFilter): boolean {
  if (filter === 'all') return true;
  const hasGlobal = user.role_assignments.some((a) => a.scope.kind === 'global');
  if (filter === 'global') return hasGlobal;
  // "scoped" means *confined* — it must exclude an account that also holds a global role, and it
  // must exclude a roleless account, which has no confined authority either.
  return !hasGlobal && user.role_assignments.length > 0;
}

/** An account with no e-mail cannot be reached by any notification the platform sends (t71's
 *  welcome mail, and every later one), which is the operational point of the filter. */
export function matchesEmail(user: UserView, filter: EmailFilter): boolean {
  if (filter === 'all') return true;
  const has = (user.email ?? '').trim() !== '';
  return filter === 'with' ? has : !has;
}

/**
 * Accounts created within the last N days — the "what appeared recently" question of an access
 * review. `now` is passed in rather than read here so a render filters against one instant and
 * a test can pin it; an unparseable `created_at` is **excluded** from a window rather than
 * treated as new, since guessing recency from a broken timestamp is the wrong way to be wrong.
 */
export function matchesCreated(user: UserView, filter: CreatedFilter, now: number): boolean {
  if (filter === 'all') return true;
  const created = Date.parse(user.created_at);
  if (Number.isNaN(created)) return false;
  return now - created <= Number(filter) * 24 * 60 * 60 * 1000;
}

function UserRow({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const update = useUpdateUser(user.id);

  // Activate/deactivate; distinct toast per action (the target state is `!user.active`).
  //
  // t68: deactivation now passes the guarded-action confirm step first — the roster is the dense
  // screen where a misplaced click is likeliest, and taking an account's access away is not
  // something a single click on a row should do. Reactivation is untouched (see the guard).
  // Rejects rather than reporting: the guard toasts the failure on the direct path and the
  // dialog surfaces it inline on the confirmed one, so reporting here would double it.
  async function applyActive(nextActive: boolean) {
    await update.mutateAsync({ active: nextActive });
    toast.success(nextActive ? t('toast.user.activated') : t('toast.user.deactivated'));
  }

  const deactivate = useDeactivateUserGuard(user, applyActive);

  return (
    <tr>
      <td>
        <code className="mono">{user.username}</code>
      </td>
      <td>{user.display_name}</td>
      <td>
        {user.active ? (
          <Badge tone="ok">{t('users.status.active')}</Badge>
        ) : (
          <Badge tone="neutral">{t('users.status.inactive')}</Badge>
        )}
      </td>
      <td>
        {/* A row of BADGES, not of controls: it reports what credentials the account holds and
            offers nothing to click. It is the one place the retired users-page helper was doing
            something other than laying out an action cell, so it takes `.row-wrap` — the app's
            generic inline row — rather than the action-cell affordance, whose `flex-end` would
            right-align a left-headed data column. Measured: badge gap 6.4px → 12px, the shared
            inline-row step; row height 42.72px → 42.22px. */}
        <span className="row-wrap">
          {user.has_secret ? (
            <Badge tone="ok">{t('users.secret.label')}</Badge>
          ) : (
            <Badge tone="neutral">{t('users.secret.none')}</Badge>
          )}
          {user.has_attestation_key ? <Badge tone="accent">{t('users.key.label')}</Badge> : null}
          {user.has_recovery_phrase ? (
            <Badge tone="accent">{t('users.recovery.label')}</Badge>
          ) : null}
        </span>
      </td>
      <td className="table-action-cell">
        <span className="table-actions">
          <GateIconButton
            perm="user.manage"
            icon={<Icon.Pencil />}
            label={t('users.action.edit')}
            onClick={() => navigate(editUserPath(user.id))}
          />
          <GateIconButton
            perm="user.manage"
            icon={<Icon.Power />}
            label={user.active ? t('users.action.deactivate') : t('users.action.reactivate')}
            disabled={update.isPending}
            data-testid="user-toggle-active"
            onClick={deactivate.requestToggle}
          />
          <GateIconButton
            perm="user.manage"
            icon={<Icon.Wrench />}
            label={t('users.access.title')}
            onClick={() => navigate(editUserSectionPath(user.id, USER_ACCESS_SECTION))}
          />
        </span>
        {/* Outside the action row: the confirm dialog is not one of the row's controls, and as a
            flex item it would take part in the row's gap and wrap calculation. */}
        {deactivate.dialog}
      </td>
    </tr>
  );
}

/**
 * The roster body — a self-contained Card with its own "novo utilizador" action, the filter bar
 * and the table/empty/error states. Rendered inline as the Configurações → Utilizadores sub-tab,
 * where the SubNav supplies the page header, so it carries no PageHeader of its own.
 */
export function UsersList() {
  const t = useT();
  // The role filter's options. A second cached read of a small, rarely-changing list — it costs
  // no per-row request, which is the property that made the função filter shippable at all.
  const roles = useRoles();
  const [params, setParams] = useSearchParams();

  /**
   * The URL **seeds** the filters on mount, and one effect mirrors them back. Deliberately not a
   * two-way binding, and deliberately not one `setParams` per control:
   *
   * React Router coalesces `setParams` calls made in the same tick, and each one receives the
   * SAME `prev`. So two writers patching different keys — a debounced `q` here, a select there —
   * do not compose: the last to land silently discards the other's edit. Clearing the filters was
   * exactly that bug, and it cleared the search box while restoring the two selects.
   *
   * One writer, writing the whole triple from one state object, cannot lose an edit: whichever
   * render lands last still produces the complete, correct address.
   */
  const [filters, setFilters] = useState<Filters>(() => readFilters(params));
  const { status, role, access, scope, email, created } = filters;

  // The box holds what is being typed; `filters.q` is the debounced value mirrored to the URL and
  // sent to the bounded server query. Keeping the raw term separate prevents both a request and an
  // address rewrite per keystroke.
  const [term, setTerm] = useState(filters.q);
  useEffect(() => {
    const timer = window.setTimeout(
      () => setFilters((current) => (current.q === term ? current : { ...current, q: term })),
      200,
    );
    return () => window.clearTimeout(timer);
  }, [term]);

  /**
   * Filters → URL, one direction only, mirroring the Legislação reader. `replace` keeps typing
   * out of the history stack, so no history entry differs from its neighbour by a filter alone
   * and there is nothing for a Back to restore — Back leaves the roster, as it should. The
   * condition is "the URL disagrees", so the effect is self-healing rather than fire-once: a
   * write from elsewhere that lands with stale params is simply corrected on the next pass.
   */
  const urlFilters = paramsSignature(params);
  useEffect(() => {
    const desired = filterParams(filters);
    if (urlFilters === desired.signature) return;
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        for (const [name, value] of Object.entries(desired.values)) {
          if (value) p.set(name, value);
          else p.delete(name);
        }
        return p;
      },
      { replace: true },
    );
  }, [filters, urlFilters, setParams]);

  function clearFilters() {
    setTerm('');
    setFilters(NO_FILTERS);
  }

  const statusOptions = useMemo(
    () => [
      { value: 'all', label: t('users.filters.status.all') },
      { value: 'active', label: t('users.status.active') },
      { value: 'inactive', label: t('users.status.inactive') },
    ],
    [t],
  );
  const accessOptions = useMemo(
    () => [
      { value: 'all', label: t('users.filters.access.all') },
      { value: 'key', label: t('users.filters.access.key') },
      { value: 'no-key', label: t('users.filters.access.noKey') },
      { value: 'no-password', label: t('users.filters.access.noPassword') },
      { value: 'recovery', label: t('users.filters.access.recovery') },
    ],
    [t],
  );

  /**
   * The role options: "qualquer", "sem função", then every **live** role. Sourced from
   * `GET /v1/roles` so an operator-authored role is offered alongside the seeded ones, and
   * labelled through `roleNameLabel(id, name)` so a seeded role shows its translated name while
   * an authored one shows what its author typed. The **value is always the id**.
   *
   * A retired role is absent from this list by construction (the migration drops it), so it can
   * only ever arrive from a URL — which is exactly the case `roleFilterRetired` handles below.
   */
  const roleOptions = useMemo(() => {
    const live = (roles.data ?? []).map((r) => ({
      value: r.id,
      label: roleNameLabel(r.id, r.name),
    }));
    live.sort((a, b) => a.label.localeCompare(b.label));
    return [
      { value: ROLE_FILTER_ALL, label: t('users.filters.role.all') },
      { value: ROLE_FILTER_NONE, label: t('users.filters.role.none') },
      ...live,
    ];
  }, [roles.data, t]);
  const scopeOptions = useMemo(
    () => [
      { value: 'all', label: t('users.filters.scope.all') },
      { value: 'global', label: t('users.filters.scope.global') },
      { value: 'scoped', label: t('users.filters.scope.scoped') },
    ],
    [t],
  );
  const emailOptions = useMemo(
    () => [
      { value: 'all', label: t('users.filters.email.all') },
      { value: 'with', label: t('users.filters.email.with') },
      { value: 'without', label: t('users.filters.email.without') },
    ],
    [t],
  );
  const createdOptions = useMemo(
    () => [
      { value: 'all', label: t('users.filters.created.all') },
      { value: '7', label: t('users.filters.created.d7') },
      { value: '30', label: t('users.filters.created.d30') },
      { value: '90', label: t('users.filters.created.d90') },
    ],
    [t],
  );

  const pageFilters = {
    q: filters.q.trim() || undefined,
    active: status === 'all' ? undefined : status === 'active',
    role_id: role === ROLE_FILTER_ALL || role === ROLE_FILTER_NONE ? undefined : role,
    roleless: role === ROLE_FILTER_NONE ? true : undefined,
    access: access === 'all' ? undefined : access,
    scope: scope === 'all' ? undefined : scope,
    email: email === 'all' ? undefined : email,
    created_days: created === 'all' ? undefined : (Number(created) as 7 | 30 | 90),
    limit: 50,
    sort: 'username',
    order: 'asc' as const,
  };
  const navigation = useCollectionNavigation(JSON.stringify(pageFilters));
  const users = useUsersPage({ ...pageFilters, ...navigation.position });
  // React Query intentionally retains the prior response during a key transition so this card's
  // controls do not unmount. Hide those stale rows until the current filter/page resolves.
  const loaded = users.isPlaceholderData ? undefined : users.data?.items;
  const all = useMemo(() => loaded ?? [], [loaded]);
  const folded = filters.q.trim();
  const visible = all;

  const advancedValues = filterParams(filters).values;
  const hasAdvanced = ADVANCED_PARAMS.some((name) => advancedValues[name] !== '');
  const hasFilters = folded !== '' || status !== 'all' || role !== ROLE_FILTER_ALL || hasAdvanced;

  /**
   * The filter names a role that is not in `GET /v1/roles`. Only reachable from an address, and
   * it means a **merged** role (t87), not a typo — a non-UUID never gets this far, `readRoleFilter`
   * degrades it to "no filter". The roster is legitimately empty, so it must say why: an unlabelled
   * empty roster would read as "this instance has no users".
   *
   * Guarded on the roles query having resolved, so the in-flight moment before `GET /v1/roles`
   * answers does not momentarily accuse every live role of having been merged.
   */
  const roleFilterRetired =
    role !== ROLE_FILTER_ALL &&
    role !== ROLE_FILTER_NONE &&
    roles.data !== undefined &&
    !roles.data.some((r) => r.id.toLowerCase() === role);

  return (
    <Card
      title={t('users.list.cardTitle')}
      actions={
        <>
          <CollectionPageCount count={all.length} />
          <GateButtonLink
            perm="user.manage"
            to={NEW_USER_PATH}
            variant="primary"
            icon={<Icon.Plus />}
          >
            {t('users.list.newButton')}
          </GateButtonLink>
        </>
      }
    >
      {users.isLoading ? (
        <SkeletonRegion>
          <SkeletonTable cols={5} />
        </SkeletonRegion>
      ) : users.error ? (
        <ErrorNote error={users.error} />
      ) : !users.isPlaceholderData && all.length === 0 && !hasFilters ? (
        <EmptyState title={t('users.list.emptyTitle')}>
          <p>{t('users.list.emptyBody')}</p>
        </EmptyState>
      ) : (
        <div className="stack">
          <div
            className="stack--tight users-filters"
            role="search"
            aria-label={t('users.filters.aria')}
          >
            <div className="users-filterbar filter">
              <div className="users-filterbar__primary">
                <Field label={t('users.filters.search.label')} htmlFor="users-search">
                  <Input
                    id="users-search"
                    type="search"
                    value={term}
                    placeholder={t('users.filters.search.placeholder')}
                    onChange={(e) => setTerm(e.target.value)}
                  />
                </Field>
                <Field label={t('users.filters.status.label')} htmlFor="users-status-filter">
                  <Select
                    id="users-status-filter"
                    value={status}
                    onChange={(e) =>
                      setFilters((current) => ({
                        ...current,
                        status: e.target.value as StatusFilter,
                      }))
                    }
                    options={statusOptions}
                  />
                </Field>
                <Field label={t('users.filters.role.label')} htmlFor="users-role-filter">
                  <Select
                    id="users-role-filter"
                    value={role}
                    onChange={(e) =>
                      setFilters((current) => ({ ...current, role: e.target.value }))
                    }
                    options={roleOptions}
                  />
                </Field>
                <IconButton
                  className="users-filterbar__clear"
                  icon={<Icon.FilterClear />}
                  label={t('users.filters.clear.aria')}
                  disabled={!hasFilters}
                  onClick={clearFilters}
                />
              </div>
            </div>
            {/*
              The less-common predicates, behind the same `<details>` disclosure Entidades uses,
              so the bar stays at three controls rather than seven.

              `open` is forced when any advanced filter is set — including on first paint from a
              link. A collapsed disclosure hiding an *active* filter is the failure mode of this
              pattern: the roster would silently show a subset with no visible reason, which is
              the same defect class as an empty roster that does not say why it is empty.
            */}
            <details className="users-advanced-filters" open={hasAdvanced}>
              <summary>{t('users.filters.advanced')}</summary>
              <div className="users-advanced-filters__body filter">
                <Field label={t('users.filters.access.label')} htmlFor="users-access-filter">
                  <Select
                    id="users-access-filter"
                    value={access}
                    onChange={(e) =>
                      setFilters((current) => ({
                        ...current,
                        access: e.target.value as AccessFilter,
                      }))
                    }
                    options={accessOptions}
                  />
                </Field>
                <Field label={t('users.filters.scope.label')} htmlFor="users-scope-filter">
                  <Select
                    id="users-scope-filter"
                    value={scope}
                    onChange={(e) =>
                      setFilters((current) => ({
                        ...current,
                        scope: e.target.value as ScopeFilter,
                      }))
                    }
                    options={scopeOptions}
                  />
                </Field>
                <Field label={t('users.filters.email.label')} htmlFor="users-email-filter">
                  <Select
                    id="users-email-filter"
                    value={email}
                    onChange={(e) =>
                      setFilters((current) => ({
                        ...current,
                        email: e.target.value as EmailFilter,
                      }))
                    }
                    options={emailOptions}
                  />
                </Field>
                <Field label={t('users.filters.created.label')} htmlFor="users-created-filter">
                  <Select
                    id="users-created-filter"
                    value={created}
                    onChange={(e) =>
                      setFilters((current) => ({
                        ...current,
                        created: e.target.value as CreatedFilter,
                      }))
                    }
                    options={createdOptions}
                  />
                </Field>
              </div>
            </details>
          </div>

          {users.isPlaceholderData ? (
            <SkeletonRegion>
              <SkeletonTable cols={5} />
            </SkeletonRegion>
          ) : visible.length === 0 ? (
            roleFilterRetired ? (
              <EmptyState title={t('users.filters.retiredRole.title')}>
                <p>{t('users.filters.retiredRole.body')}</p>
              </EmptyState>
            ) : (
              <EmptyState title={t('users.filters.empty.title')}>
                <p>{t('users.filters.empty.body')}</p>
              </EmptyState>
            )
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('users.table.username')}</th>
                  <th>{t('users.table.name')}</th>
                  <th>{t('users.table.state')}</th>
                  <th>{t('users.table.access')}</th>
                  <th>{t('users.table.action')}</th>
                </tr>
              }
            >
              {visible.map((u) => (
                <UserRow key={u.id} user={u} />
              ))}
            </Table>
          )}
          {!users.isPlaceholderData ? (
            <CollectionPager
              offset={navigation.displayOffset}
              count={visible.length}
              hasPrevious={navigation.hasPrevious}
              hasNext={users.data?.has_more ?? false}
              disabled={users.isFetching}
              onPrevious={navigation.previous}
              onNext={() =>
                navigation.next(
                  users.data?.next_offset ?? null,
                  users.data?.next_cursor,
                  navigation.displayOffset + visible.length,
                )
              }
            />
          ) : null}
        </div>
      )}
    </Card>
  );
}
