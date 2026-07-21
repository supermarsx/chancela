import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn(
    (result: { filename: string }) =>
      `Transferência iniciada pelo navegador: ${result.filename}. A pasta é definida pelo browser.`,
  ),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { LegacyUserEditRedirect, LegacyUsersRedirect } from '../../app/router';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';
import { UsersList } from './UserListPage';
import { NewUserPage } from './NewUserPage';
import { EditUserPage } from './EditUserPage';
import { isValidUsername, usernameError } from './username';
import { formatDateTime, formatTimestamp } from '../../format';
import type { DsrRequestView, DsrRequestType, TwoFactorStatus, UserView } from '../../api/types';

/**
 * Render the edit screen at its real path so `useParams` and the section hook both resolve.
 *
 * The route carries the optional section segment (t103) exactly as the app registers it, so a
 * test exercises the real address rather than a simplified one — `useSectionNav` reads the
 * pathname, so a route without the segment would silently pin every test to the Geral tab.
 * Omit `section` to land on Geral, which is the default and carries no segment.
 */
function renderEditAt(id: string, section?: 'dsr' | 'roles' | 'access') {
  return renderWithProviders(
    <Routes>
      <Route path="/users/:id/:sec?" element={<EditUserPage />} />
    </Routes>,
    [`/users/${id}${section ? `/${section}` : ''}`],
  );
}

function LocationProbe() {
  const location = useLocation();
  return (
    <output aria-label="location">
      {`${location.pathname}${location.search}${location.hash}`}
    </output>
  );
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

const AMELIA: UserView = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-07-07T12:00:00Z',
  active: true,
  has_secret: false,
  has_attestation_key: false,
  has_recovery_phrase: false,
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
};

interface Recorded {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

function recordingFetch(responder: (r: Recorded) => Response): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    const rec = { url, method, body };
    calls.push(rec);
    return Promise.resolve(responder(rec));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
});

describe('username validation', () => {
  it('accepts a lowercase slug and rejects uppercase/spaces/overlong', () => {
    expect(isValidUsername('amelia.marques')).toBe(true);
    expect(isValidUsername('m.ari-ana_1')).toBe(true);
    expect(isValidUsername('Amelia')).toBe(false);
    expect(isValidUsername('with space')).toBe(false);
    expect(isValidUsername('a'.repeat(65))).toBe(false);
    // An empty field is "incomplete", not an error message.
    expect(usernameError('')).toBeNull();
    expect(usernameError('Amelia')).toMatch(/minúsculas/);
  });
});

describe('UsersList (Configurações → Utilizadores)', () => {
  it('lists users with their state', async () => {
    const { fn } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersList />, ['/settings/users']);

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.getByText('Amélia Marques')).toBeTruthy();
    // Scoped to the table: `Ativo` is also a filter option now, and an assertion that cannot
    // tell the badge from the option would pass on a roster that renders no rows at all.
    expect(within(screen.getByRole('table')).getByText('Ativo')).toBeTruthy();
  });

  it('exposes icon-only row actions via their accessible names', async () => {
    const { fn } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersList />, ['/settings/users']);

    // Each row action is an icon-only button whose accessible name comes from its tooltip
    // label (t50 W1 IconButton) — no visible text label, no native title.
    expect(await screen.findByRole('button', { name: 'Editar' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Desativar' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Acesso e auditoria' })).toBeTruthy();
  });

  it('sends the row actions to the dedicated screens, never to an inline panel', async () => {
    const { fn } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <>
        <Routes>
          <Route path="/settings/:sec?" element={<UsersList />} />
          <Route path="/users/:id" element={null} />
        </Routes>
        <LocationProbe />
      </>,
      ['/settings/users'],
    );

    // t71: the roster's create action leaves Configurações for the dedicated create screen.
    const novo = await screen.findByRole('link', { name: /novo utilizador/i });
    expect(novo.getAttribute('href')).toBe('/users/new');

    // t89: editing leaves Configurações too. The row action navigates to the edit SCREEN — the
    // `?user=` state it used to set is gone, so there is no second way to reach these controls.
    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    fireEvent.click(await screen.findByRole('button', { name: 'Editar' }));
    expect(screen.getByLabelText('location').textContent).toBe('/users/u1');
  });

  it('sends the access action to the edit screen anchored at its access section', async () => {
    const { fn } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <>
        <Routes>
          <Route path="/settings/:sec?" element={<UsersList />} />
          <Route path="/users/:id/:sec?" element={null} />
        </Routes>
        <LocationProbe />
      </>,
      ['/settings/users'],
    );

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Acesso e auditoria' }));
    // t103: the access section is a TAB now, so the row action addresses it as a path segment
    // rather than the '#acesso' fragment. The fragment still resolves — the screen promotes it
    // to this same tab — but the roster no longer depends on that translation.
    expect(screen.getByLabelText('location').textContent).toBe('/users/u1/access');
  });

  it('toggles a user active/inactive via PATCH', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'PATCH' ? jsonResponse({ ...AMELIA, active: false }) : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersList />, ['/settings/users']);

    fireEvent.click(await screen.findByRole('button', { name: 'Desativar' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.url).toContain('/v1/users/u1');
    expect(patch?.body).toMatchObject({ active: false });
    // Deactivating fires the distinct deactivated toast (t44 retrofit-b).
    expect(await screen.findByText('Utilizador desativado.')).toBeTruthy();
  });
});

// --- Roster filters (t89) -------------------------------------------------------------
//
// Three accounts that differ in exactly the facets the filters key on, so a filter that matched
// on the wrong field would show the wrong name rather than merely the wrong count.
const BRUNO_INACTIVE: UserView = {
  id: 'u2',
  username: 'bruno.dias',
  display_name: 'Bruno Dias',
  email: 'bruno@example.pt',
  created_at: '2026-07-07T12:05:00Z',
  active: false,
  has_secret: true,
  has_attestation_key: true,
  has_recovery_phrase: false,
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
};

const CLARA_RECOVERY: UserView = {
  id: 'u3',
  username: 'clara.nunes',
  display_name: 'Clara Nunes',
  created_at: '2026-07-07T12:06:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: true,
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
};

// --- Role fixtures for the função filter (t103) ---------------------------------------
//
// The real seeded Owner id. It matters that this is the ACTUAL id and not a placeholder: the
// filter renders it through `roleNameLabel`, which resolves a seeded id to its translated name,
// so a made-up id would render as a bare UUID and the label assertions would be vacuous.
const ROLE_OWNER = '6f776e65-7200-0000-0000-000000000001';
/** An operator-authored role — rendered verbatim, never translated. */
const ROLE_CUSTOM = '11111111-2222-4333-8444-555555555555';
/** Well-formed, and deliberately absent from `GET /v1/roles` — i.e. a role merged away (t87). */
const ROLE_RETIRED = '99999999-8888-4777-8666-555555555555';

const ROLES = [
  { id: ROLE_OWNER, name: 'Owner', permissions: [], protected: true },
  { id: ROLE_CUSTOM, name: 'Gerente da filial', permissions: [], protected: false },
];

/** Amélia holds the seeded Owner role globally; Bruno an authored role scoped to one entity. */
const AMELIA_OWNER: UserView = {
  ...AMELIA,
  role_assignments: [{ role_id: ROLE_OWNER, scope: { kind: 'global' } }],
};
const BRUNO_SCOPED: UserView = {
  ...BRUNO_INACTIVE,
  role_assignments: [{ role_id: ROLE_CUSTOM, scope: { kind: 'entity', id: 'e1' } }],
};
// Clara deliberately holds NO role — the `?role=none` anomaly case.

function renderRoster(entries: string[]) {
  // Branch on the URL: the roster reads `GET /v1/users` AND `GET /v1/roles` (the função filter's
  // options). A single-response stub would hand the user array back as the role list, which is
  // not merely untidy — every live role id would then be a user id, so the "this role was merged"
  // empty state would fire on a perfectly good filter.
  const { fn } = recordingFetch((call) =>
    call.url.includes('/v1/roles')
      ? jsonResponse(ROLES)
      : jsonResponse([AMELIA_OWNER, BRUNO_SCOPED, CLARA_RECOVERY]),
  );
  vi.stubGlobal('fetch', fn);
  return renderWithProviders(
    <Routes>
      <Route
        path="/settings/:sec?"
        element={
          <>
            <UsersList />
            <LocationProbe />
          </>
        }
      />
    </Routes>,
    entries,
  );
}

describe('UsersList filters (t89) — Arquivo idiom, state carried in the URL', () => {
  it('filters by the search term across username, name and e-mail, and mirrors it to ?q', async () => {
    renderRoster(['/settings/users']);
    expect(await screen.findByText('amelia.marques')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Pesquisar'), { target: { value: 'bruno@example' } });

    // The box → URL write is debounced: the address does not change on the keystroke itself.
    expect(screen.getByLabelText('location').textContent).toBe('/settings/users');

    // …and once it settles, the term is in the URL — with the section segment preserved — so
    // the filtered roster is a link someone else can open.
    await waitFor(() =>
      expect(screen.getByLabelText('location').textContent).toBe(
        '/settings/users?q=bruno%40example',
      ),
    );
    // Matched on the e-mail, which the table does not even render — and the others are gone.
    expect(screen.getByText('bruno.dias')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();
    expect(screen.queryByText('clara.nunes')).toBeNull();
  });

  it('folds accents and case, so "amelia" finds "Amélia Marques"', async () => {
    renderRoster(['/settings/users']);
    expect(await screen.findByText('clara.nunes')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Pesquisar'), { target: { value: 'AMÉLIA marques' } });
    await waitFor(() => expect(screen.queryByText('clara.nunes')).toBeNull());
    expect(screen.getByText('amelia.marques')).toBeTruthy();
  });

  it('applies a filtered URL on first paint, so the view survives a reload and a Back', async () => {
    renderRoster(['/settings/users?status=inactive']);

    expect(await screen.findByText('bruno.dias')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();
    // The select reads its value from the URL rather than from a fresh component state.
    expect((screen.getByLabelText('Estado') as HTMLSelectElement).value).toBe('inactive');
  });

  it('filters on the credential facts the list payload can actually answer', async () => {
    renderRoster(['/settings/users?access=key']);
    expect(await screen.findByText('bruno.dias')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();

    fireEvent.change(screen.getByLabelText('Acesso'), { target: { value: 'no-password' } });
    // Only Amélia has no sign-in secret.
    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.queryByText('bruno.dias')).toBeNull();
    expect(screen.getByLabelText('location').textContent).toBe(
      '/settings/users?access=no-password',
    );

    fireEvent.change(screen.getByLabelText('Acesso'), { target: { value: 'recovery' } });
    expect(await screen.findByText('clara.nunes')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();
  });

  it('clears every filter param at once and keeps the section', async () => {
    renderRoster(['/settings/users?q=bruno&status=inactive&access=key']);
    expect(await screen.findByText('bruno.dias')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Limpar filtros de utilizadores' }));

    await waitFor(() => expect(screen.queryByText('amelia.marques')).not.toBeNull());
    expect(screen.getByLabelText('location').textContent).toBe('/settings/users');
    expect((screen.getByLabelText('Pesquisar') as HTMLInputElement).value).toBe('');
  });

  it('says so when the filters exclude everyone, rather than showing an empty roster', async () => {
    renderRoster(['/settings/users?q=nao-existe']);

    expect(await screen.findByText('Sem resultados')).toBeTruthy();
    // The roster is not empty — the FILTERS are. The two states must not read alike.
    expect(screen.queryByText('Sem utilizadores')).toBeNull();
  });

  it('ignores an unknown filter value instead of showing nobody', async () => {
    // A hand-edited or stale link must degrade to the unfiltered roster, not to a blank page.
    renderRoster(['/settings/users?status=banido&access=quantum']);

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.getByText('bruno.dias')).toBeTruthy();
    expect(screen.getByText('clara.nunes')).toBeTruthy();
  });
});

// --- The função filter and the advanced tier (t103) -----------------------------------
describe('UsersList filters (t103) — função, and the advanced disclosure', () => {
  it('filters by role id, and labels a seeded role with its translated name', async () => {
    renderRoster(['/settings/users']);
    expect(await screen.findByText('amelia.marques')).toBeTruthy();

    const role = screen.getByLabelText('Função') as HTMLSelectElement;
    // A seeded role is rendered through `roleNameLabel`, so what the operator reads is the
    // translated name — NOT the English name the server stores, and not the raw UUID.
    await waitFor(() => expect(within(role).getByText('Proprietário')).toBeTruthy());
    // An operator-authored role is rendered verbatim in every locale.
    expect(within(role).getByText('Gerente da filial')).toBeTruthy();

    fireEvent.change(role, { target: { value: ROLE_OWNER } });

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.queryByText('bruno.dias')).toBeNull();
    expect(screen.queryByText('clara.nunes')).toBeNull();
    // The address carries the stable id, which is what makes the link survive a role rename.
    expect(screen.getByLabelText('location').textContent).toBe(
      `/settings/users?role=${ROLE_OWNER}`,
    );
  });

  it('matches the role id, not the displayed name', async () => {
    // The guard against the tempting shortcut: Bruno's role is NAMED "Gerente da filial" and
    // Amélia's is named "Owner"/"Proprietário". Filtering by Amélia's id must not match Bruno
    // however the two names are compared, and a name-keyed implementation would break the moment
    // an operator authored a role sharing a seeded name.
    renderRoster([`/settings/users?role=${ROLE_CUSTOM}`]);

    expect(await screen.findByText('bruno.dias')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();
  });

  it('finds the accounts holding no role at all', async () => {
    renderRoster(['/settings/users?role=none']);

    // t71 went to some trouble so an account never lands roleless, so this is an anomaly report.
    expect(await screen.findByText('clara.nunes')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();
    expect(screen.queryByText('bruno.dias')).toBeNull();
  });

  it('says a role was merged rather than showing a bare empty roster', async () => {
    // A well-formed id that names no live role is a RETIRED role (t87), not a typo. It correctly
    // matches nobody, and the screen has to say why — "Sem resultados" would be true but useless,
    // and showing everyone would falsely imply the filter had been applied.
    renderRoster([`/settings/users?role=${ROLE_RETIRED}`]);

    expect(await screen.findByText('Esta função foi fundida')).toBeTruthy();
    expect(screen.queryByText('Sem resultados')).toBeNull();
    expect(screen.queryByText('amelia.marques')).toBeNull();
  });

  it('degrades a malformed role value to no filter, unlike a retired id', async () => {
    // The distinction the previous test depends on: `readRoleFilter` only lets a UUID through, so
    // garbage shows the whole roster while a well-formed unknown id gets the merged-role state.
    renderRoster(['/settings/users?role=owner']);

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.getByText('bruno.dias')).toBeTruthy();
    expect(screen.getByText('clara.nunes')).toBeTruthy();
    expect(screen.queryByText('Esta função foi fundida')).toBeNull();
  });

  it('separates global authority from authority confined to resources', async () => {
    renderRoster(['/settings/users?scope=global']);
    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.queryByText('bruno.dias')).toBeNull();
    // A roleless account has no global authority — and no confined authority either, so it must
    // not fall into "scoped" as a leftover bucket.
    expect(screen.queryByText('clara.nunes')).toBeNull();

    fireEvent.change(screen.getByLabelText('Âmbito'), { target: { value: 'scoped' } });
    expect(await screen.findByText('bruno.dias')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();
    expect(screen.queryByText('clara.nunes')).toBeNull();
  });

  it('filters on whether the account can be reached by e-mail', async () => {
    renderRoster(['/settings/users?email=with']);
    // Only Bruno carries an address; an account without one receives no notification at all.
    expect(await screen.findByText('bruno.dias')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();

    fireEvent.change(screen.getByLabelText('E-mail'), { target: { value: 'without' } });
    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.queryByText('bruno.dias')).toBeNull();
  });

  it('opens the advanced disclosure when a link arrives with an advanced filter set', async () => {
    // The failure mode this pattern invites: a collapsed `<details>` hiding an ACTIVE filter, so
    // the roster silently shows a subset with no visible reason.
    renderRoster(['/settings/users?access=key']);

    expect(await screen.findByText('bruno.dias')).toBeTruthy();
    const disclosure = screen.getByText('Filtros avançados').closest('details');
    expect(disclosure?.open).toBe(true);
  });

  it('leaves the advanced disclosure closed when only the bar is filtered', async () => {
    renderRoster(['/settings/users?status=active']);

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.getByText('Filtros avançados').closest('details')?.open).toBe(false);
  });

  it('clears all seven filter params at once, including the advanced tier', async () => {
    renderRoster([
      `/settings/users?q=bruno&status=inactive&role=${ROLE_CUSTOM}` +
        '&access=key&scope=scoped&email=with&created=90',
    ]);
    expect(await screen.findByText('bruno.dias')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Limpar filtros de utilizadores' }));

    // One writer produces the whole address, so no filter can survive a clear (t89's coalescing
    // bug would have restored whichever controls lost the race).
    await waitFor(() =>
      expect(screen.getByLabelText('location').textContent).toBe('/settings/users'),
    );
    expect(screen.getByText('amelia.marques')).toBeTruthy();
    expect(screen.getByText('clara.nunes')).toBeTruthy();
  });
});

describe('NewUserPage (/users/new)', () => {
  it('renders a client-side validation error for an invalid username and disables submit', async () => {
    const { fn } = recordingFetch(() => jsonResponse([]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<NewUserPage />, ['/users/new']);

    const input = await screen.findByLabelText('Nome de utilizador');
    fireEvent.change(input, { target: { value: 'Amelia' } });

    expect(await screen.findByText(/minúsculas/)).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: /criar utilizador/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  // t88: the audit key is generated from the password typed on this screen, which means the
  // operator filling it in can unlock it and attest as the new user until it is changed. That is a
  // property of a password-wrapped key, not a bug — but it has to be on the screen, so this pins
  // that the disclosure is present and names the mitigation.
  it('discloses on the credentials card that the audit key is bound to this password', async () => {
    const { fn } = recordingFetch(() => jsonResponse([]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<NewUserPage />, ['/users/new']);

    const note = await screen.findByText(/chave de auditoria/i);
    expect(note.textContent).toMatch(/em nome deste utilizador/i);
    expect(note.textContent).toMatch(/altere no primeiro acesso/i);
  });

  it('creates a user with a valid slug and sends identity email fields', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'POST' ? jsonResponse(AMELIA, 201) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<NewUserPage />, ['/users/new']);

    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.change(screen.getByLabelText('Nome a apresentar (opcional)'), {
      target: { value: 'Amélia Marques' },
    });
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), {
      target: { value: 'amelia@example.pt' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'Str0ng!Vault9' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'Str0ng!Vault9' },
    });
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.url).toContain('/v1/users');
    expect(post?.body).toMatchObject({
      username: 'amelia.marques',
      display_name: 'Amélia Marques',
      email: 'amelia@example.pt',
      password: 'Str0ng!Vault9',
    });
    // A success toast confirms the create (t44 retrofit-b) — it fires as the page navigates
    // to the new user's edit screen (ToastProvider is above the router).
    expect(await screen.findByText('Utilizador criado.')).toBeTruthy();
  });

  it('surfaces a duplicate-username 409 inline against the field', async () => {
    const { fn } = recordingFetch((r) =>
      r.method === 'POST'
        ? jsonResponse({ error: 'username already exists' }, 409)
        : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<NewUserPage />, ['/users/new']);

    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'Str0ng!Vault9' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'Str0ng!Vault9' },
    });
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    // The 409 message shows inline against the field and in the error toast (R7).
    expect((await screen.findAllByText(/already exists/)).length).toBeGreaterThanOrEqual(1);
  });

  /** Serve the reads the create screen makes: the role catalog and the SMTP status. */
  function createScreenFetch(
    roles: { id: string; name: string; permissions: string[]; protected: boolean }[],
    emailDeliverable: boolean,
  ) {
    return recordingFetch((r) => {
      if (r.method === 'POST') return jsonResponse(AMELIA, 201);
      if (r.url.includes('/v1/settings/email/status')) {
        return jsonResponse({
          password_configured: emailDeliverable,
          deliverable: emailDeliverable,
          encrypted: true,
          warnings: [],
        });
      }
      if (r.url.includes('/v1/roles')) return jsonResponse(roles);
      return jsonResponse([]);
    });
  }

  const LEITOR = { id: 'r-leitor', name: 'Leitor', permissions: ['entity.read'], protected: false };
  const OWNERISH = {
    id: 'r-owner',
    name: 'Proprietário',
    permissions: ['entity.read', 'data.wipe'],
    protected: true,
  };

  /** A creator holding `entity.read`@global and nothing else — Owner is above their ceiling. */
  function renderAsNarrowCreator(fn: typeof fetch) {
    vi.stubGlobal('fetch', fn);
    return renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission === 'entity.read')}
      >
        <NewUserPage />
      </StaticPermissionsProvider>,
      ['/users/new'],
    );
  }

  async function fillRequired() {
    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'Str0ng!Vault9' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'Str0ng!Vault9' },
    });
  }

  it('offers a grantable role and blocks one above the creators ceiling, naming it', async () => {
    const { fn } = createScreenFetch([LEITOR, OWNERISH], true);
    renderAsNarrowCreator(fn);

    const picker = (await screen.findByLabelText('Função')) as HTMLSelectElement;
    await waitFor(() =>
      expect(Array.from(picker.options).some((o) => o.value === 'r-leitor')).toBe(true),
    );
    const options = Array.from(picker.options);

    // The role whose whole permission set the creator holds is selectable.
    expect(options.find((o) => o.value === 'r-leitor')?.disabled).toBe(false);

    // The one carrying a verb they lack stays VISIBLE but unselectable, and says why —
    // a disabled option with a reason beats a 403 on submit.
    const owner = options.find((o) => o.value === 'r-owner');
    expect(owner?.disabled).toBe(true);
    expect(owner?.textContent).toContain('Proprietário');
    expect(owner?.textContent).toMatch(/acima da sua autoridade/i);
  });

  it('sends the chosen role in the SAME request as the create', async () => {
    const { fn, calls } = createScreenFetch([LEITOR, OWNERISH], true);
    renderAsNarrowCreator(fn);

    await fillRequired();
    fireEvent.change(await screen.findByLabelText('Função'), { target: { value: 'r-leitor' } });
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    // One request carries both the account and its authority — no second round trip that
    // could leave the user created-but-roleless.
    expect(calls.find((c) => c.method === 'POST')?.body).toMatchObject({
      username: 'amelia.marques',
      role: { role_id: 'r-leitor', scope: { kind: 'global' } },
    });
    expect(calls.filter((c) => c.method === 'POST').length).toBe(1);
  });

  it('disables the welcome tickbox when SMTP cannot deliver, and explains why', async () => {
    const { fn } = createScreenFetch([LEITOR], false);
    renderAsNarrowCreator(fn);

    const tickbox = (await screen.findByLabelText(/mensagem de boas-vindas/i)) as HTMLInputElement;
    expect(tickbox.disabled).toBe(true);
    expect(screen.getByText(/envio de e-mail não está configurado/i)).toBeTruthy();
    // The explanation points at the settings page rather than failing at submit.
    expect(screen.getByRole('link', { name: /configurar e-mail/i }).getAttribute('href')).toBe(
      '/settings/operations/email',
    );
  });

  it('keeps the tickbox disabled until an address is entered, then sends the flag', async () => {
    const { fn, calls } = createScreenFetch([LEITOR], true);
    renderAsNarrowCreator(fn);

    const tickbox = (await screen.findByLabelText(/mensagem de boas-vindas/i)) as HTMLInputElement;
    // Deliverable SMTP, but nowhere to send it yet.
    expect(tickbox.disabled).toBe(true);

    await fillRequired();
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), {
      target: { value: 'amelia@example.pt' },
    });
    await waitFor(() => expect(tickbox.disabled).toBe(false));
    fireEvent.click(tickbox);
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')?.body).toMatchObject({
      email: 'amelia@example.pt',
      send_welcome_email: true,
    });
  });

  it('defaults the language to auto and sends a chosen locale', async () => {
    const { fn, calls } = createScreenFetch([LEITOR], true);
    renderAsNarrowCreator(fn);

    const picker = (await screen.findByLabelText('Idioma')) as HTMLSelectElement;
    // `auto` is the default: a new account keeps following its user's environment until
    // somebody deliberately pins it.
    expect(picker.value).toBe('auto');

    await fillRequired();
    fireEvent.change(picker, { target: { value: 'de-DE' } });
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')?.body).toMatchObject({ language: 'de-DE' });
  });

  it('sends language auto untouched rather than resolving it to a detected locale', async () => {
    const { fn, calls } = createScreenFetch([LEITOR], true);
    renderAsNarrowCreator(fn);

    await fillRequired();
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    // The literal string, NOT whatever locale happened to be active — storing the detected
    // value would silently turn "follow my environment" into "pin me to this one".
    expect(calls.find((c) => c.method === 'POST')?.body).toMatchObject({ language: 'auto' });
  });

  it('never echoes the submitted password back into the form', async () => {
    const { fn } = createScreenFetch([LEITOR], true);
    renderAsNarrowCreator(fn);

    await fillRequired();

    // The secret lives only in the two password inputs, which are type=password — it is
    // never rendered as text anywhere on the screen.
    expect(screen.queryByText('Str0ng!Vault9')).toBeNull();
    for (const input of ['Nova palavra-passe', 'Confirmar palavra-passe']) {
      expect((screen.getByLabelText(input) as HTMLInputElement).type).toBe('password');
    }
  });
});

const BRUNO: UserView = {
  id: 'u2',
  username: 'bruno.dias',
  display_name: 'Bruno Dias',
  created_at: '2026-07-07T12:05:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
};

describe('EditUserPage (/users/:id) — identity + access manager', () => {
  it('renders identity and resolves a cold deep link via GET /v1/users/{id}', async () => {
    // Empty list cache → the edit screen falls back to the single-user read.
    const user = { ...AMELIA, email: 'amelia@example.pt' };
    const { fn, calls } = recordingFetch((r) =>
      r.url.endsWith('/v1/users/u1') ? jsonResponse(user) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

    // The immutable username and display name show as form values on the edit screen.
    expect(await screen.findByDisplayValue('amelia.marques')).toBeTruthy();
    expect(screen.getByDisplayValue('Amélia Marques')).toBeTruthy();
    expect(screen.getByDisplayValue('amelia@example.pt')).toBeTruthy();
    expect(calls.some((c) => c.url.endsWith('/v1/users/u1'))).toBe(true);
  });

  it('updates a user email via PATCH /v1/users/{id}', async () => {
    const user = { ...AMELIA, email: 'amelia@example.pt' };
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'PATCH'
        ? jsonResponse({ ...user, email: 'amelia.legal@example.pt' })
        : r.url.endsWith('/v1/users/u1')
          ? jsonResponse(user)
          : jsonResponse([user]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

    fireEvent.change(await screen.findByLabelText('E-mail (opcional)'), {
      target: { value: 'amelia.legal@example.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar nome' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.url).toContain('/v1/users/u1');
    expect(patch?.body).toMatchObject({ email: 'amelia.legal@example.pt' });
  });

  it('sets a sign-in password via POST /v1/users/{id}/secret', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.url.includes('/secret') && r.method === 'POST'
        ? jsonResponse({ ...AMELIA, has_secret: true })
        : r.url.endsWith('/v1/users/u1')
          ? jsonResponse(AMELIA)
          : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1', 'access');

    fireEvent.click(await screen.findByRole('button', { name: 'Definir palavra-passe' }));

    fireEvent.change(await screen.findByLabelText('Nova palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/secret') && c.method === 'POST')).toBe(true),
    );
    const post = calls.find((c) => c.url.includes('/secret') && c.method === 'POST');
    expect(post?.url).toContain('/v1/users/u1/secret');
    expect(post?.body).toMatchObject({ password: 'password123' });
  });

  it('hides the remove-password action for users that already have a password', async () => {
    const secured = { ...AMELIA, has_secret: true };
    const { fn, calls } = recordingFetch((r) =>
      r.url.endsWith('/v1/users/u1') ? jsonResponse(secured) : jsonResponse([secured]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1', 'access');

    expect(await screen.findByRole('button', { name: 'Alterar' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Remover' })).toBeNull();
    expect(calls.some((c) => c.url.includes('/secret') && c.method === 'DELETE')).toBe(false);
  });

  it('blocks mismatched passwords before hitting the server', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.url.endsWith('/v1/users/u1') ? jsonResponse(AMELIA) : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1', 'access');

    fireEvent.click(await screen.findByRole('button', { name: 'Definir palavra-passe' }));
    fireEvent.change(await screen.findByLabelText('Nova palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'different1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    expect(await screen.findByText('As palavras-passe não coincidem.')).toBeTruthy();
    expect(calls.some((c) => c.url.includes('/secret'))).toBe(false);
  });

  it('generates an audit key for a user that already has a password', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.url.includes('/attestation-key') && r.method === 'POST'
        ? jsonResponse({
            ...BRUNO,
            has_attestation_key: true,
            attestation_key_fingerprint: 'ab'.repeat(16),
          })
        : r.url.endsWith('/v1/users/u2')
          ? jsonResponse(BRUNO)
          : jsonResponse([BRUNO]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2', 'access');

    fireEvent.change(await screen.findByLabelText('Palavra-passe atual'), {
      target: { value: 'current-pw' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Gerar chave' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/attestation-key') && c.method === 'POST')).toBe(
        true,
      ),
    );
    const post = calls.find((c) => c.url.includes('/attestation-key') && c.method === 'POST');
    expect(post?.url).toContain('/v1/users/u2/attestation-key');
    expect(post?.body).toMatchObject({ current_password: 'current-pw' });
  });

  it('downloads the DSR/privacy JSON export without rendering its contents', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'chancela-dsr-user-amelia.marques.json',
      contentType: 'application/json',
      bytes: 82,
    });
    const exportPayload = {
      user: { id: 'u1', username: 'amelia.marques' },
      audit_marker: 'opaque-internal-value',
    };
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/privacy/users/u1/export')) {
        return jsonResponse(exportPayload);
      }
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests')) return jsonResponse([]);
      if (r.url.endsWith('/v1/users/u1')) return jsonResponse(AMELIA);
      return jsonResponse([AMELIA]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1', 'dsr');

    fireEvent.click(await screen.findByRole('button', { name: 'Descarregar exportação DSR' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      filters: { name: string; extensions: string[] }[];
    };
    expect(saved.filename).toBe('chancela-dsr-user-amelia.marques.json');
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/json');
    expect(saved.contentType).toBe('application/json');
    expect(saved.filters).toEqual([{ name: 'JSON', extensions: ['json'] }]);
    expect(await blobText(saved.blob)).toBe(JSON.stringify(exportPayload, null, 2));
    expect(calls).toContainEqual({
      url: '/v1/privacy/users/u1/export',
      method: 'GET',
      body: null,
    });
    expect(screen.queryByText('opaque-internal-value')).toBeNull();
    expect(saveFileMock.saveBlobResultMessage).toHaveBeenCalledWith({
      kind: 'browser-download',
      filename: 'chancela-dsr-user-amelia.marques.json',
      contentType: 'application/json',
      bytes: 82,
    });
    expect(
      await screen.findByText(
        'Transferência iniciada pelo navegador: chancela-dsr-user-amelia.marques.json. A pasta é definida pelo browser.',
      ),
    ).toBeTruthy();
  });

  it('lists, creates, and completes DSR lifecycle requests', async () => {
    const pending: DsrRequestView = {
      id: 'dsr-1',
      subject_user_id: 'u1',
      request_type: 'export',
      status: 'pending',
      created_at: '2026-07-08T09:00:00Z',
      created_by: 'operator',
    };
    let dsrRequests: DsrRequestView[] = [pending];
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests') && r.method === 'GET') {
        return jsonResponse(dsrRequests);
      }
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests') && r.method === 'POST') {
        const created: DsrRequestView = {
          id: 'dsr-2',
          subject_user_id: 'u1',
          request_type: r.body?.request_type as DsrRequestType,
          status: 'pending',
          created_at: '2026-07-08T10:00:00Z',
          created_by: 'operator',
        };
        dsrRequests = [...dsrRequests, created];
        return jsonResponse(created, 201);
      }
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests/dsr-1/complete')) {
        const completed: DsrRequestView = {
          ...pending,
          status: 'completed',
          completed_at: '2026-07-08T11:00:00Z',
          completed_by: 'operator',
        };
        dsrRequests = [completed, ...dsrRequests.slice(1)];
        return jsonResponse(completed);
      }
      if (r.url.endsWith('/v1/users/u1')) return jsonResponse(AMELIA);
      return jsonResponse([AMELIA]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1', 'dsr');

    expect(await screen.findByText('Pedidos DSR / privacidade')).toBeTruthy();
    expect(await screen.findByText('Exportação')).toBeTruthy();
    expect(screen.getByText('Pendente')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Tipo de pedido'), {
      target: { value: 'erasure' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar pedido DSR' }));

    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.url.endsWith('/v1/privacy/users/u1/dsr-requests') &&
            c.method === 'POST' &&
            c.body?.request_type === 'erasure',
        ),
      ).toBe(true),
    );
    expect((await screen.findAllByText('Apagamento')).length).toBeGreaterThanOrEqual(2);
    expect(await screen.findByText('Pedido DSR criado.')).toBeTruthy();

    fireEvent.click(screen.getAllByRole('button', { name: 'Marcar concluído' })[0]);

    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.url.endsWith('/v1/privacy/users/u1/dsr-requests/dsr-1/complete') &&
            c.method === 'POST' &&
            c.body === null,
        ),
      ).toBe(true),
    );
    expect((await screen.findAllByText('Concluído')).length).toBeGreaterThanOrEqual(2);
    expect(await screen.findByText('Pedido DSR marcado como concluído.')).toBeTruthy();
  });

  it('renders the DSR created-at as an evidentiary timestamp, not a rounded one', async () => {
    // A data-subject request is a privacy-compliance record: its timestamp must carry seconds and
    // the zone (the `evidentiary` flag), not the to-the-minute everyday form. t102 flagged this
    // as behaviour to preserve when the markup moved into a tab; "I did not touch it" is a weaker
    // guarantee than an assertion, so this pins it. Expected value computed the same way the
    // component does, so it is locale/zone-independent (the footer-version test's pattern).
    const pending: DsrRequestView = {
      id: 'dsr-1',
      subject_user_id: 'u1',
      request_type: 'export',
      status: 'pending',
      created_at: '2026-07-08T09:00:00Z',
      created_by: 'operator',
    };
    const { fn } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests') && r.method === 'GET') {
        return jsonResponse([pending]);
      }
      if (r.url.endsWith('/v1/users/u1')) return jsonResponse(AMELIA);
      return jsonResponse([AMELIA]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1', 'dsr');

    // Wait for the actual request ROW, not the 'Exportação' select option which is present
    // immediately in the create form regardless of the list load state.
    await screen.findByText('Pendente');
    // The evidentiary rendering and the everyday one differ precisely by seconds + zone, so
    // matching the former and NOT the latter is what proves the flag survived the move. Read it
    // off the `<time>` element's textContent — DateTime splits the value across nodes — and the
    // expected string is computed the same way the component does, so it is locale/zone-neutral.
    const times = [...document.querySelectorAll('time')].map((el) => el.textContent ?? '');
    expect(times).toContain(formatTimestamp(pending.created_at));
    expect(times).not.toContain(formatDateTime(pending.created_at));
  });

  it('omits the DSR lifecycle surface for users without user.manage', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.url.endsWith('/v1/users/u1') ? jsonResponse(AMELIA) : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'user.manage')}
      >
        <Routes>
          <Route path="/users/:id" element={<EditUserPage />} />
        </Routes>
      </StaticPermissionsProvider>,
      ['/users/u1'],
    );

    expect(await screen.findByDisplayValue('amelia.marques')).toBeTruthy();
    expect(screen.queryByText('Pedidos DSR / privacidade')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Criar pedido DSR' })).toBeNull();
    expect(calls.some((c) => c.url.includes('/v1/privacy/'))).toBe(false);
  });
});

// --- Estado da conta, rebuilt (t103) --------------------------------------------------
describe('EditUserPage — account status reads as a state with an action', () => {
  function stubUser(user: UserView) {
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'PATCH'
        ? jsonResponse({ ...user, active: !user.active })
        : r.url.endsWith(`/v1/users/${user.id}`)
          ? jsonResponse(user)
          : jsonResponse([user]),
    );
    vi.stubGlobal('fetch', fn);
    return calls;
  }

  it('names the action in words rather than leaving it an unlabelled icon', async () => {
    stubUser(AMELIA);
    renderEditAt('u1');

    // The defect this replaces: a Badge and a bare power glyph side by side, where the only
    // name the action had was a tooltip. `getByRole('button', {name})` matching on visible text
    // is exactly the assertion that would have failed before.
    expect(await screen.findByRole('button', { name: 'Desativar' })).toBeTruthy();
    expect(screen.getByText('Estado da conta')).toBeTruthy();
  });

  it('states the consequence next to the control, for each state', async () => {
    stubUser(AMELIA);
    renderEditAt('u1');

    // Accounts are never deleted — that is the fact that makes deactivation legible, and it
    // has to be adjacent to the control, not in a manual.
    expect(await screen.findByText(/nunca são eliminadas/)).toBeTruthy();
  });

  it('offers reactivation, and the matching explanation, for an inactive account', async () => {
    stubUser({ ...AMELIA, id: 'u9', active: false });
    renderWithProviders(
      <Routes>
        <Route path="/users/:id" element={<EditUserPage />} />
      </Routes>,
      ['/users/u9'],
    );

    expect(await screen.findByRole('button', { name: 'Reativar' })).toBeTruthy();
    expect(screen.getByText(/não pode iniciar sessão/)).toBeTruthy();
  });

  it('still performs the toggle', async () => {
    const calls = stubUser(AMELIA);
    renderEditAt('u1');

    fireEvent.click(await screen.findByRole('button', { name: 'Desativar' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    expect(calls.find((c) => c.method === 'PATCH')?.body).toMatchObject({ active: false });
  });

  it('gates the toggle on user.manage, like the identical control on the roster', async () => {
    // Before t103 this was a plain IconButton while the roster's equivalent was a
    // GateIconButton, so an operator without `user.manage` was offered a control whose only
    // possible outcome was a 403. The server was always the real gate; the screen was lying.
    const calls = stubUser(AMELIA);
    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'user.manage')}
      >
        <Routes>
          <Route path="/users/:id" element={<EditUserPage />} />
        </Routes>
      </StaticPermissionsProvider>,
      ['/users/u1'],
    );

    const button = await screen.findByRole('button', { name: 'Desativar' });
    expect(button.getAttribute('data-gated')).toBe('true');
    expect(button.getAttribute('aria-disabled')).toBe('true');

    fireEvent.click(button);
    // The gate swallows the click — no request is attempted at all.
    await waitFor(() => expect(screen.getByText('Estado da conta')).toBeTruthy());
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false);
  });
});

// --- Acesso e auditoria, brought onto the house primitives (t103) ----------------------
describe('EditUserPage — access & audit uses the shared card/row treatment', () => {
  function stubUser(user: UserView) {
    const { fn } = recordingFetch((r) =>
      r.url.endsWith(`/v1/users/${user.id}`) ? jsonResponse(user) : jsonResponse([user]),
    );
    vi.stubGlobal('fetch', fn);
  }

  it('renders the three credentials as grouped cards, not one private two-column grid', async () => {
    stubUser({ ...AMELIA, has_secret: true });
    renderEditAt('u1', 'access');

    // Wait for the user to resolve — the section only exists once the screen has one. Waiting on
    // access-tab content, not the identity field: that field is on the Geral tab now.
    await screen.findByText('Palavra-passe');
    const acesso = document.querySelector('section#acesso');
    expect(acesso).not.toBeNull();

    // Three cards, one per credential — each carrying the shared `.panel` treatment.
    const cards = acesso!.querySelectorAll('.panel');
    expect(cards.length).toBe(3);
    // …and each is a real card with a heading, which the old `__label` span was not.
    expect(within(acesso as HTMLElement).getByText('Palavra-passe')).toBeTruthy();
    expect(within(acesso as HTMLElement).getByText('Frase de recuperação')).toBeTruthy();
    expect(within(acesso as HTMLElement).getByText('Chave de auditoria')).toBeTruthy();
  });

  it('drops the private grid classes in favour of the shared row grid', async () => {
    stubUser({ ...AMELIA, has_secret: true });
    renderEditAt('u1', 'access');

    await screen.findByText('Palavra-passe');
    const acesso = document.querySelector('section#acesso') as HTMLElement;

    // The hand-rolled stand-ins are gone…
    for (const dead of [
      '.access-manager__head',
      '.access-manager__label',
      '.access-manager__form',
      '.access-manager__actions',
      '.access-manager__fingerprint',
    ]) {
      expect(acesso.querySelector(dead), dead).toBeNull();
    }
    // …and the section is no longer a panel nested inside another panel.
    expect(acesso.querySelector('.panel .panel')).toBeNull();
  });

  it('keeps the t92 rotation copy exactly, and does not reintroduce the old claim', async () => {
    stubUser({
      ...AMELIA,
      has_secret: true,
      has_attestation_key: true,
      attestation_key_fingerprint: 'a'.repeat(32),
    });
    renderEditAt('u1', 'access');

    expect(await screen.findByRole('button', { name: 'Rodar chave' })).toBeTruthy();
    // The fingerprint is now a labelled row rather than a bare paragraph.
    expect(screen.getByText('Impressão digital')).toBeTruthy();
    expect(screen.getByText('a'.repeat(32))).toBeTruthy();
    // Rotation retains superseded PUBLIC halves, so past attestations keep verifying (t92).
    // Any wording claiming they stop verifying would be a regression.
    expect(document.body.textContent).not.toMatch(/deixam de ser verificáveis/i);
  });
});

describe('legacy /users routes', () => {
  it('redirects /users to the settings users section', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/users" element={<LegacyUsersRedirect />} />
        <Route path="/settings/:sec?" element={<LocationProbe />} />
      </Routes>,
      ['/users'],
    );

    expect((await screen.findByLabelText('location')).textContent).toBe('/settings/users');
  });

  it('redirects legacy edit-style user links onto the edit screen, keeping #acesso', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/users/:id/edit" element={<LegacyUserEditRedirect />} />
        <Route path="/users/:id" element={<LocationProbe />} />
      </Routes>,
      ['/users/u1/edit#acesso'],
    );

    expect((await screen.findByLabelText('location')).textContent).toBe('/users/u1#acesso');
  });
});

// The signed-in operator, a DIFFERENT user from the one being edited — makes every edit of
// BRUNO/AMELIA a cross-user op (t51).
const OPERATOR: UserView = {
  id: 'u9',
  username: 'operator',
  display_name: 'Operador',
  created_at: '2026-07-07T12:10:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
};

describe('EditUserPage — cross-user password change proof + 403 (t51)', () => {
  it('self-service change shows the plain current-password field, not the cross-user proof', async () => {
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: BRUNO }); // editing yourself
      if (r.url.includes('/secret') && r.method === 'POST') return jsonResponse({ ...BRUNO });
      if (r.url.endsWith('/v1/users/u2')) return jsonResponse(BRUNO);
      return jsonResponse([BRUNO]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2', 'access');

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    // Self-service keeps the plain "Palavra-passe atual" field and shows NO proof selector.
    // (The password form's current field precedes the key block's, so [0] is the change field.)
    expect((await screen.findAllByLabelText('Palavra-passe atual')).length).toBeGreaterThanOrEqual(
      1,
    );
    expect(screen.queryByText('Prova de autorização')).toBeNull();

    fireEvent.change(screen.getAllByLabelText('Palavra-passe atual')[0], {
      target: { value: 'current-pw' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/secret') && c.method === 'POST')).toBe(true),
    );
    const post = calls.find((c) => c.url.includes('/secret') && c.method === 'POST');
    expect(post?.body).toMatchObject({ password: 'newpassword1', current_password: 'current-pw' });
    expect(post?.body).not.toHaveProperty('recovery_phrase');
  });

  it('cross-user change collects the target current password and sends it as the proof', async () => {
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: OPERATOR });
      if (r.url.includes('/secret') && r.method === 'POST') return jsonResponse({ ...BRUNO });
      if (r.url.endsWith('/v1/users/u2')) return jsonResponse(BRUNO);
      return jsonResponse([BRUNO]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2', 'access');

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    // Cross-user: the proof selector + the target's current-password field are shown.
    expect(await screen.findByText('Prova de autorização')).toBeTruthy();
    // The proof value field (password block) precedes the key block's current field → [0].
    fireEvent.change((await screen.findAllByLabelText('Palavra-passe atual do utilizador'))[0], {
      target: { value: 'target-current' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/secret') && c.method === 'POST')).toBe(true),
    );
    const post = calls.find((c) => c.url.includes('/secret') && c.method === 'POST');
    expect(post?.body).toMatchObject({
      password: 'newpassword1',
      current_password: 'target-current',
    });
    expect(post?.body).not.toHaveProperty('recovery_phrase');
  });

  it('cross-user change can authorize with a recovery phrase instead', async () => {
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: OPERATOR });
      if (r.url.includes('/secret') && r.method === 'POST') return jsonResponse({ ...BRUNO });
      if (r.url.endsWith('/v1/users/u2')) return jsonResponse(BRUNO);
      return jsonResponse([BRUNO]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2', 'access');

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    // Switch the proof kind to a recovery phrase.
    fireEvent.change(await screen.findByLabelText('Prova de autorização'), {
      target: { value: 'recovery' },
    });
    fireEvent.change(screen.getByLabelText('Frase de recuperação do utilizador'), {
      target: { value: 'ABCD1234-EFGH5678' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/secret') && c.method === 'POST')).toBe(true),
    );
    const post = calls.find((c) => c.url.includes('/secret') && c.method === 'POST');
    expect(post?.body).toMatchObject({
      password: 'newpassword1',
      recovery_phrase: 'ABCD1234-EFGH5678',
    });
    expect(post?.body).not.toHaveProperty('current_password');
  });

  it('renders a 403 refusal inline + toast and keeps the field retryable', async () => {
    const serverMsg = 'não autorizado a alterar as credenciais de outro utilizador';
    const { fn } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: OPERATOR });
      if (r.url.includes('/secret') && r.method === 'POST')
        return jsonResponse({ error: serverMsg }, 403);
      if (r.url.endsWith('/v1/users/u2')) return jsonResponse(BRUNO);
      return jsonResponse([BRUNO]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2', 'access');

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    fireEvent.change((await screen.findAllByLabelText('Palavra-passe atual do utilizador'))[0], {
      target: { value: 'wrong' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    // Honest inline refusal (distinct from the toast) + the field stays present/editable.
    expect(await screen.findByText(/Não autorizado — precisa da palavra-passe atual/)).toBeTruthy();
    expect(
      screen.getAllByLabelText('Palavra-passe atual do utilizador').length,
    ).toBeGreaterThanOrEqual(1);
    // The server's PT 403 message surfaces via the error toast.
    expect(await screen.findByText(new RegExp(serverMsg))).toBeTruthy();
  });

  it('issues a recovery phrase, shows it once, then clears it on dismissal', async () => {
    const phrase = 'ABCD1234-EFGH5678-JKMN9012-PQRS3456';
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: AMELIA }); // self, no secret
      if (r.url.includes('/recovery') && r.method === 'POST')
        return jsonResponse({ ...AMELIA, has_recovery_phrase: true, recovery_phrase: phrase });
      if (r.url.endsWith('/v1/users/u1')) return jsonResponse(AMELIA);
      return jsonResponse([AMELIA]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1', 'access');

    fireEvent.click(await screen.findByRole('button', { name: 'Gerar frase de recuperação' }));
    // Self + legacy no-hash state → no proof exists; just submit.
    fireEvent.click(await screen.findByRole('button', { name: 'Gerar frase' }));

    // The phrase is shown exactly once, prominently.
    expect(await screen.findByText(phrase)).toBeTruthy();
    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/recovery') && c.method === 'POST')).toBe(true),
    );

    // Dismiss → the phrase is gone from the UI (never retrievable again).
    fireEvent.click(screen.getByRole('button', { name: 'Concluído' }));
    await waitFor(() => expect(screen.queryByText(phrase)).toBeNull());
  });
});

// --- The tabbed edit screen (t103) ----------------------------------------------------
//
// The three properties the brief names — deep-linkable, survives reload, answers Back — are all
// consequences of ONE decision: the section lives in the path and is derived from it on every
// render, never mirrored into component state. A local tab strip would fail all three at once,
// so these tests are written against the address rather than against the strip.
describe('EditUserPage — sub-tabs live in the path', () => {
  /** Drives history backwards, which a MemoryRouter cannot do through `window.history`. */
  function BackButton() {
    const navigate = useNavigate();
    return (
      <button type="button" onClick={() => navigate(-1)}>
        back-probe
      </button>
    );
  }

  function renderTabbed(entries: string[], canManage = true) {
    const { fn } = recordingFetch((r) =>
      r.url.endsWith('/v1/users/u1') ? jsonResponse(AMELIA) : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);
    return renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => canManage || permission !== 'user.manage')}
      >
        <Routes>
          <Route
            path="/users/:id/:sec?"
            element={
              <>
                <EditUserPage />
                <LocationProbe />
                <BackButton />
              </>
            }
          />
        </Routes>
      </StaticPermissionsProvider>,
      entries,
    );
  }

  it('paints a deep-linked tab directly, without rendering the default one first', async () => {
    renderTabbed(['/users/u1/access']);

    expect(await screen.findByText('Chave de auditoria')).toBeTruthy();
    // Geral's identity form is not merely hidden — it was never rendered. A tab strip that
    // mirrored the path into state would have flashed this field before switching.
    expect(screen.queryByDisplayValue('amelia.marques')).toBeNull();
  });

  it('is the same view after a reload, because the address carries the whole state', async () => {
    // "Survives reload" for a client-side app means: mounting fresh at that address reproduces
    // the view. Re-rendering from scratch at the deep link is exactly that.
    const first = renderTabbed(['/users/u1/roles']);
    expect(await screen.findByText('Funções')).toBeTruthy();
    first.unmount();

    renderTabbed(['/users/u1/roles']);
    expect(await screen.findByText('Funções')).toBeTruthy();
  });

  it('pushes on a tab switch, so Back returns to the previous tab', async () => {
    renderTabbed(['/users/u1']);
    await screen.findByDisplayValue('amelia.marques');
    expect(screen.getByLabelText('location').textContent).toBe('/users/u1');

    fireEvent.click(screen.getByRole('button', { name: 'Acesso e auditoria' }));
    await waitFor(() =>
      expect(screen.getByLabelText('location').textContent).toBe('/users/u1/access'),
    );

    // Back must return to Geral rather than leaving the screen: a tab is somewhere the operator
    // navigated to. This is what a `replace` would have broken.
    fireEvent.click(screen.getByRole('button', { name: 'back-probe' }));
    await waitFor(() => expect(screen.getByLabelText('location').textContent).toBe('/users/u1'));
    expect(screen.getByDisplayValue('amelia.marques')).toBeTruthy();
  });

  it('promotes the retired #acesso fragment to the access tab', async () => {
    // The fragment was carried across t89 and t97 so an old bookmark would still land on access.
    // Now that access is a tab there is nothing to scroll to, so it has to become the segment —
    // otherwise the bookmark silently lands on Geral, which is the failure it was preserved
    // against. `replace`, so Back does not bounce between the two addresses.
    renderTabbed(['/users/u1#acesso']);

    await waitFor(() =>
      expect(screen.getByLabelText('location').textContent).toBe('/users/u1/access'),
    );
    expect(await screen.findByText('Chave de auditoria')).toBeTruthy();
  });

  it('falls back to Geral for an unknown section instead of blanking the screen', async () => {
    renderTabbed(['/users/u1/quantum']);

    // Same rule the roster filters follow: a stale or hand-edited address degrades to the
    // default view, never to an empty one.
    expect(await screen.findByDisplayValue('amelia.marques')).toBeTruthy();
  });

  it('hides the DSR tab from an operator without user.manage', async () => {
    renderTabbed(['/users/u1'], false);

    await screen.findByDisplayValue('amelia.marques');
    // The panel already self-gates and would render nothing; offering a tab that opens onto
    // nothing is worse than not offering it.
    expect(screen.queryByRole('button', { name: 'Pedidos DSR' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Acesso e auditoria' })).toBeTruthy();
  });
});

// --- Segurança tab (t103) -------------------------------------------------------------
describe('EditUserPage — Segurança tab', () => {
  /** `session` decides self-vs-other; the edited user is always `u1` (Amélia). `twoFactor`, when
   *  given, answers `GET …/two-factor` — otherwise a state derived from `user.has_totp`. */
  function renderSecurity(
    user: UserView,
    sessionUser: UserView,
    twoFactor?: Partial<TwoFactorStatus>,
  ) {
    const { fn } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: sessionUser });
      if (r.url.endsWith(`/v1/users/${user.id}/two-factor`)) {
        return jsonResponse({
          enrolled: user.has_totp,
          confirmed: user.has_totp,
          required: user.two_factor_required,
          backup_codes_remaining: user.has_totp ? 8 : undefined,
          ...twoFactor,
        });
      }
      if (r.url.endsWith(`/v1/users/${user.id}`)) return jsonResponse(user);
      return jsonResponse([user]);
    });
    vi.stubGlobal('fetch', fn);
    return renderWithProviders(
      <Routes>
        <Route
          path="/users/:id/:sec?"
          element={
            <>
              <EditUserPage />
              <LocationProbe />
            </>
          }
        />
      </Routes>,
      [`/users/${user.id}/security`],
    );
  }

  it('sits between Funções and Acesso e auditoria in the strip', async () => {
    renderSecurity(AMELIA, AMELIA);
    await screen.findByText('Segurança da conta');

    const strip = document.querySelector('.subnav') as HTMLElement;
    const labels = [...strip.querySelectorAll('button')].map((b) => b.textContent?.trim());
    expect(labels).toEqual(['Geral', 'Pedidos DSR', 'Funções', 'Segurança', 'Acesso e auditoria']);
  });

  it('reads as the holder’s own view when editing your own account', async () => {
    renderSecurity(AMELIA, AMELIA); // session user == edited user
    // The self copy names the verb distinction — "here you see them as the account holder".
    expect(await screen.findByText(/gere a segurança da sua própria conta/i)).toBeTruthy();
  });

  it('reads as read-only state when editing another user', async () => {
    renderSecurity(AMELIA, OPERATOR); // session user != edited user
    // The other-user copy defers actions to Acesso e auditoria rather than offering self-service.
    expect(await screen.findByText(/Estado de segurança desta conta/i)).toBeTruthy();
  });

  it('shows credential posture from UserView, including the key fingerprint', async () => {
    const withKey: UserView = {
      ...AMELIA,
      has_secret: true,
      has_attestation_key: true,
      has_recovery_phrase: true,
      has_totp: false,
      two_factor_required: false,
      attestation_key_fingerprint: 'b'.repeat(32),
    };
    renderSecurity(withKey, withKey);

    await screen.findByText('Segurança da conta');
    // Posture is read from the booleans + fingerprint the list payload already carries — no new
    // request, and no key material beyond the fingerprint UserView publishes.
    expect(screen.getByText('b'.repeat(32))).toBeTruthy();
    // The t92 rotation truth is stated and must not regress to the old "stop verifying" wording.
    expect(document.body.textContent).toMatch(/continuam verificáveis/i);
    expect(document.body.textContent).not.toMatch(/deixam de ser verificáveis/i);
  });

  it('links management to Acesso e auditoria rather than duplicating the controls', async () => {
    renderSecurity(AMELIA, AMELIA);

    // Single-source: the credential managers live on the access tab, and Segurança points there
    // instead of re-mounting them — two places to change one credential is the defect t71/t89
    // removed. So there is NO password/key/recovery FORM control on this tab.
    await screen.findByText('Segurança da conta');
    expect(screen.queryByLabelText('Nova palavra-passe')).toBeNull();
    expect(screen.getByRole('button', { name: 'Gerir em Acesso e auditoria' })).toBeTruthy();
  });

  it('renders the real TOTP block now that t107 landed it, but still no sessions placeholder', async () => {
    // TOTP has shipped against t107's frozen contract, so it is present (not a stub). The
    // sessions panel is still a seam — its backend (enriched record + list/revoke) is funded but
    // not built — so there is deliberately no "Sessões ativas" text or placeholder for it yet.
    renderSecurity(AMELIA, AMELIA);
    await screen.findByText('Segurança da conta');

    const body = document.body.textContent ?? '';
    expect(body).toMatch(/dois fatores/i); // TOTP block is real
    expect(body).not.toMatch(/sess(ões|ão) ativ/i); // sessions still a seam, no fake list
  });

  it('is visible without user.manage, unlike the DSR tab', async () => {
    // Segurança shows only state UserView already exposes and reached via a screen already behind
    // user.manage; it needs no extra gate, and hiding it would remove the one place a user reads
    // their own posture. (Contrast the DSR tab, which is hidden without user.manage.)
    const { fn } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: AMELIA });
      if (r.url.endsWith('/v1/users/u1')) return jsonResponse(AMELIA);
      return jsonResponse([AMELIA]);
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'user.manage')}
      >
        <Routes>
          <Route path="/users/:id/:sec?" element={<EditUserPage />} />
        </Routes>
      </StaticPermissionsProvider>,
      ['/users/u1/security'],
    );

    expect(await screen.findByText('Segurança da conta')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Pedidos DSR' })).toBeNull();
  });
});

// --- TOTP block on the Segurança tab (t103 against t107's frozen contract) -------------
describe('EditUserPage — two-factor (TOTP)', () => {
  const SELF = { ...AMELIA };

  function stub(user: UserView, sessionUser: UserView, handlers: Record<string, () => Response>) {
    const { fn, calls } = recordingFetch((r) => {
      for (const [suffix, make] of Object.entries(handlers)) {
        if (r.url.endsWith(suffix)) return make();
      }
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: sessionUser });
      if (r.url.endsWith(`/v1/users/${user.id}/two-factor`)) {
        return jsonResponse({
          enrolled: user.has_totp,
          confirmed: user.has_totp,
          required: user.two_factor_required,
          backup_codes_remaining: user.has_totp ? 8 : undefined,
        });
      }
      if (r.url.endsWith(`/v1/users/${user.id}`)) return jsonResponse(user);
      return jsonResponse([user]);
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <Routes>
        <Route path="/users/:id/:sec?" element={<EditUserPage />} />
      </Routes>,
      [`/users/${user.id}/security`],
    );
    return calls;
  }

  it('walks a self-service enrolment: QR + secret, confirm, then backup codes shown once', async () => {
    let enrolled = false;
    const calls = stub(SELF, SELF, {
      '/two-factor/totp/enrol': () =>
        jsonResponse({
          secret: 'JBSWY3DPEHPK3PXP',
          provisioning_uri: 'otpauth://totp/Chancela:amelia?secret=JBSWY3DPEHPK3PXP',
          confirmed: false,
        }),
      '/two-factor/totp/confirm': () => {
        enrolled = true;
        return jsonResponse({
          backup_codes: Array.from({ length: 10 }, (_, i) => `code-${i}`),
          backup_codes_remaining: 10,
        });
      },
    });
    void enrolled;

    fireEvent.click(await screen.findByRole('button', { name: 'Ativar dois fatores' }));

    // The manual secret is shown for keying by hand, and a QR (an <svg>) for scanning.
    expect(await screen.findByText('JBSWY3DPEHPK3PXP')).toBeTruthy();
    const card = screen.getByText('JBSWY3DPEHPK3PXP').closest('.panel') as HTMLElement;
    expect(card.querySelector('svg')).not.toBeNull();

    fireEvent.change(screen.getByLabelText('Código de verificação'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar' }));

    // The ten backup codes are shown once, with the save-now warning.
    expect(await screen.findByText('Guarde os códigos de recuperação')).toBeTruthy();
    expect(screen.getByText('code-0')).toBeTruthy();
    expect(screen.getByText('code-9')).toBeTruthy();
    expect(
      calls.some((c) => c.url.endsWith('/two-factor/totp/confirm') && c.body?.code === '123456'),
    ).toBe(true);
  });

  it('surfaces a wrong confirmation code inline without ejecting the operator', async () => {
    stub(SELF, SELF, {
      '/two-factor/totp/enrol': () =>
        jsonResponse({
          secret: 'JBSWY3DPEHPK3PXP',
          provisioning_uri: 'otpauth://totp/Chancela:amelia?secret=JBSWY3DPEHPK3PXP',
          confirmed: false,
        }),
      // A wrong code is a 401 — the API client must treat it as a credential proof, NOT a dead
      // session, or a typo would sign the operator out of the whole app.
      '/two-factor/totp/confirm': () => jsonResponse({ message: 'código inválido' }, 401),
    });

    fireEvent.click(await screen.findByRole('button', { name: 'Ativar dois fatores' }));
    fireEvent.change(await screen.findByLabelText('Código de verificação'), {
      target: { value: '000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar' }));

    // Inline refusal, field still there to retry.
    expect(await screen.findByText('Código incorreto. Tente novamente.')).toBeTruthy();
    expect(screen.getByLabelText('Código de verificação')).toBeTruthy();
  });

  it('offers regenerate + disable when enrolled and the account is not required', async () => {
    const enrolledUser: UserView = { ...SELF, has_totp: true, two_factor_required: false };
    stub(enrolledUser, enrolledUser, {});

    expect(await screen.findByRole('button', { name: 'Gerar novos códigos' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Desativar dois fatores' })).toBeTruthy();
    // The remaining-codes count comes from the two-factor read.
    expect(screen.getByText('8')).toBeTruthy();
  });

  it('replaces disable with an explanation when the account is required to keep 2FA', async () => {
    const requiredUser: UserView = { ...SELF, has_totp: true, two_factor_required: true };
    stub(requiredUser, requiredUser, {});

    // Wait for the SELF branch — the regenerate button only exists there — so the assertion does
    // not race the session query (before it resolves, `isSelf` is false and the admin branch shows).
    expect(await screen.findByRole('button', { name: 'Gerar novos códigos' })).toBeTruthy();
    // The server would 409 a disable on a required account, so the UI does not offer the button.
    expect(screen.queryByRole('button', { name: 'Desativar dois fatores' })).toBeNull();
    expect(screen.getByText(/obrigada a manter dois fatores/i)).toBeTruthy();
  });

  it('shows an admin read-only state plus the require toggle, never enrol or disable', async () => {
    const other: UserView = { ...SELF, has_totp: true, two_factor_required: false };
    const calls = stub(other, OPERATOR, {
      '/v1/users/u1': () => jsonResponse(other), // PATCH echoes; GET returns the user
    });

    // Read-only for an admin: no enrol, no disable, no confirmation field.
    await screen.findByText('Segurança da conta');
    expect(screen.queryByRole('button', { name: 'Ativar dois fatores' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Desativar dois fatores' })).toBeNull();
    expect(screen.queryByLabelText('Código de verificação')).toBeNull();

    // The one legitimate admin action: require a second factor.
    fireEvent.click(screen.getByRole('button', { name: 'Exigir' }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === 'PATCH' && c.body?.two_factor_required === true)).toBe(
        true,
      ),
    );
  });

  it('regenerates backup codes and shows the fresh set once', async () => {
    const enrolledUser: UserView = { ...SELF, has_totp: true, two_factor_required: false };
    const calls = stub(enrolledUser, enrolledUser, {
      '/two-factor/backup-codes': () =>
        jsonResponse({
          backup_codes: Array.from({ length: 10 }, (_, i) => `fresh-${i}`),
          backup_codes_remaining: 10,
        }),
    });

    fireEvent.click(await screen.findByRole('button', { name: 'Gerar novos códigos' }));

    expect(await screen.findByText('fresh-0')).toBeTruthy();
    expect(screen.getByText('Guarde os códigos de recuperação')).toBeTruthy();
    expect(calls.some((c) => c.url.endsWith('/two-factor/backup-codes'))).toBe(true);
  });
});
