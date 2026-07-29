/**
 * The page chrome every RGPD register record page wears (t55) — breadcrumbs, title, the two
 * cancel affordances, the permission gate, and the four states an edit page can be in.
 *
 * ## Measure: narrow, deliberately NOT `.wide-page`
 *
 * `TemplateCreatePage` opts into the wide shell because it hosts a WYSIWYG plus a live preview.
 * These five are label/control row forms, and the measurement already recorded in
 * `SettingsPage.tsx` is that widening those takes the reading measure from 78ch to 126ch — worse,
 * not better. They stay at the shell's prose measure, which is also why t55 writes no CSS at all.
 *
 * ## The four states (§4.5)
 *
 * There is no `GET`-by-id for any of the five registers; the API exposes list + create + patch
 * only. An edit page therefore resolves its record client-side from the already-cached list query,
 * exactly as `TemplateCreatePage` does for `?fork=`. That gives four states, and the fourth is a
 * HARD REQUIREMENT rather than a nicety:
 *
 *  1. `loading`  — the list query is in flight; the header is already painted.
 *  2. `error`    — the list query failed.
 *  3. `ready`    — the record resolved (or this is a create page); the form renders.
 *  4. `notFound` — a bad or stale id. It says so, by name, with a link back.
 *
 * Falling through state 4 to a blank create form would silently turn an edit into a create — a new
 * record where the operator meant to amend an existing one. That is
 * "reject, never silently transform" applied to routing.
 *
 * ## Permission
 *
 * Gated FIRST, and by the page's own verb (`privacy.manage` for four of them, `retention.manage`
 * for the retention policies). The list's affordances are gated, but a direct URL bypasses them,
 * so the page fails closed on its own: no authoring read, no draft, no late POST.
 */
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useT } from '../../../i18n';
import { usePrivacyPagesT } from '../../../i18n/privacyPagesFallback';
import {
  ButtonLink,
  Card,
  EmptyState,
  ErrorNote,
  Icon,
  PageHeader,
  SkeletonDeflist,
} from '../../../ui';
import { PermissionDeniedNote } from '../../session/permissions';

export type PrivacyRecordPageState = 'loading' | 'error' | 'ready' | 'notFound';

export function PrivacyRecordPageShell({
  title,
  listPath,
  state,
  error,
  notFoundMessage,
  allowed,
  children,
}: {
  /** A complete per-register sentence — never `New {register}` with a noun dropped in. */
  title: string;
  /** Where all three exits lead: the register's own list. */
  listPath: string;
  state: PrivacyRecordPageState;
  error?: unknown;
  /** The state-4 sentence, naming this register. */
  notFoundMessage: string;
  allowed: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const pt = usePrivacyPagesT();

  // ` · ` is the house crumb separator (ProviderCredentialPage, EditUserPage).
  const crumbs = (
    <>
      <Link to="/settings">{t('settings.page.title')}</Link> ·{' '}
      <Link to={listPath}>{pt('settings.privacy.page.crumb')}</Link>
    </>
  );
  const backLink = <Link to={listPath}>{pt('settings.privacy.page.backToList')}</Link>;

  if (!allowed) {
    return (
      <div className="stack form-page">
        <PageHeader crumbs={crumbs} title={title} />
        <PermissionDeniedNote />
        <p>{backLink}</p>
      </div>
    );
  }

  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={crumbs}
        title={title}
        actions={
          <ButtonLink to={listPath} variant="ghost" icon={<Icon.Close />}>
            {t('settings.privacy.action.cancel')}
          </ButtonLink>
        }
      />

      {state === 'error' ? <ErrorNote error={error} /> : null}

      {/* The cards carry NO title: the `<h1>` above already names the page, and repeating a
          58-character pt-PT register name immediately under itself is noise at every viewport. */}
      {state === 'loading' ? (
        <Card>
          <SkeletonDeflist />
        </Card>
      ) : null}

      {state === 'notFound' ? (
        <Card>
          <EmptyState title={notFoundMessage}>
            <p>{backLink}</p>
          </EmptyState>
        </Card>
      ) : null}

      {state === 'ready' ? <Card>{children}</Card> : null}
    </div>
  );
}
