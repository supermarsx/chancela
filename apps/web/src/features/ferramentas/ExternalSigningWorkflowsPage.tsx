import { useMemo, useState, type FormEvent } from 'react';
import { useMutation, useQueries } from '@tanstack/react-query';
import type {
  ActView,
  BookView,
  Entity,
  ExternalSignerInvitePublicView,
  ExternalSignerInviteStatus,
  ExternalSignerInviteView,
} from '../../api/types';
import { api } from '../../api/client';
import { keys, useBooks, useEntities } from '../../api/hooks';
import { openExternal } from '../../desktop/openExternal';
import { useLocale, useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  ButtonLink,
  Card,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Loading,
  Table,
  useToast,
} from '../../ui';
import { scopeBook, useCan } from '../session/permissions';

interface ActContext {
  act: ActView;
  book: BookView;
  entity: Entity | null;
}

interface InviteRow {
  invite: ExternalSignerInviteView;
  act: ActView;
  book: BookView;
  entity: Entity | null;
}

const STATUS_ORDER: Record<ExternalSignerInviteStatus, number> = {
  pending: 0,
  accepted: 1,
  declined: 2,
  expired: 3,
  revoked: 4,
};

export function externalSignerInviteLink(token: string, origin?: string): string | null {
  const trimmed = token.trim();
  if (!trimmed) return null;
  const path = `/assinatura-externa?token=${encodeURIComponent(trimmed)}`;
  const base =
    origin ??
    (typeof window !== 'undefined' && window.location.origin ? window.location.origin : null);
  if (!base) return path;
  try {
    return new URL(path, base).toString();
  } catch {
    return path;
  }
}

function formatDateTime(value: string | undefined, locale: string): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function statusBadge(status: ExternalSignerInviteStatus, t: TFunction) {
  if (status === 'pending')
    return <Badge tone="accent">{t('signing.invites.status.pending')}</Badge>;
  if (status === 'accepted') return <Badge tone="ok">{t('signing.invites.status.accepted')}</Badge>;
  if (status === 'declined')
    return <Badge tone="warn">{t('signing.invites.status.declined')}</Badge>;
  if (status === 'expired') return <Badge tone="warn">{t('signing.invites.status.expired')}</Badge>;
  return <Badge tone="neutral">{t('signing.invites.status.revoked')}</Badge>;
}

function workflowLabel(workflow: string, t: TFunction): string {
  if (workflow === 'tracking_only') return t('signing.invites.workflow.trackingOnly');
  if (workflow === 'external_envelope') return t('signing.invites.workflow.externalEnvelope');
  return workflow;
}

function sortRows(a: InviteRow, b: InviteRow): number {
  const status = STATUS_ORDER[a.invite.status] - STATUS_ORDER[b.invite.status];
  if (status !== 0) return status;
  return a.invite.expires_at.localeCompare(b.invite.expires_at);
}

function countRows(rows: InviteRow[]) {
  return rows.reduce(
    (acc, row) => {
      acc.total += 1;
      if (row.invite.status === 'pending') acc.pending += 1;
      if (row.invite.status === 'accepted' || row.invite.status === 'declined') acc.answered += 1;
      if (
        row.invite.status === 'expired' ||
        row.invite.status === 'revoked' ||
        row.invite.status === 'declined'
      )
        acc.closed += 1;
      return acc;
    },
    { total: 0, pending: 0, answered: 0, closed: 0 },
  );
}

function rowContext(row: InviteRow, t: TFunction): string {
  const entity = row.entity?.name ?? t('externalSigning.unknownEntity');
  return `${entity} · ${row.book.kind}`;
}

function EnvelopeDetails({
  envelope,
  locale,
}: {
  envelope: ExternalSignerInvitePublicView;
  locale: string;
}) {
  const t = useT();
  return (
    <div className="external-signing-envelope stack--tight">
      <div className="section-head">
        <div>
          <p className="card__label">{t('externalSigning.envelope.title')}</p>
          <p className="chainrow__meta">{envelope.act.title}</p>
        </div>
        {statusBadge(envelope.status, t)}
      </div>
      <InlineWarning tone="info" title={t('externalSigning.notice.title')}>
        {envelope.notice || t('externalSigning.envelope.noticeFallback')}
      </InlineWarning>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('externalSigning.envelope.entity')}</dt>
          <dd>{envelope.act.entity_name}</dd>
        </div>
        <div>
          <dt>{t('externalSigning.envelope.recipient')}</dt>
          <dd>{envelope.recipient_name}</dd>
        </div>
        <div>
          <dt>{t('externalSigning.envelope.workflow')}</dt>
          <dd>{workflowLabel(envelope.workflow, t)}</dd>
        </div>
        <div>
          <dt>{t('externalSigning.envelope.expires')}</dt>
          <dd>{formatDateTime(envelope.expires_at, locale)}</dd>
        </div>
        {envelope.responded_at ? (
          <div>
            <dt>{t('externalSigning.envelope.responded')}</dt>
            <dd>{formatDateTime(envelope.responded_at, locale)}</dd>
          </div>
        ) : null}
        <div className="deflist__wide">
          <dt>{t('externalSigning.envelope.purpose')}</dt>
          <dd>{envelope.purpose}</dd>
        </div>
      </dl>
      {envelope.document ? (
        <div className="stack--tight">
          <p className="card__label">{t('externalSigning.envelope.document')}</p>
          <Digest value={envelope.document.pdf_digest} copyable={false} />
          <p className="field__hint">{envelope.document.artifact.notice}</p>
        </div>
      ) : (
        <InlineWarning tone="warn" title={t('externalSigning.envelope.noDocument.title')}>
          {t('externalSigning.envelope.noDocument.body')}
        </InlineWarning>
      )}
    </div>
  );
}

export function ExternalSigningWorkflowsPage() {
  const t = useT();
  const locale = useLocale();
  const toast = useToast();
  const can = useCan();
  const entities = useEntities();
  const books = useBooks();
  const [token, setToken] = useState('');
  const link = externalSignerInviteLink(token);
  const canUseToken = !!link;

  const entityById = useMemo(() => {
    const map = new Map<string, Entity>();
    for (const entity of entities.data ?? []) map.set(entity.id, entity);
    return map;
  }, [entities.data]);

  const manageableBooks = useMemo(
    () => (books.data ?? []).filter((book) => can('signing.perform', scopeBook(book.id))),
    [books.data, can],
  );

  const acts = useQueries({
    queries: manageableBooks.map((book) => ({
      queryKey: keys.bookActs(book.id),
      queryFn: () => api.listBookActs(book.id),
      retry: false,
    })),
  });

  const actContexts = useMemo<ActContext[]>(() => {
    return acts.flatMap((query, index) => {
      const book = manageableBooks[index];
      if (!book || !query.data) return [];
      const entity = entityById.get(book.entity_id) ?? null;
      return query.data.map((act) => ({ act, book, entity }));
    });
  }, [acts, entityById, manageableBooks]);

  const inviteQueries = useQueries({
    queries: actContexts.map((ctx) => ({
      queryKey: keys.externalSignerInvites(ctx.act.id),
      queryFn: () => api.listExternalSignerInvites(ctx.act.id),
      retry: false,
    })),
  });

  const rows = useMemo<InviteRow[]>(() => {
    return actContexts
      .flatMap((ctx, index) =>
        (inviteQueries[index]?.data ?? []).map((invite) => ({
          invite,
          act: ctx.act,
          book: ctx.book,
          entity: ctx.entity,
        })),
      )
      .sort(sortRows);
  }, [actContexts, inviteQueries]);

  const counts = countRows(rows);
  const isLoading =
    entities.isLoading ||
    books.isLoading ||
    acts.some((query) => query.isLoading) ||
    inviteQueries.some((query) => query.isLoading);
  const isFetching =
    entities.isFetching ||
    books.isFetching ||
    acts.some((query) => query.isFetching) ||
    inviteQueries.some((query) => query.isFetching);
  const firstError =
    entities.error ??
    books.error ??
    acts.find((query) => query.error)?.error ??
    inviteQueries.find((query) => query.error)?.error;

  const lookup = useMutation({
    mutationFn: (lookupToken: string) => api.lookupExternalSignerInvite(lookupToken),
  });

  async function copyLink() {
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      toast.success(t('common.copied'));
    } catch (error) {
      toast.error(error);
    }
  }

  function openLink() {
    if (!link) return;
    void openExternal(link);
  }

  function lookupEnvelope(e: FormEvent) {
    e.preventDefault();
    const trimmed = token.trim();
    if (!trimmed) return;
    lookup.mutate(trimmed, { onError: (error) => toast.error(error) });
  }

  function refreshAll() {
    void entities.refetch();
    void books.refetch();
    for (const query of acts) void query.refetch();
    for (const query of inviteQueries) void query.refetch();
  }

  return (
    <div className="stack">
      <Card
        title={t('externalSigning.title')}
        actions={
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Refresh />}
            disabled={isFetching}
            onClick={refreshAll}
          >
            {isFetching ? t('externalSigning.refreshing') : t('externalSigning.refresh')}
          </Button>
        }
      >
        <div className="stack--tight">
          <InlineWarning tone="info" title={t('externalSigning.notice.title')}>
            {t('externalSigning.notice.body')}
          </InlineWarning>
          <dl className="deflist external-signing-summary">
            <div>
              <dt>{t('externalSigning.summary.total')}</dt>
              <dd>{counts.total}</dd>
            </div>
            <div>
              <dt>{t('externalSigning.summary.pending')}</dt>
              <dd>{counts.pending}</dd>
            </div>
            <div>
              <dt>{t('externalSigning.summary.answered')}</dt>
              <dd>{counts.answered}</dd>
            </div>
            <div>
              <dt>{t('externalSigning.summary.closed')}</dt>
              <dd>{counts.closed}</dd>
            </div>
          </dl>

          {isLoading ? <Loading label={t('externalSigning.loading')} /> : null}
          {firstError ? <ErrorNote error={firstError} /> : null}
          {!isLoading && !firstError && manageableBooks.length === 0 ? (
            <InlineWarning tone="info" title={t('signing.invites.title')}>
              {t('signing.invites.permissionNote')}
            </InlineWarning>
          ) : null}
          {!isLoading && !firstError && manageableBooks.length > 0 && rows.length === 0 ? (
            <EmptyState title={t('externalSigning.empty.title')}>
              <p>{t('externalSigning.empty.body')}</p>
            </EmptyState>
          ) : null}

          {rows.length > 0 ? (
            <Table
              head={
                <tr>
                  <th>{t('externalSigning.table.act')}</th>
                  <th>{t('externalSigning.table.signer')}</th>
                  <th>{t('externalSigning.table.status')}</th>
                  <th>{t('externalSigning.table.workflow')}</th>
                  <th>{t('externalSigning.table.link')}</th>
                  <th>{t('externalSigning.table.expires')}</th>
                  <th>{t('externalSigning.table.actions')}</th>
                </tr>
              }
            >
              {rows.map((row) => (
                <tr key={row.invite.id}>
                  <td>
                    <strong>{row.act.title}</strong>
                    <br />
                    <span className="muted">{rowContext(row, t)}</span>
                  </td>
                  <td>
                    <strong>{row.invite.recipient_name}</strong>
                    <br />
                    <span className="muted">{row.invite.recipient_email}</span>
                  </td>
                  <td>{statusBadge(row.invite.status, t)}</td>
                  <td>
                    <span>{workflowLabel(row.invite.workflow, t)}</span>
                    <br />
                    <span className="muted">{t('externalSigning.workflow.limitation')}</span>
                  </td>
                  <td>
                    <code className="mono">{row.invite.token_hint}</code>
                    <br />
                    <span className="muted">{t('externalSigning.link.redacted')}</span>
                  </td>
                  <td>
                    <time dateTime={row.invite.expires_at}>
                      {formatDateTime(row.invite.expires_at, locale)}
                    </time>
                    {row.invite.responded_at ? (
                      <p className="chainrow__meta">
                        {t('externalSigning.respondedAt', {
                          date: formatDateTime(row.invite.responded_at, locale),
                        })}
                      </p>
                    ) : null}
                  </td>
                  <td>
                    <ButtonLink
                      to={`/atas/${encodeURIComponent(row.act.id)}`}
                      icon={<Icon.ExternalLink />}
                    >
                      {t('externalSigning.openAct')}
                    </ButtonLink>
                  </td>
                </tr>
              ))}
            </Table>
          ) : null}
        </div>
      </Card>

      <Card title={t('externalSigning.token.title')}>
        <form className="form" onSubmit={lookupEnvelope}>
          <p className="field__hint">{t('externalSigning.token.body')}</p>
          <Field
            label={t('externalSigning.token.label')}
            htmlFor="external-signing-token"
            hint={t('externalSigning.token.hint')}
          >
            <Input
              id="external-signing-token"
              value={token}
              autoComplete="off"
              placeholder={t('externalSigning.token.placeholder')}
              onChange={(e) => setToken(e.target.value)}
            />
          </Field>
          {link ? (
            <div className="api-key-secret__value">
              <code className="mono">{link}</code>
              <Button type="button" variant="secondary" icon={<Icon.Copy />} onClick={copyLink}>
                {t('externalSigning.token.copyLink')}
              </Button>
              <Button type="button" variant="ghost" icon={<Icon.ExternalLink />} onClick={openLink}>
                {t('externalSigning.token.openLink')}
              </Button>
            </div>
          ) : null}
          <div className="form__actions">
            <Button
              type="submit"
              variant="primary"
              icon={<Icon.Search />}
              disabled={!canUseToken || lookup.isPending}
            >
              {lookup.isPending
                ? t('externalSigning.token.lookupPending')
                : t('externalSigning.token.lookup')}
            </Button>
          </div>
          {lookup.error ? <ErrorNote error={lookup.error} /> : null}
          {lookup.data ? <EnvelopeDetails envelope={lookup.data} locale={locale} /> : null}
        </form>
      </Card>
    </div>
  );
}
