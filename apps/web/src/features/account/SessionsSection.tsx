/**
 * Sessões ativas — the account holder's own sign-ins (t103's design, extracted here).
 *
 * ## Self-only by the shape of the endpoint, which is why it belongs to `/account`
 *
 * `GET /v1/sessions` returns the **caller's own** sessions, never a path parameter's. So this panel
 * is only ever meaningful on your own account: an administrator viewing another user's screen would
 * see *their own* sessions, not the target's, which is worse than useless. The admin screen
 * therefore mounts it only when `isSelf`, and the self-service `/account` area mounts it
 * unconditionally — there is no other case there.
 *
 * It takes no props for the same reason: there is no user to pass. The caller is the subject.
 *
 * ## Genuinely tabular — the one place on this surface a `Table` belongs
 *
 * A list of sign-ins with device, network, last-seen and expiry columns is exactly what the
 * `Table` primitive with a hidden `<caption>` is for. Nothing here is a form.
 *
 * ## The revoke footgun, handled
 *
 * Revoking the `current` session signs you out — that is what the sign-out control is already for,
 * so a per-row revoke is offered only on the OTHER sessions, and the current row is labelled
 * instead. "Terminar as outras sessões" revokes every session but the current one. A revoked
 * session is rejected on its next request (not merely delisted), so the other tabs are genuinely
 * signed out. Only `session_id` crosses the wire — never the token.
 *
 * The one control that DOES end the current session is deliberately elsewhere: suspending the
 * account ({@link AccountSuspendCard}) ends every session including this one, and it is step-up
 * gated because it cannot be undone without an administrator. "I do not recognise a session" and
 * "my account is compromised" are different judgements and get different affordances.
 */
import { useRevokeOtherSessions, useRevokeSession, useSessions } from '../../api/hooks';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  DateTime,
  EmptyState,
  ErrorNote,
  Icon,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { PermissionDeniedNote, isPermissionError } from '../session/permissions';

export function SessionsSection() {
  const t = useT();
  const toast = useToast();
  const sessions = useSessions();
  const revoke = useRevokeSession();
  const revokeOthers = useRevokeOtherSessions();

  const list = sessions.data?.sessions ?? [];
  const others = list.filter((s) => !s.current);
  const busy = revoke.isPending || revokeOthers.isPending;

  function doRevoke(sessionId: string) {
    revoke.mutate(sessionId, {
      onSuccess: () => toast.success(t('users.sessions.revoked')),
      onError: (e) => toast.error(e),
    });
  }

  function doRevokeOthers() {
    revokeOthers.mutate(undefined, {
      onSuccess: (res) => toast.success(t('users.sessions.revokedOthers', { count: res.revoked })),
      onError: (e) => toast.error(e),
    });
  }

  return (
    <Card
      title={t('users.sessions.title')}
      actions={
        others.length > 0 ? (
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.SignOut />}
            disabled={busy}
            onClick={doRevokeOthers}
          >
            {t('users.sessions.revokeOthers')}
          </Button>
        ) : undefined
      }
    >
      <div className="stack">
        <p className="field__hint">{t('users.sessions.intro')}</p>
        {sessions.isLoading ? (
          <SkeletonTable cols={5} />
        ) : sessions.error ? (
          isPermissionError(sessions.error) ? (
            <PermissionDeniedNote />
          ) : (
            <ErrorNote error={sessions.error} />
          )
        ) : list.length === 0 ? (
          <EmptyState title={t('users.sessions.empty')} />
        ) : (
          <>
            <Table
              caption={t('users.sessions.caption')}
              head={
                <tr>
                  <th>{t('users.sessions.col.device')}</th>
                  <th>{t('users.sessions.col.network')}</th>
                  <th>{t('users.sessions.col.lastSeen')}</th>
                  <th>{t('users.sessions.col.expires')}</th>
                  <th>{t('users.sessions.col.action')}</th>
                </tr>
              }
            >
              {list.map((s) => (
                <tr key={s.session_id}>
                  <td>
                    {s.device ?? <span className="muted">{t('users.sessions.unknownDevice')}</span>}
                    {s.current ? (
                      <>
                        {' '}
                        <Badge tone="accent">{t('users.sessions.current')}</Badge>
                      </>
                    ) : null}
                  </td>
                  {/* An address the server read out of a proxy forwarding header is not an address
                      the server observed: the header is client-controllable, and it is believed
                      only because the deployment declared a trusted proxy in front. This column is
                      what an operator uses to decide "do I recognise this — should I terminate
                      it?", so a told-to-us value is marked as such rather than presented as a
                      witnessed fact. The explicit space keeps a real character between the address
                      and the badge: the badge's own margin is invisible to `textContent` and to
                      find-in-page, so without it the two read fused to a screen reader. */}
                  <td>
                    {s.ip ? (
                      <>
                        <code className="mono">{s.ip}</code>
                        {s.ip_asserted ? (
                          <>
                            {' '}
                            <Badge tone="neutral" wrap>
                              {t('users.sessions.networkReported')}
                            </Badge>
                          </>
                        ) : null}
                      </>
                    ) : (
                      <span className="muted">{t('users.sessions.unknownNetwork')}</span>
                    )}
                  </td>
                  <td>
                    <DateTime value={s.last_seen_at} />
                  </td>
                  <td>
                    <DateTime value={s.expires_at} />
                  </td>
                  {/* One fact, one label: the accent badge in the device column already says this
                      row is the caller's own session, and that is where an operator identifies a
                      row (it is also the text a screen reader reads first in the row). Repeating it
                      here as muted prose put a second name for the same fact inside the column
                      reserved for controls. There is no control to offer — you leave your own
                      session by signing out, never by revoking it — and a permanently-disabled
                      button would be an affordance that can never fire, so the cell is empty. The
                      shared action-cell classes keep the row's geometry identical either way. */}
                  <td className="table-action-cell">
                    {s.current ? null : (
                      <span className="table-actions">
                        <Button
                          type="button"
                          variant="ghost"
                          icon={<Icon.Trash />}
                          disabled={busy}
                          onClick={() => doRevoke(s.session_id)}
                        >
                          {t('users.sessions.revoke')}
                        </Button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </Table>
            {/* The badge above is a two-word tag; on its own it does not tell an operator what to
                make of the row. The footnote appears only when some row actually carries an
                asserted address, so a deployment with no proxy in front never sees an explanation
                for a distinction its list does not draw. */}
            {list.some((s) => s.ip && s.ip_asserted) ? (
              <p className="field__hint">{t('users.sessions.networkReportedHint')}</p>
            ) : null}
          </>
        )}
      </div>
    </Card>
  );
}
