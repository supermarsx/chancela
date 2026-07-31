/**
 * Perfil — the facts about you that you own, and an honest statement of the ones you do not.
 *
 * ## Three cards, three different owners
 *
 * 1. **Identidade** — the audit username (immutable, and said so), display name and contact
 *    e-mail, written through `PATCH /v1/me/profile`. This is the endpoint that did not exist:
 *    `PATCH /v1/users/{id}` is `user.manage`\@Global, so before it an ordinary user could not
 *    correct their own name.
 * 2. **Idioma da interface** — the SAME `LanguagePreferenceSection` that Configurações → Aparência
 *    renders, imported rather than reimplemented. It was already self-only by construction (it
 *    reads the session user), and it now writes through the self endpoint, which also means it
 *    finally works for the ordinary users it was always written for.
 * 3. **Os meus dados** — the RGPD subject-access export, and the one honest refusal on this
 *    surface.
 *
 * ## The export, and why it is not self-service
 *
 * `GET /v1/privacy/users/{id}/export` is gated `privacy.manage`\@Global with **no self arm**. An
 * ordinary user therefore cannot export their own record, which is a real gap in the
 * subject-access story of a product that keeps a privacy register.
 *
 * That gap is stated rather than closed here. Widening the verb — or adding a self arm — is a
 * privacy-model ruling, not a screen-wiring detail: the export carries the subject's role
 * assignments and their ledger event references, and "every user may read that about themselves"
 * is a decision with consequences beyond this card. So a holder of `privacy.manage` gets a working
 * download of their own record (there is nothing new to authorize — they may already export
 * anyone's), and everybody else is told, in a sentence, that the export exists and who to ask.
 * Silently hiding the card would leave a subject-access right invisible; a dead button would be a
 * lie about what pressing it does.
 */
import { useEffect, useState } from 'react';
import { useExportUserDsr, useUpdateMyProfile } from '../../api/hooks';
import type { UserView } from '../../api/types';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { useT } from '../../i18n';
import { Button, Card, Field, Icon, InlineWarning, Input, useToast } from '../../ui';
import { useCan } from '../session/permissions';
import { LanguagePreferenceSection } from '../settings/LanguagePreferenceSection';

const EXPORT_CONTENT_TYPE = 'application/json';
const EXPORT_FILTERS = [{ name: 'JSON', extensions: ['json'] }];

function safeFilenamePart(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
}

function IdentityCard({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const update = useUpdateMyProfile();
  const [displayName, setDisplayName] = useState(user.display_name);
  const [email, setEmail] = useState(user.email ?? '');

  // Keep the fields in sync if the session refetches (another tab renamed the account, or a
  // mutation elsewhere invalidated `keys.session`).
  useEffect(() => {
    setDisplayName(user.display_name);
    setEmail(user.email ?? '');
  }, [user.display_name, user.email]);

  const trimmedDisplayName = displayName.trim();
  const trimmedEmail = email.trim();
  const dirty = trimmedDisplayName !== user.display_name || trimmedEmail !== (user.email ?? '');

  function save(e: React.FormEvent) {
    e.preventDefault();
    if (!dirty) return;
    // Only what actually changed, so a save never rewrites a field the operator did not touch —
    // `PATCH` semantics, and it keeps the `user.updated` ledger payload honest.
    update.mutate(
      {
        ...(trimmedDisplayName !== user.display_name ? { display_name: trimmedDisplayName } : {}),
        ...(trimmedEmail !== (user.email ?? '')
          ? { email: trimmedEmail === '' ? null : trimmedEmail }
          : {}),
      },
      {
        onSuccess: () => toast.success(t('account.identity.saved')),
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <Card title={t('account.identity.card')}>
      <p className="field__hint">{t('account.identity.lede')}</p>
      <form className="form settings-rows" onSubmit={save}>
        <Field
          label={t('users.table.username')}
          htmlFor="account-username"
          hint={t('account.identity.usernameHint')}
        >
          <Input id="account-username" value={user.username} readOnly />
        </Field>
        <Field label={t('users.edit.displayNameLabel')} htmlFor="account-display">
          <Input
            id="account-display"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder={t('users.field.displayName.placeholder')}
            autoComplete="off"
          />
        </Field>
        <Field label={t('registry.email.label')} htmlFor="account-email">
          <Input
            id="account-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder={t('registry.email.placeholder')}
            autoComplete="email"
          />
        </Field>
        <div className="form__actions">
          <Button type="submit" variant="primary" disabled={update.isPending || !dirty}>
            {update.isPending ? t('common.saving') : t('account.identity.save')}
          </Button>
        </div>
      </form>

      {/* What this screen deliberately cannot do. Stating it beats letting an operator hunt for a
          control that is not here — and it names the reason, so "ask an administrator" is not the
          only thing they learn. */}
      <InlineWarning tone="info" title={t('account.identity.adminOnly.title')}>
        <p>{t('account.identity.adminOnly.body')}</p>
      </InlineWarning>
    </Card>
  );
}

function MyDataCard({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const can = useCan();
  const dsrExport = useExportUserDsr(user.id);

  // `privacy.manage` at Global is exactly what `GET /v1/privacy/users/{id}/export` requires. Read
  // rather than gated-button: a holder gets a working control, and a non-holder gets a sentence
  // that tells them the export exists and how to obtain it — which a disabled button cannot.
  const mayExport = can('privacy.manage');

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') toast.info(saveBlobResultMessage(result));
    else toast.success(saveBlobResultMessage(result));
  }

  function download() {
    dsrExport.mutate(undefined, {
      onSuccess: async (data) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob: new Blob([JSON.stringify(data, null, 2)], { type: EXPORT_CONTENT_TYPE }),
              filename: `chancela-dsr-user-${safeFilenamePart(user.username)}.json`,
              contentType: EXPORT_CONTENT_TYPE,
              filters: EXPORT_FILTERS,
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <Card title={t('account.export.card')}>
      <div className="stack">
        <p className="field__hint">{t('account.export.body')}</p>
        {mayExport ? (
          <div className="form__actions">
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.FileText />}
              disabled={dsrExport.isPending}
              onClick={download}
            >
              {dsrExport.isPending ? t('account.export.pending') : t('account.export.download')}
            </Button>
          </div>
        ) : (
          <InlineWarning tone="info">{t('account.export.unavailable')}</InlineWarning>
        )}
      </div>
    </Card>
  );
}

export function AccountProfileSection({ user }: { user: UserView }) {
  return (
    <div className="stack">
      <IdentityCard user={user} />
      {/* The same card Configurações → Aparência renders — one module, one query, one mutation, so
          the two surfaces cannot drift. It is mounted in both places deliberately: the preference
          belongs to "how this app looks to me" AND to "my account", and sharing the component means
          the second address is a second view of one thing rather than a second implementation. */}
      <LanguagePreferenceSection />
      <MyDataCard user={user} />
    </div>
  );
}
