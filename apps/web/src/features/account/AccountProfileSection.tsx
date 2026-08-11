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
 * 3. **Os meus dados** — the RGPD subject-access export, self-service for everyone.
 *
 * ## The export: a purpose-built self-service payload
 *
 * `GET /v1/privacy/users/{id}/data-export` is the subject-access export (RGPD art. 15 / 20), gated
 * **self OR `privacy.manage`**. It is a deliberately different payload from the administrative
 * `…/export`: it carries only the subject's own personal data — profile and credential *metadata*
 * (which credentials they hold, with names and dates, never any secret material) — and omits the
 * role assignments and ledger event references that make the admin export structural, instance-level
 * information. Those omissions are what let it be self-service.
 *
 * So this card is the same for every account: a working download, with no permission check, calling
 * the endpoint with the session user's own id. The server's self arm admits it; passing anyone
 * else's id would be refused, but this surface never does. The earlier version of this card gated
 * the button on `privacy.manage` and told everyone else the export was unavailable — that gap is now
 * closed, so both the gate and the "unavailable" message are gone.
 */
import { useEffect, useState } from 'react';
import { useExportPersonalData, useUpdateMyProfile } from '../../api/hooks';
import type { UserView } from '../../api/types';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { useT } from '../../i18n';
import { Button, Card, Field, Icon, InlineWarning, Input, useToast } from '../../ui';
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
          help={t('account.identity.usernameHint')}
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
  // The subject's own personal-data export, self-service for every account. `user.id` is the
  // session user's own id (this surface only ever renders for the signed-in user), so the server's
  // self arm authorizes it with no administrative permission.
  const personalExport = useExportPersonalData(user.id);

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') toast.info(saveBlobResultMessage(result));
    else toast.success(saveBlobResultMessage(result));
  }

  function download() {
    personalExport.mutate(undefined, {
      onSuccess: async (data) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob: new Blob([JSON.stringify(data, null, 2)], { type: EXPORT_CONTENT_TYPE }),
              filename: `chancela-personal-data-${safeFilenamePart(user.username)}.json`,
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
        <InlineWarning tone="info">{t('account.export.scope')}</InlineWarning>
        <div className="form__actions">
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.FileText />}
            disabled={personalExport.isPending}
            onClick={download}
          >
            {personalExport.isPending ? t('account.export.pending') : t('account.export.download')}
          </Button>
        </div>
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
