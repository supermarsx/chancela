/**
 * Aparência → Idioma da interface — the signed-in user's own language preference (t69, on t71's
 * `language` field and `resolveUiLocale`).
 *
 * ## Why this is a separate card from the rest of Aparência
 *
 * The tab carries three settings with three different **scopes**, which is invisible unless the
 * layout says so:
 *
 * - theme / leather / intensity live in the **settings document** — instance-wide, every user;
 * - the colour overrides live in `localStorage` — this **browser** only;
 * - this one lives on the **user record** — this account, every browser they sign in from.
 *
 * Putting a per-user preference in the same card as instance-wide ones would invite an operator to
 * think they had changed the language for everybody, or for nobody. Its own card, with a lede that
 * states the scope, is the cheapest way to be honest about that.
 *
 * ## The three distinctions the copy has to carry
 *
 * 1. **`auto` here is not the theme's `system`.** They sit inches apart and read like synonyms.
 *    Theme follows the *operating system's* appearance setting; language negotiates against the
 *    *browser's* `Accept-Language` list. Identical wording would advertise a shared mechanism that
 *    does not exist, and the first person to "unify" them would wire the wrong one.
 * 2. **This is not the document locale.** `settings.documents.locale` is the language generated
 *    legal instruments are *written in*. A Portuguese company's atas stay pt-PT however its
 *    operator reads the interface — so this control names Documentos rather than letting someone
 *    conclude they are the same knob.
 * 3. **Detection is signed-in only** (t71's decision). `auto` is a *user's* standing instruction
 *    and there is no user on the sign-in screen, so that screen keeps using the instance language.
 *    Saying so beats letting someone discover it and read it as a bug.
 *
 * ## `auto` stays `auto`
 *
 * The select's value is the **stored preference**, never the resolved locale. Showing "English
 * (UK)" as selected because that is what `auto` currently negotiates to would make a standing
 * instruction indistinguishable from a pinned choice — and the next save would write the resolved
 * value back, silently freezing a user who asked to follow their environment. What `auto` resolves
 * to right now is shown as a *sentence*, not as the selection. Asserted in the tests, and
 * mutation-checked: injecting either half of that bug fails exactly one test each.
 */
import { useSession, useSettings, useUpdateUser } from '../../api/hooks';
import { DEFAULT_SETTINGS, LANGUAGE_AUTO, LOCALES } from '../../api/types';
import type { Locale, UserLanguage } from '../../api/types';
import { localeLabels } from '../../api/labels';
import { resolveUiLocale } from '../../theme/AppearanceEffects';
import { useT } from '../../i18n';
import { Card, ErrorNote, Field, InlineWarning, Select, useToast } from '../../ui';

export function LanguagePreferenceSection() {
  const t = useT();
  const toast = useToast();

  const session = useSession();
  const user = session.data?.user ?? null;

  const settings = useSettings();
  const documentLocale: Locale =
    settings.data?.documents.locale ?? DEFAULT_SETTINGS.documents.locale;

  // `useUpdateUser` needs an id up front. Signed out there is no user to update, and the control
  // is not rendered at all — the empty id is never reached by a request.
  const update = useUpdateUser(user?.id ?? '');

  if (!user) {
    return (
      <Card title={t('settings.language.cardTitle')}>
        <InlineWarning tone="info" title={t('settings.language.signedOut.title')}>
          <p>{t('settings.language.signedOut.body')}</p>
        </InlineWarning>
      </Card>
    );
  }

  const preference = user.language;
  // What `auto` means on THIS browser right now. Displayed as a sentence, never as the selection.
  const resolvedByAuto = resolveUiLocale(LANGUAGE_AUTO, documentLocale);

  function choose(next: UserLanguage) {
    if (next === preference) return;
    update.mutate(
      { language: next },
      {
        onSuccess: () => toast.success(t('settings.language.savedToast')),
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <Card title={t('settings.language.cardTitle')}>
      <p className="lede">{t('settings.language.lede')}</p>
      {update.error ? <ErrorNote error={update.error} /> : null}

      <div className="form settings-rows">
        <Field
          label={t('settings.language.field.label')}
          htmlFor="set-ui-language"
          hint={t('settings.language.field.hint')}
          help={t('settings.language.help')}
        >
          <Select
            id="set-ui-language"
            value={preference}
            disabled={update.isPending}
            onChange={(e) => choose(e.target.value as UserLanguage)}
            options={[
              { value: LANGUAGE_AUTO, label: t('settings.language.auto') },
              ...LOCALES.map((value) => ({ value, label: localeLabels[value] })),
            ]}
          />
        </Field>
      </div>

      {/* Only meaningful while `auto` is the stored choice: it states what the standing instruction
          currently produces WITHOUT the select pretending that is the stored value. */}
      {preference === LANGUAGE_AUTO ? (
        <p className="field__hint">
          {t('settings.language.autoResolves', { locale: localeLabels[resolvedByAuto] })}
        </p>
      ) : null}

      <p className="field__hint">{t('settings.language.notTheme')}</p>
      <p className="field__hint">{t('settings.language.notDocuments')}</p>
      <p className="field__hint">{t('settings.language.signInScreen')}</p>
    </Card>
  );
}
