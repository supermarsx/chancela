/**
 * The footer of every privacy register form: cancel, then save (t55).
 *
 * One component so the five forms cannot drift apart, and so the modal-era and page-era spellings
 * of "cancel" live side by side in one place:
 *
 *  - **`onCancel`** — a `<button>`, the behaviour the (still-mounted) list panels rely on.
 *  - **`cancelTo`** — a `<ButtonLink>`, which is what a page wants: a real address the operator can
 *    middle-click, and a navigation the unsaved-changes guard can challenge. This is one of the
 *    three explicit exits that replace the modal's implicit Escape/backdrop dismissal — which
 *    discarded a nine-field DPIA on one stray click, with no confirmation at all.
 *
 * Exactly one of the two is given. The rendered markup is otherwise identical in both spellings,
 * so moving a form onto a page changes the element the operator clicks and nothing else.
 */
import { Button, ButtonLink, Icon } from '../../../../ui';
import { useT } from '../../../../i18n';

export function PrivacyFormActions({
  editing,
  saving,
  canSubmit,
  onCancel,
  cancelTo,
}: {
  editing: boolean;
  saving: boolean;
  canSubmit: boolean;
  onCancel?: () => void;
  cancelTo?: string;
}) {
  const t = useT();
  return (
    <div className="form__actions">
      {cancelTo !== undefined ? (
        <ButtonLink to={cancelTo} variant="ghost">
          {t('settings.privacy.action.cancel')}
        </ButtonLink>
      ) : (
        <Button type="button" variant="ghost" disabled={saving} onClick={onCancel}>
          {t('settings.privacy.action.cancel')}
        </Button>
      )}
      <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
        {saving
          ? t('settings.privacy.action.saving')
          : editing
            ? t('settings.privacy.action.save')
            : t('settings.privacy.action.create')}
      </Button>
    </div>
  );
}
