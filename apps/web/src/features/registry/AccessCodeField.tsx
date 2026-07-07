/**
 * The "código da certidão permanente" input. The 12-digit código de acesso is a
 * secret (possession alone grants full access to the registry record), so the field
 * is deliberately hardened against being captured or leaked (plan t11 §4 secrecy):
 *
 *  - `autoComplete="off"` + a non-standard `name` so browsers/password managers do not
 *    store or offer to fill it;
 *  - `spellCheck={false}` / `autoCapitalize`/`autoCorrect` off so mobile keyboards do
 *    not mangle or memorise it;
 *  - the value is fully controlled by the caller, which clears it after submit so it is
 *    never echoed back once used.
 *
 * The caller passes it transiently to the import mutation and never persists it.
 */
import { Field, Input } from '../../ui';
import { useT } from '../../i18n';

interface Props {
  id: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
  error?: React.ReactNode;
}

export function AccessCodeField({ id, value, onChange, hint, error }: Props) {
  const t = useT();
  return (
    <Field
      label={t('registry.accessCode.label')}
      htmlFor={id}
      hint={hint ?? t('registry.accessCode.hint')}
      error={error}
    >
      <Input
        id={id}
        name="certidao-access-code"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={t('registry.accessCode.placeholder')}
        inputMode="numeric"
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
      />
    </Field>
  );
}
