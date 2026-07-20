/**
 * The "código da certidão permanente" input. The 12-digit código de acesso is a
 * secret (possession alone grants full access to the registry record), so the field
 * is deliberately hardened against being captured or leaked (plan t11 §4 secrecy):
 *
 *  - rendered as `type="password"` by default so shoulder-surfing / screen-capture
 *    cannot read it; a reveal toggle (eye icon) switches to `type="text"` on demand;
 *  - `autoComplete="off"` + a non-standard `name` so browsers/password managers do not
 *    store or offer to fill it;
 *  - `spellCheck={false}` / `autoCapitalize`/`autoCorrect` off so mobile keyboards do
 *    not mangle or memorise it;
 *  - the value is fully controlled by the caller, which clears it after submit so it is
 *    never echoed back once used.
 *
 * The caller passes it transiently to the import mutation and never persists it.
 */
import { useState } from 'react';
import type { SVGProps } from 'react';
import { Button, Field, Input } from '../../ui';
import { useT } from '../../i18n';
import { registryFieldHelp } from './fieldHelp';

interface Props {
  id: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
  error?: React.ReactNode;
}

type IconProps = SVGProps<SVGSVGElement>;

/** Eye — shown when the value is masked; click to reveal. */
function EyeIcon(props: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

/** Eye-off — shown when the value is revealed; click to mask again. */
function EyeOffIcon(props: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      <path d="M9.9 5.1A10.5 10.5 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 3.9M6.1 6.1A17 17 0 0 0 2 12s3.5 7 10 7a10.5 10.5 0 0 0 4.2-.9" />
      <path d="M3 3l18 18" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
    </svg>
  );
}

export function AccessCodeField({ id, value, onChange, hint, error }: Props) {
  const t = useT();
  const [revealed, setRevealed] = useState(false);

  return (
    <Field
      label={t('registry.accessCode.label')}
      htmlFor={id}
      hint={hint ?? t('registry.accessCode.hint')}
      help={registryFieldHelp.accessCode}
      error={error}
    >
      <div
        className="access-code-field"
        style={{ display: 'flex', alignItems: 'stretch', gap: '0.4rem' }}
      >
        <Input
          id={id}
          name="certidao-access-code"
          type={revealed ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={t('registry.accessCode.placeholder')}
          inputMode="numeric"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          style={{ flex: '1 1 auto', minWidth: 0 }}
        />
        <Button
          type="button"
          variant="ghost"
          className="access-code-field__reveal"
          aria-label={revealed ? t('registry.accessCode.hide') : t('registry.accessCode.show')}
          aria-pressed={revealed}
          title={revealed ? t('registry.accessCode.hide') : t('registry.accessCode.show')}
          onClick={() => setRevealed((r) => !r)}
          style={{ flex: 'none', padding: '0 0.6rem' }}
        >
          {revealed ? <EyeOffIcon /> : <EyeIcon />}
        </Button>
      </div>
    </Field>
  );
}
