/**
 * FieldHelp — a subtle, borderless help affordance placed after a field label (t60 E1).
 *
 * Renders a quiet `Icon.Info` trigger that, on hover OR keyboard focus, reveals a plain-
 * language explanation of the setting in a gilt {@link Tooltip} (the FROZEN W1 primitive).
 * It reuses that tooltip wholesale — same motion kill-switches, same `aria-describedby`
 * wiring — so the accessible name of the trigger stays a generic "Ajuda" while the actual
 * explanation rides on the description (a screen reader announces "Ajuda, {explanation}").
 *
 * Why a dedicated primitive rather than a raw `IconButton`: `IconButton` renders the full
 * gilt `.btn--iconOnly` chrome (too heavy inline right after a label) and forces its
 * accessible name to equal the bubble text. `FieldHelp` keeps the trigger visually quiet
 * (a borderless currentColor glyph) and separates the accessible NAME ("Ajuda") from the
 * DESCRIPTION (the sentence). The `.field-help-wrap` span lets the owned CSS relax the
 * tooltip bubble from its short-label defaults (nowrap/uppercase) to a wrapping sentence
 * without touching the frozen `.tooltip*` block.
 */
import { useT } from '../i18n';
import { Tooltip, type TooltipPlacement } from './Tooltip';
import * as Icon from './icons';

interface FieldHelpProps {
  /** Plain-language explanation shown in the tooltip bubble (already `t()`-translated). */
  text: string;
  /** Accessible name of the trigger button. Default: `t('common.help')` ("Ajuda"). */
  label?: string;
  /** Where the bubble sits relative to the trigger. Default `top`. */
  placement?: TooltipPlacement;
}

export function FieldHelp({ text, label, placement = 'top' }: FieldHelpProps) {
  const t = useT();
  return (
    <span className="field-help-wrap">
      <Tooltip label={text} placement={placement}>
        <button type="button" className="field-help" aria-label={label ?? t('common.help')}>
          <Icon.Info />
        </button>
      </Tooltip>
    </span>
  );
}
