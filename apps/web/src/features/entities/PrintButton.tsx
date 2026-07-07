/**
 * A discreet "Imprimir" action for the entity detail page. Gold-outline chrome with
 * an inline printer glyph; on click it opens the platform print dialog via
 * `window.print()`. The dedicated `@media print` stylesheet (theme.css) hides all the
 * app chrome and composes the filing-quality registry abstract rendered by
 * {@link EntityPrintDocument}, so the printed page is a clean document rather than a
 * screenshot of the UI.
 *
 * WebView2 (the desktop shell's engine) implements `window.print()` and opens the
 * Chromium print preview, so the same code path serves browser and desktop. The call
 * is guarded so a hypothetical environment without it degrades to a no-op instead of
 * throwing.
 */
import { Printer } from '../../ui/icons';
import { useT } from '../../i18n';

export function PrintButton() {
  const t = useT();
  function print() {
    if (typeof window !== 'undefined' && typeof window.print === 'function') {
      window.print();
    }
  }

  return (
    <button
      type="button"
      className="btn btn--print btn--icon"
      onClick={print}
      title={t('entities.print.title')}
    >
      <span className="btn__icon">
        <Printer />
      </span>
      {t('common.print')}
    </button>
  );
}
