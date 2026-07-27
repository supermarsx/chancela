/**
 * The two book-scoped ZIP export rows — moved verbatim out of `LedgerPage.tsx`'s
 * `BookExportControls` (t52) so the toggle-validation and download wiring lives exactly once,
 * shared by both places that offer them: `LedgerPage.tsx`'s Arquivo → Exportação tab (ad hoc, any
 * book via its own entity→kind→book picker) and `BookDetailPage.tsx`'s own Export tab (the book is
 * already known). Copying this logic into both call sites was the exact divergence risk the
 * extraction avoids.
 *
 * Renders only the two `<tr>`s — same DOM/roles/i18n keys as before the extraction — so a caller
 * drops them straight into its own `<Table>`.
 *
 * - **Pacote de preservação Chancela**: read-only, no ledger event, an export-time legal-hold
 *   toggle guards the request the same way the server does (a blank reason with the hold on is a
 *   422, so the button is held back rather than firing a request known to fail).
 * - **Pacote de portabilidade**: mutating and retained — it appends a chained `ledger.exported`
 *   event server-side, so it carries the `InlineWarning` that makes that side effect
 *   unmistakable, distinct from the un-warned read-only row beside it.
 */
import { useState } from 'react';
import { useDownloadBookArchivePackage, useExportBook } from '../../api/hooks';
import { useT } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { GateButton, scopeBook } from '../session/permissions';
import { Field, Icon, InlineWarning, Input, Toggle, useToast } from '../../ui';

/**
 * The two per-book ZIP profiles, spelled out because picking the wrong one is a real operator
 * error: the preservation package is a read-only archival/evidence deposit that the importer does
 * NOT accept, the bundle is the portability format that it does.
 */
const PRESERVATION_PACKAGE_PROFILE = 'chancela-internal-preservation-package/v1';
const BOOK_BUNDLE_PROFILE = 'chancela-book-bundle/v1';

function preservationPackageFilename(bookId: string): string {
  return `chancela-preservation-book-${bookId}.zip`;
}

function bookBundleFilename(bookId: string): string {
  return `book-${bookId}.zip`;
}

function showSaveResultVia(toast: ReturnType<typeof useToast>, result: SaveBlobResult) {
  if (result.kind === 'cancelled') {
    toast.info(saveBlobResultMessage(result));
    return;
  }
  toast.success(saveBlobResultMessage(result));
}

export function BookExportRows({ bookId }: { bookId: string }) {
  const t = useT();
  const toast = useToast();
  const [legalHold, setLegalHold] = useState(false);
  const [legalHoldReason, setLegalHoldReason] = useState('');
  const [reasonTouched, setReasonTouched] = useState(false);

  const preservation = useDownloadBookArchivePackage(bookId);
  const bundle = useExportBook();

  const trimmedReason = legalHoldReason.trim();
  // Mirrors the server rule: `legal_hold=true` without a non-blank reason is a 422, so the button
  // is held back rather than sending a request that is known to fail.
  const reasonMissing = legalHold && trimmedReason === '';

  function onDownloadPreservationPackage() {
    if (!bookId || reasonMissing) {
      setReasonTouched(true);
      return;
    }
    preservation.mutate(legalHold ? { legal_hold: true, legal_hold_reason: trimmedReason } : {}, {
      onSuccess: async (blob) => {
        try {
          showSaveResultVia(
            toast,
            await saveBlobAs({
              blob,
              filename: preservationPackageFilename(bookId),
              contentType: 'application/zip',
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

  function onDownloadBundle() {
    if (!bookId) return;
    bundle.mutate(bookId, {
      onSuccess: async ({ blob }) => {
        try {
          showSaveResultVia(
            toast,
            await saveBlobAs({
              blob,
              filename: bookBundleFilename(bookId),
              contentType: 'application/zip',
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
    <>
      <tr>
        <th scope="row">{t('ledger.export.preservation.title')}</th>
        <td>
          <p className="field__hint">
            {t('ledger.export.preservation.body')} <code>{PRESERVATION_PACKAGE_PROFILE}</code>
          </p>
          <p className="field__hint">{t('ledger.export.preservation.contents')}</p>
        </td>
        <td>
          <div className="stack--tight">
            <Toggle
              id="ledger-export-legal-hold"
              checked={legalHold}
              onChange={(next) => {
                setLegalHold(next);
                if (!next) setReasonTouched(false);
              }}
              label={t('ledger.export.legalHold.label')}
            />
            <p className="field__hint">{t('ledger.export.legalHold.help')}</p>
            {legalHold ? (
              <Field
                label={t('ledger.export.legalHold.reason.label')}
                htmlFor="ledger-export-legal-hold-reason"
                error={
                  reasonTouched && reasonMissing
                    ? t('ledger.export.legalHold.reason.required')
                    : undefined
                }
              >
                <Input
                  id="ledger-export-legal-hold-reason"
                  value={legalHoldReason}
                  placeholder={t('ledger.export.legalHold.reason.placeholder')}
                  onChange={(e) => setLegalHoldReason(e.target.value)}
                  onBlur={() => setReasonTouched(true)}
                />
              </Field>
            ) : null}
            <GateButton
              perm="book.export"
              scope={scopeBook(bookId)}
              type="button"
              variant="primary"
              icon={<Icon.Archive />}
              disabled={!bookId || preservation.isPending}
              onClick={onDownloadPreservationPackage}
            >
              {preservation.isPending
                ? t('books.preservationPackage.downloading')
                : t('books.preservationPackage.download')}
            </GateButton>
          </div>
        </td>
      </tr>

      <tr>
        <th scope="row">{t('ledger.export.bundle.title')}</th>
        <td>
          <p className="field__hint">
            {t('ledger.export.bundle.body')} <code>{BOOK_BUNDLE_PROFILE}</code>
          </p>
          <InlineWarning tone="info" title={t('ledger.export.bundle.retainedTitle')}>
            {t('ledger.export.bundle.retained')}
          </InlineWarning>
        </td>
        <td>
          <div className="stack--tight">
            <GateButton
              perm="book.export"
              scope={scopeBook(bookId)}
              type="button"
              variant="secondary"
              icon={<Icon.Tray />}
              disabled={!bookId || bundle.isPending}
              onClick={onDownloadBundle}
            >
              {bundle.isPending
                ? t('ledger.export.bundle.downloading')
                : t('ledger.export.bundle.download')}
            </GateButton>
          </div>
        </td>
      </tr>
    </>
  );
}
