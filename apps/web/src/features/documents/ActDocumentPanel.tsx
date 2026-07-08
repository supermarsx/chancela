/**
 * ActDocumentPanel — the document surface mounted on the ata editor (plan t48-e6).
 *
 * Composes the three deliverables into one card on the act screen:
 *   • the template picker (which model applies — informational, pre-seal);
 *   • the live draft preview ("Pré-visualizar") that renders the server `DocumentModel`
 *     so the operator sees the document as they fill the record — including an HONEST
 *     "sem modelo disponível" state when the family has no template (the endpoint 422s);
 *   • the post-seal PDF/A download, gated on the DOC-03 bundle actually existing (so a
 *     sealed act whose family has no template shows an honest "não gerado" note, not a
 *     broken download), with the pdf digest surfaced as an integrity note.
 *
 * Reads render inline errors only; the one mutation here (the download) follows the toast
 * idiom (success + error) per CONVENTIONS §2/§3.
 */
import { useState } from 'react';
import type { ActView, EntityFamily } from '../../api/types';
import { ApiError } from '../../api/client';
import {
  useActDocumentBundle,
  useActDocumentPreview,
  useDownloadActDocument,
} from '../../api/hooks';
import { useT } from '../../i18n';
import { Button, Card, Digest, ErrorNote, Icon, InlineWarning, Skeleton, useToast } from '../../ui';
import { DocumentPreview } from './DocumentPreview';
import { TemplatePicker } from './TemplatePicker';
import './documents.css';

/** A 422/404 from the document endpoints is the "family has no template" signal. */
function isNoTemplate(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 422 || error.status === 404);
}

/** Slugify an entity/title fragment for a filesystem-friendly download name. */
function slug(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'documento'
  );
}

/** Trigger a browser download of a Blob with an explicit filename. */
function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/**
 * Print just the document: toggle `body.printing-doc` so the print-only rules in
 * documents.css isolate the `.doc-preview` subtree, then open the platform print dialog.
 * The class is removed on `afterprint` (and guarded for environments without `print`).
 */
function printDocument() {
  if (typeof window === 'undefined' || typeof window.print !== 'function') return;
  document.body.classList.add('printing-doc');
  const cleanup = () => {
    document.body.classList.remove('printing-doc');
    window.removeEventListener('afterprint', cleanup);
  };
  window.addEventListener('afterprint', cleanup);
  window.print();
}

export function ActDocumentPanel({
  act,
  entityName,
  family,
}: {
  act: ActView;
  entityName?: string;
  family?: EntityFamily;
}) {
  const t = useT();
  const toast = useToast();
  const [open, setOpen] = useState(false);

  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const preview = useActDocumentPreview(act.id, open);
  const bundle = useActDocumentBundle(act.id, sealed);
  const download = useDownloadActDocument(act.id);

  function onDownload() {
    const base = entityName ? `${slug(entityName)}-` : '';
    const n = act.ata_number != null ? String(act.ata_number) : act.id;
    const filename = `${base}ata-${n}.pdf`;
    download.mutate(undefined, {
      onSuccess: (blob) => {
        triggerDownload(blob, filename);
        toast.success(t('toast.document.downloaded'));
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <Card title={t('documents.title')}>
      <div className="stack--tight">
        {!sealed && family ? <TemplatePicker family={family} stage="Ata" /> : null}

        {/* Post-seal download, gated on the DOC-03 bundle actually existing. */}
        {sealed ? (
          bundle.isLoading ? (
            <Skeleton height="2.4rem" />
          ) : bundle.data ? (
            <div className="stack--tight">
              <Button
                type="button"
                variant="primary"
                icon={<Icon.FileText />}
                disabled={download.isPending}
                onClick={onDownload}
              >
                {download.isPending ? t('documents.download.pending') : t('documents.download')}
              </Button>
              <p className="doc-integrity">
                <span>{t('documents.digest.label')}</span>
                <Digest value={bundle.data.document.pdf_digest} />
              </p>
            </div>
          ) : isNoTemplate(bundle.error) || bundle.error ? (
            <InlineWarning tone="info" title={t('documents.download.noneTitle')}>
              {t('documents.download.noneBody')}
            </InlineWarning>
          ) : null
        ) : null}

        {/* Live preview toggle — works pre- and post-seal (renders the current record). */}
        <div className="rowline">
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.FileText />}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? t('documents.preview.hide') : t('documents.preview.show')}
          </Button>
          {open && preview.data ? (
            <Button type="button" variant="ghost" icon={<Icon.Printer />} onClick={printDocument}>
              {t('documents.print')}
            </Button>
          ) : null}
        </div>

        {open ? (
          <div className="stack--tight">
            <p className="field__hint">{t('documents.preview.hint')}</p>
            {preview.isLoading ? (
              <Skeleton height="12rem" />
            ) : isNoTemplate(preview.error) ? (
              <InlineWarning tone="info" title={t('documents.preview.noTemplate.title')}>
                {t('documents.preview.noTemplate.body')}
              </InlineWarning>
            ) : preview.error ? (
              <ErrorNote error={preview.error} />
            ) : preview.data ? (
              <DocumentPreview doc={preview.data} />
            ) : null}
          </div>
        ) : null}
      </div>
    </Card>
  );
}
