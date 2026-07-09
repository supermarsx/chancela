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
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import type {
  ActView,
  EntityFamily,
  ImportDocumentBody,
  ImportedDocumentView,
} from '../../api/types';
import { ApiError, api } from '../../api/client';
import {
  useActDocumentBundle,
  useActDocumentPreview,
  useDownloadActDocument,
  useDownloadActDocumentOffice,
  useDownloadActDocumentWorkingCopy,
} from '../../api/hooks';
import { useT } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Button,
  Card,
  Digest,
  EmptyState,
  ErrorNote,
  Icon,
  InlineWarning,
  Skeleton,
  Truncate,
  useToast,
} from '../../ui';
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

const IMPORT_NOTICE =
  'Documentos importados ficam guardados como evidência ou referência não canónica. Não substituem o PDF/A preservado nem qualquer PDF assinado; a importação não declara validade legal, conformidade PDF/A ou validade de assinatura.';

function importedDocumentsKey(actId: string) {
  return ['documents', 'imported', { actId }] as const;
}

function importedDocumentKey(id: string) {
  return ['documents', 'imported', id] as const;
}

async function listImportedDocumentsForAct(actId: string): Promise<ImportedDocumentView[]> {
  try {
    return await api.listImportedDocuments({ act_id: actId });
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return [];
    throw e;
  }
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function readFileAsBase64(file: File): Promise<string> {
  if (typeof FileReader === 'undefined') {
    return file.arrayBuffer().then(arrayBufferToBase64);
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result !== 'string') {
        reject(new Error('Não foi possível ler o ficheiro importado.'));
        return;
      }
      const base64 = result.includes(',') ? result.slice(result.indexOf(',') + 1) : result;
      resolve(base64);
    };
    reader.onerror = () => reject(reader.error ?? new Error('Não foi possível ler o ficheiro.'));
    reader.readAsDataURL(file);
  });
}

function metadataText(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return 'Tamanho não indicado';
  if (value < 1024) return `${value} bytes`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let amount = value;
  let unit = 'bytes';
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  const decimals = amount >= 10 || Number.isInteger(amount) ? 0 : 1;
  return `${amount.toFixed(decimals)} ${unit}`;
}

function importedDisplayName(document: ImportedDocumentView): string {
  return metadataText(document.filename) ?? 'Documento importado sem nome';
}

function importedDownloadName(document: ImportedDocumentView): string {
  return metadataText(document.filename) ?? `documento-importado-${slug(document.id)}.bin`;
}

function mergeImportedDocument(
  current: ImportedDocumentView[] | undefined,
  document: ImportedDocumentView,
): ImportedDocumentView[] {
  const existing = current ?? [];
  return [document, ...existing.filter((item) => item.id !== document.id)];
}

function MetadataValue({ value, missing }: { value: unknown; missing: string }) {
  const text = metadataText(value);
  if (!text) return <span className="muted">{missing}</span>;
  return <Truncate text={text} mono />;
}

function ActDocumentMetadata({
  document,
}: {
  document: {
    id?: unknown;
    template_id?: unknown;
    profile?: unknown;
    created_at?: unknown;
  };
}) {
  const createdAt = metadataText(document.created_at);
  return (
    <div className="stack--tight" role="group" aria-label="Metadados e proveniência do documento">
      <p className="card__label">Metadados do PDF/A</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>Documento</dt>
          <dd>
            <MetadataValue value={document.id} missing="Não indicado no bundle" />
          </dd>
        </div>
        <div>
          <dt>Modelo</dt>
          <dd>
            <MetadataValue value={document.template_id} missing="Não indicado no bundle" />
          </dd>
        </div>
        <div>
          <dt>Perfil PDF/A canónico</dt>
          <dd>
            <MetadataValue value={document.profile} missing="Não indicado no bundle" />
          </dd>
        </div>
        <div>
          <dt>Gerado em</dt>
          <dd>
            {createdAt ? (
              <time className="mono" dateTime={createdAt}>
                {createdAt}
              </time>
            ) : (
              <span className="muted">Não indicado no bundle</span>
            )}
          </dd>
        </div>
        <div>
          <dt>Fonte legal</dt>
          <dd className="muted">
            Não fornecida pelo bundle do documento; nenhuma ligação foi criada.
          </dd>
        </div>
        <div>
          <dt>Limiar legal</dt>
          <dd className="muted">Não fornecido pelo bundle do documento.</dd>
        </div>
      </dl>
      <p className="field__hint">
        Estes são metadados de geração e preservação; não constituem verificação legal.
      </p>
    </div>
  );
}

function ImportedDocumentDetails({
  document,
  error,
  isLoading,
}: {
  document: ImportedDocumentView | null;
  error: unknown;
  isLoading: boolean;
}) {
  if (error) return <ErrorNote error={error} />;
  if (isLoading && !document) return <Skeleton height="7rem" />;
  if (!document) return null;

  const filename = metadataText(document.filename);
  const importedAt = metadataText(document.imported_at);
  const declaredType = metadataText(document.declared_content_type);
  const detectedType = metadataText(document.detected_content_type);
  const importedBy = metadataText(document.imported_by);
  const legalNotice = metadataText(document.legal_notice) ?? IMPORT_NOTICE;

  return (
    <div className="stack--tight" role="group" aria-label="Metadados do documento importado">
      <p className="card__label">Leitura do documento importado</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>Ficheiro</dt>
          <dd>
            {filename ? (
              <Truncate text={filename} />
            ) : (
              <span className="muted">Nome não fornecido pelo importador</span>
            )}
          </dd>
        </div>
        <div>
          <dt>Identificador</dt>
          <dd>
            <Truncate text={document.id} mono />
          </dd>
        </div>
        <div>
          <dt>Natureza</dt>
          <dd>
            <Badge tone={document.non_canonical ? 'warn' : 'neutral'}>
              {document.non_canonical ? 'Não canónico' : 'Importado'}
            </Badge>
          </dd>
        </div>
        <div>
          <dt>Tamanho</dt>
          <dd>{formatBytes(document.size_bytes)}</dd>
        </div>
        <div>
          <dt>Tipo declarado</dt>
          <dd>{declaredType ?? <span className="muted">Não declarado</span>}</dd>
        </div>
        <div>
          <dt>Tipo detetado</dt>
          <dd>{detectedType ?? <span className="muted">Não indicado</span>}</dd>
        </div>
        <div>
          <dt>Importado em</dt>
          <dd>
            {importedAt ? (
              <time className="mono" dateTime={importedAt}>
                {importedAt}
              </time>
            ) : (
              <span className="muted">Não indicado</span>
            )}
          </dd>
        </div>
        <div>
          <dt>Importado por</dt>
          <dd>{importedBy ?? <span className="muted">Não indicado</span>}</dd>
        </div>
        <div>
          <dt>SHA-256</dt>
          <dd>
            <Digest value={document.sha256} />
          </dd>
        </div>
        <div>
          <dt>Aviso</dt>
          <dd>{legalNotice}</dd>
        </div>
      </dl>
    </div>
  );
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
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [selectedImportId, setSelectedImportId] = useState<string | null>(null);
  const [importError, setImportError] = useState<unknown>(null);

  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const preview = useActDocumentPreview(act.id, open);
  const bundle = useActDocumentBundle(act.id, sealed);
  const download = useDownloadActDocument(act.id);
  const workingCopyDownload = useDownloadActDocumentWorkingCopy(act.id);
  const officeDownload = useDownloadActDocumentOffice(act.id);
  const importedDocuments = useQuery({
    queryKey: importedDocumentsKey(act.id),
    queryFn: () => listImportedDocumentsForAct(act.id),
  });
  const selectedImportedDocument = useQuery({
    queryKey: importedDocumentKey(selectedImportId ?? ''),
    queryFn: () => api.getImportedDocument(selectedImportId ?? ''),
    enabled: selectedImportId != null,
  });
  const importDocument = useMutation({
    mutationFn: (body: ImportDocumentBody) => api.importDocument(body),
    onSuccess: (document) => {
      queryClient.setQueryData<ImportedDocumentView[]>(importedDocumentsKey(act.id), (current) =>
        mergeImportedDocument(current, document),
      );
      setSelectedImportId(document.id);
      void queryClient.invalidateQueries({ queryKey: importedDocumentsKey(act.id) });
    },
  });
  const importedDownload = useMutation({
    mutationFn: (document: ImportedDocumentView) => api.fetchImportedDocumentBytes(document.id),
  });

  const importList = importedDocuments.data ?? [];
  const selectedImportFromList =
    importList.find((document) => document.id === selectedImportId) ?? null;
  const selectedImport = selectedImportedDocument.data ?? selectedImportFromList;

  function downloadBaseName() {
    const base = entityName ? `${slug(entityName)}-` : '';
    const n = act.ata_number != null ? String(act.ata_number) : act.id;
    return `${base}ata-${n}`;
  }

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  function onDownload() {
    const filename = `${downloadBaseName()}.pdf`;
    download.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(await saveBlobAs({ blob, filename, preferBrowserSavePicker: true }));
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  function onDownloadWorkingCopy() {
    const filename = `${downloadBaseName()}-working-copy.md`;
    workingCopyDownload.mutate(undefined, {
      onSuccess: async (download) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob: download.blob,
              filename,
              contentType: download.contentType,
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

  function onDownloadOffice() {
    const filename = `${downloadBaseName()}-office-working-copy.docx`;
    officeDownload.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(await saveBlobAs({ blob, filename, preferBrowserSavePicker: true }));
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  async function onImportFile(file: File) {
    setImportError(null);
    try {
      const content_base64 = await readFileAsBase64(file);
      const body: ImportDocumentBody = {
        content_base64,
        content_type: metadataText(file.type),
        filename: metadataText(file.name),
        act_id: act.id,
      };
      await importDocument.mutateAsync(body);
      toast.success('Documento importado como evidência não canónica.');
    } catch (e) {
      setImportError(e);
      toast.error(e);
    }
  }

  async function onDownloadImported(document: ImportedDocumentView) {
    try {
      const blob = await importedDownload.mutateAsync(document);
      showSaveResult(
        await saveBlobAs({
          blob,
          filename: importedDownloadName(document),
          preferBrowserSavePicker: true,
        }),
      );
    } catch (e) {
      toast.error(e);
    }
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
              <div className="rowline">
                <Button
                  type="button"
                  variant="primary"
                  icon={<Icon.FileText />}
                  disabled={download.isPending}
                  onClick={onDownload}
                >
                  {download.isPending ? t('documents.download.pending') : t('documents.download')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.FileText />}
                  disabled={workingCopyDownload.isPending}
                  onClick={onDownloadWorkingCopy}
                >
                  {workingCopyDownload.isPending
                    ? t('documents.download.pending')
                    : 'Descarregar Markdown'}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.FileText />}
                  disabled={officeDownload.isPending}
                  onClick={onDownloadOffice}
                >
                  {officeDownload.isPending ? t('documents.download.pending') : 'Descarregar DOCX'}
                </Button>
              </div>
              <p className="field__hint">
                Markdown e DOCX são cópias de trabalho não probatórias para revisão; o PDF/A
                preservado é o documento oficial.
              </p>
              <ActDocumentMetadata document={bundle.data.document} />
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

        <section className="stack--tight" aria-label="Documentos importados de referência">
          <div className="section-head">
            <div className="stack--tight">
              <p className="card__label">Documentos importados</p>
              <p className="field__hint">{IMPORT_NOTICE}</p>
              <p className="field__hint">
                O servidor valida o conteúdo antes de gravar; rejeições não são persistidas.
              </p>
            </div>
            <Badge tone="warn">Evidência não canónica</Badge>
          </div>

          <div className="row-wrap">
            <label className="btn btn--secondary btn--icon file-btn">
              <span className="btn__icon">
                <Icon.Tray />
              </span>
              {importDocument.isPending ? 'A importar...' : 'Importar evidência'}
              <input
                type="file"
                className="sr-only"
                disabled={importDocument.isPending}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void onImportFile(file);
                  e.target.value = '';
                }}
              />
            </label>
          </div>

          {importError ? <ErrorNote error={importError} /> : null}

          {importedDocuments.isLoading ? (
            <Skeleton height="4.5rem" />
          ) : importedDocuments.error ? (
            <ErrorNote error={importedDocuments.error} />
          ) : importList.length === 0 ? (
            <EmptyState title="Nenhum documento importado">
              <p>Esta ata ainda não tem evidência ou referência importada.</p>
            </EmptyState>
          ) : (
            <ul className="plain-list" aria-label="Documentos importados">
              {importList.map((document) => {
                const displayName = importedDisplayName(document);
                const detectedType = metadataText(document.detected_content_type);
                const importedAt = metadataText(document.imported_at);
                const selected = selectedImportId === document.id;
                return (
                  <li className="chainrow" key={document.id} aria-current={selected || undefined}>
                    <div className="section-head">
                      <div className="stack--tight">
                        <p className="row-wrap">
                          <Badge tone={document.non_canonical ? 'warn' : 'neutral'}>
                            {document.non_canonical ? 'Não canónico' : 'Importado'}
                          </Badge>
                          <Truncate text={displayName} />
                        </p>
                        <p className="chainrow__meta">
                          {formatBytes(document.size_bytes)}
                          {detectedType ? ` · ${detectedType}` : ''}
                          {importedAt ? (
                            <>
                              {' · '}
                              <time dateTime={importedAt}>{importedAt}</time>
                            </>
                          ) : null}
                        </p>
                      </div>
                      <div className="row-wrap">
                        <Button
                          type="button"
                          variant={selected ? 'primary' : 'secondary'}
                          icon={<Icon.FileText />}
                          onClick={() => setSelectedImportId(document.id)}
                        >
                          Ver metadados
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          icon={<Icon.Tray />}
                          disabled={importedDownload.isPending}
                          onClick={() => void onDownloadImported(document)}
                        >
                          Descarregar importado
                        </Button>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}

          {selectedImportId ? (
            <ImportedDocumentDetails
              document={selectedImport}
              error={selectedImportedDocument.error}
              isLoading={selectedImportedDocument.isLoading}
            />
          ) : null}
        </section>

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
