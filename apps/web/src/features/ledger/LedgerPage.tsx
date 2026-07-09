/**
 * Arquivo — the append-only ledger with its verify status. The chain-valid badge
 * comes from `GET /v1/ledger/verify`; the table from `GET /v1/ledger/events`. A
 * chain + scope filter narrows the feed, and the archive action renders those same
 * filters through `GET /v1/ledger/archive/document` as a PDF/A.
 */
import { useMemo, useState } from 'react';
import {
  useDownloadLedgerArchiveDocument,
  useLedger,
  useLedgerIntegrity,
  useLedgerVerify,
} from '../../api/hooks';
import type { LedgerArchiveDocumentParams, LedgerQueryParams } from '../../api/types';
import { useT, type TFunction } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  Icon,
  Input,
  PageHeader,
  Select,
  SkeletonTable,
  useToast,
} from '../../ui';
import { LedgerTable } from './LedgerTable';

function filteredParams(scope: string, chain: string): LedgerQueryParams {
  const trimmedScope = scope.trim();
  return {
    ...(chain ? { chain } : {}),
    ...(trimmedScope ? { scope: trimmedScope } : {}),
  };
}

function shortId(id: string | undefined): string {
  return id ? id.slice(0, 8) : '';
}

function chainLabel(chain: string, t: TFunction): string {
  if (chain === 'application') return t('ledger.chain.application');
  const [kind, id] = chain.split(':', 2);
  if (kind === 'book') return t('ledger.chain.book', { id: shortId(id) });
  if (kind === 'company') return t('ledger.chain.company', { id: shortId(id) });
  return chain;
}

function slug(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'global'
  );
}

function archiveFilename(params: LedgerArchiveDocumentParams): string {
  const chain = params.chain ? slug(params.chain) : 'global';
  const scope = params.scope ? `-${slug(params.scope)}` : '';
  return `arquivo-${chain}${scope}.pdf`;
}

export function LedgerPage() {
  const t = useT();
  const toast = useToast();
  const [scope, setScope] = useState('');
  const [chain, setChain] = useState('');
  const verify = useLedgerVerify();
  const integrity = useLedgerIntegrity();
  const downloadArchive = useDownloadLedgerArchiveDocument();
  const ledgerParams = useMemo(() => filteredParams(scope, chain), [scope, chain]);
  const events = useLedger(ledgerParams);
  const chainOptions = useMemo(() => {
    const options = [{ value: '', label: t('ledger.chain.global') }];
    const seen = new Set(['global']);
    for (const status of integrity.data?.chains ?? []) {
      if (seen.has(status.chain)) continue;
      seen.add(status.chain);
      options.push({ value: status.chain, label: chainLabel(status.chain, t) });
    }
    if (chain && !seen.has(chain)) {
      options.push({ value: chain, label: chainLabel(chain, t) });
    }
    return options;
  }, [chain, integrity.data?.chains, t]);

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  function onDownloadArchive() {
    const params = filteredParams(scope, chain);
    downloadArchive.mutate(params, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename: archiveFilename(params),
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
    <div className="stack">
      <PageHeader title={t('ledger.page.title')} />

      <div className="row-wrap">
        <div className="chain-status">
          <span className="card__label">{t('ledger.integrity.label')}</span>{' '}
          {verify.isLoading ? (
            <Badge tone="neutral">{t('ledger.verify.checking')}</Badge>
          ) : verify.data?.valid ? (
            <Badge tone="ok">{t('ledger.chain.verified', { count: verify.data.length })}</Badge>
          ) : (
            <Badge tone="error">{t('ledger.chain.compromised')}</Badge>
          )}
        </div>
      </div>

      <Card
        title={t('ledger.events.title')}
        actions={
          <div className="ledger-controls">
            <Field label={t('ledger.chain.label')} htmlFor="ledger-chain">
              <Select
                id="ledger-chain"
                options={chainOptions}
                value={chain}
                onChange={(e) => setChain(e.target.value)}
              />
            </Field>
            <Field label={t('ledger.scope.label')} htmlFor="ledger-scope">
              <Input
                id="ledger-scope"
                placeholder={t('ledger.scope.placeholder')}
                value={scope}
                onChange={(e) => setScope(e.target.value)}
              />
            </Field>
            <Button
              type="button"
              variant="primary"
              icon={<Icon.FileText />}
              disabled={downloadArchive.isPending}
              onClick={onDownloadArchive}
            >
              {downloadArchive.isPending
                ? t('ledger.archive.downloading')
                : t('ledger.archive.download')}
            </Button>
          </div>
        }
      >
        {events.isLoading ? (
          <SkeletonTable cols={7} />
        ) : events.error ? (
          <ErrorNote error={events.error} />
        ) : (
          <LedgerTable events={events.data ?? []} showChains />
        )}
      </Card>
    </div>
  );
}
