/**
 * TermoSlotPkcs12Signer — the per-slot REAL PAdES co-signature form for a termo (abertura or
 * encerramento), shared by both editors (t45).
 *
 * A frozen termo is signed slot by slot. This form collects a locally supplied PKCS#12/PFX
 * certificate + passphrase for the active slot and produces a **real** PAdES signature over the
 * termo's PDF (`…/sign/pkcs12`) — the signature the fail-closed `open`/`close` gate requires. It
 * reuses the exact certificate UX of the act signing flows ({@link ../signing/Pkcs12SignerFields})
 * rather than rebuilding it. The bytes + passphrase are TRANSIENT: cleared on success and error,
 * never persisted.
 *
 * Local PKCS#12 signing is the desk-application flow: a remote/browser-hosted server refuses the
 * `sign/pkcs12` call with `409`, surfaced honestly as the co-location note (the same one the act
 * XAdES/ASiC tools show). CMD/CSC remain deferred, so a slot with no local certificate simply stays
 * unsigned and the `open`/`close` gate keeps failing closed — the honest state.
 */
import { useState } from 'react';
import { ApiError } from '../../api/client';
import type { SignTermoSlotPkcs12Body } from '../../api/types';
import {
  Pkcs12SignerFields,
  emptyPkcs12Signer,
  fileToBase64,
  type Pkcs12SignerState,
} from '../signing/Pkcs12SignerFields';
import { Button, ErrorNote, Icon, InlineWarning, useToast } from '../../ui';
import { useT } from '../../i18n';
import { useTermoT } from './termoStrings';

export function TermoSlotPkcs12Signer({
  slotId,
  sign,
  isPending,
  onSigned,
  onCancel,
}: {
  slotId: string;
  /** Produce the real PAdES signature for this slot (the pkcs12 mutation's `mutateAsync`). */
  sign: (body: SignTermoSlotPkcs12Body) => Promise<unknown>;
  isPending: boolean;
  onSigned: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  const tt = useTermoT();
  const toast = useToast();
  const [signer, setSigner] = useState<Pkcs12SignerState>(emptyPkcs12Signer);
  const [error, setError] = useState<unknown>(null);
  const [coLocationBlocked, setCoLocationBlocked] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!signer.file || signer.passphrase.length === 0 || isPending) return;
    setError(null);
    try {
      const pkcs12Base64 = await fileToBase64(signer.file);
      await sign({
        slot_id: slotId,
        pkcs12_base64: pkcs12Base64,
        passphrase: signer.passphrase,
        friendly_name: signer.friendlyName.trim() || undefined,
      });
      setSigner(emptyPkcs12Signer());
      toast.success(tt('books.termo.signing.signed'));
      onSigned();
    } catch (err) {
      // A 409 from the sign/pkcs12 call means the server is not co-located with the certificate (a
      // remote/browser host); surface the honest desk-app-only note rather than a raw error.
      setSigner(emptyPkcs12Signer());
      if (err instanceof ApiError && err.status === 409) setCoLocationBlocked(true);
      else setError(err);
      toast.error(err);
    }
  }

  if (coLocationBlocked) {
    return (
      <div className="stack--tight">
        <InlineWarning tone="info" title={t('signing.tool.coLocation.title')}>
          {t('signing.tool.coLocation.body')}
        </InlineWarning>
        <div className="rowline">
          <Button type="button" variant="ghost" icon={<Icon.Refresh />} onClick={onCancel}>
            {tt('books.termo.signing.pkcs12.cancel')}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <p className="field__hint">{tt('books.termo.signing.pkcs12.intro')}</p>
      <Pkcs12SignerFields
        idPrefix={`termo-slot-${slotId}`}
        signer={signer}
        disabled={isPending}
        onChange={(patch) => setSigner((current) => ({ ...current, ...patch }))}
      />
      {error ? <ErrorNote error={error} /> : null}
      <div className="rowline">
        <Button
          type="submit"
          variant="primary"
          icon={<Icon.PenNib />}
          disabled={!signer.file || signer.passphrase.length === 0 || isPending}
        >
          {isPending
            ? tt('books.termo.action.signing')
            : tt('books.termo.signing.pkcs12.submit')}
        </Button>
        <Button
          type="button"
          variant="ghost"
          icon={<Icon.Refresh />}
          disabled={isPending}
          onClick={onCancel}
        >
          {tt('books.termo.signing.pkcs12.cancel')}
        </Button>
      </div>
    </form>
  );
}
