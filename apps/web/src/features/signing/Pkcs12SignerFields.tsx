/**
 * The co-located PKCS#12/PFX signer field group and its base64 helpers, factored out of
 * {@link ./SigningPanel} so the same certificate UX can back both the act signing flows (XAdES / ASiC
 * local tools, the act's own local PKCS#12 co-signature) and the termo de abertura / encerramento
 * per-slot PAdES co-signature ({@link ../books/TermoSlotPkcs12Signer}) without rebuilding it.
 *
 * The bytes + passphrase are TRANSIENT: the parent clears them on success and error and never
 * persists them (no localStorage, no query cache, no logging). This module owns no signing logic — it
 * only collects the file + passphrase (+ optional friendly name) and renders them; the parent submits.
 */
import { useT } from '../../i18n';
import { Field, Input } from '../../ui';

/** Encode raw bytes as base64, chunked so a large PFX does not overflow the argument list. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/** Decode a base64 payload to raw bytes for a download blob. */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Read a picked file's bytes and encode them as base64 for a transient signing request. */
export async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  return bytesToBase64(bytes);
}

/** Transient co-located software-certificate signer form state (PKCS#12 + passphrase). */
export type Pkcs12SignerState = {
  file: File | null;
  passphrase: string;
  friendlyName: string;
};

export function emptyPkcs12Signer(): Pkcs12SignerState {
  return { file: null, passphrase: '', friendlyName: '' };
}

/**
 * The shared co-located PKCS#12 signer fields. The bytes + passphrase are transient: the parent clears
 * them on success and error and never persists them.
 */
export function Pkcs12SignerFields({
  idPrefix,
  signer,
  disabled,
  onChange,
}: {
  idPrefix: string;
  signer: Pkcs12SignerState;
  disabled: boolean;
  onChange: (patch: Partial<Pkcs12SignerState>) => void;
}) {
  const t = useT();
  return (
    <>
      <p className="card__label">{t('signing.tool.signer.legend')}</p>
      <div className="form__grid">
        <Field
          label={t('signing.tool.signer.file.label')}
          htmlFor={`${idPrefix}-pkcs12-file`}
          hint={t('signing.tool.signer.file.hint')}
        >
          <Input
            id={`${idPrefix}-pkcs12-file`}
            type="file"
            accept=".p12,.pfx,application/x-pkcs12"
            autoComplete="off"
            disabled={disabled}
            onChange={(event) => onChange({ file: event.target.files?.[0] ?? null })}
          />
        </Field>
        <Field
          label={t('signing.tool.signer.passphrase.label')}
          htmlFor={`${idPrefix}-pkcs12-passphrase`}
          hint={t('signing.tool.signer.passphrase.hint')}
        >
          <Input
            id={`${idPrefix}-pkcs12-passphrase`}
            type="password"
            autoComplete="off"
            value={signer.passphrase}
            disabled={disabled}
            onChange={(event) => onChange({ passphrase: event.target.value })}
          />
        </Field>
        <Field
          label={t('signing.tool.signer.friendlyName.label')}
          htmlFor={`${idPrefix}-pkcs12-friendly-name`}
          hint={t('signing.tool.signer.friendlyName.hint')}
        >
          <Input
            id={`${idPrefix}-pkcs12-friendly-name`}
            type="text"
            autoComplete="off"
            value={signer.friendlyName}
            disabled={disabled}
            onChange={(event) => onChange({ friendlyName: event.target.value })}
          />
        </Field>
      </div>
    </>
  );
}
