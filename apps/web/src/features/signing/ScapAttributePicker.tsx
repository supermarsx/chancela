/**
 * ScapAttributePicker — attach a professional attribute (AMA SCAP) at signing time (t67-e13).
 *
 * The flow mirrors the backend's honest, declared-first design:
 *
 *   1. enter the citizen reference → «Procurar atributos» lists the attribute providers SCAP knows
 *      about (`POST /v1/scap/providers`) and the professional attributes SCAP reports for the citizen
 *      (`POST /v1/scap/attributes`);
 *   2. pick one reported attribute;
 *   3. upload a co-located PKCS#12 software certificate and sign (`POST /v1/scap/sign`) — the backend
 *      produces a CAdES attribute-qualified signature over the act's PDF/A and reports the HONEST
 *      capacity status.
 *
 * **Honesty invariant (load-bearing).** The default transport is the offline `preprod` mock, which is
 * structurally incapable of a verified capacity: every attribute it reports is a *declared* claim, and
 * every signature it backs reports `verified: false`. This component therefore:
 *   - labels every reported attribute «Declarado — não verificado pela SCAP» before signing (the mock
 *     never verifies), and
 *   - after signing, keys the status badge STRICTLY off the response's `verification.verified` flag —
 *     a declared/mock result can never render as verified.
 * A verified badge is only ever reachable through the real `prod` transport on a live Granted
 * decision, which is deployment-gated (creds supplied out of band; prod-without-creds fails closed).
 *
 * The PKCS#12 bytes + passphrase are transient: held only in this component's form state while the
 * request is in flight, cleared on both success and error, and `reset()`-purged from the retained
 * mutation variables. They never reach localStorage/sessionStorage/URL/query-cache.
 */
import { useState } from 'react';
import type {
  ActView,
  ProfessionalAttributeView,
  ScapSignResponse,
  ScapVerification,
} from '../../api/types';
import { ApiError } from '../../api/client';
import { useScapAttributes, useScapProviders, useScapSign } from '../../api/hooks';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Digest,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  InlineWarning,
  Input,
  Skeleton,
  useToast,
} from '../../ui';

/** Decode a base64 payload to raw bytes for a download blob. */
function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Base64-encode a `File`'s bytes in bounded chunks (avoids a huge spread on large PFX files). */
async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/** A stable key for an attribute (provider + name uniquely identify a reported attribute). */
function attributeKey(attribute: ProfessionalAttributeView): string {
  return `${attribute.provider_id}::${attribute.name}`;
}

function attributeValidity(attribute: ProfessionalAttributeView, t: TFunction): string | null {
  if (!attribute.valid_from && !attribute.valid_until) return null;
  const open = t('signing.scap.attribute.validity.open');
  return t('signing.scap.attribute.validity', {
    from: attribute.valid_from ?? open,
    until: attribute.valid_until ?? open,
  });
}

/**
 * The honest capacity badge. `verified` is the SOLE input: it is `true` only on a real Granted SCAP
 * verification (never from the mock/declared path), so a declared attribute can never render verified.
 */
function CapacityStatus({ verified }: { verified: boolean }) {
  const t = useT();
  return verified ? (
    <Badge tone="ok">
      {t('signing.scap.status.verified')}
      <FieldHelp text={t('signing.scap.status.verified.help')} placement="bottom" />
    </Badge>
  ) : (
    <Badge tone="warn">
      {t('signing.scap.status.declared')}
      <FieldHelp text={t('signing.scap.status.declared.help')} placement="bottom" />
    </Badge>
  );
}

export function ScapAttributePicker({
  loadContentBase64,
}: {
  act: ActView;
  /** Loads the base64 of the act's sealed PDF/A — the content the attribute-qualified signature binds. */
  loadContentBase64: () => Promise<string>;
}) {
  const t = useT();
  const toast = useToast();

  const providers = useScapProviders();
  const attributes = useScapAttributes();
  const scapSign = useScapSign();

  const [citizenId, setCitizenId] = useState('');
  const [fullName, setFullName] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  // Transient signer material — cleared on success AND error; never persisted.
  const [pkcs12File, setPkcs12File] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [friendlyName, setFriendlyName] = useState('');
  const [signError, setSignError] = useState<unknown>(null);
  const [coLocationBlocked, setCoLocationBlocked] = useState(false);
  const [result, setResult] = useState<ScapSignResponse | null>(null);

  const attributeList = attributes.data?.attributes ?? [];
  const providerList = providers.data?.providers ?? [];
  const selectedAttribute = attributeList.find((a) => attributeKey(a) === selected) ?? null;
  const loadingLookup = providers.isPending || attributes.isPending;

  function onLookup(e: React.FormEvent) {
    e.preventDefault();
    const id = citizenId.trim();
    if (!id || loadingLookup) return;
    setSelected(null);
    setResult(null);
    setSignError(null);
    const name = fullName.trim() || undefined;
    // List providers (context) and fetch the citizen's reported attributes together. The mock
    // transport is the default; nothing here can report a verified capacity.
    providers.mutate({ environment: 'preprod' });
    attributes.mutate({ citizen_id: id, full_name: name, environment: 'preprod' });
  }

  function clearSigner() {
    setPkcs12File(null);
    setPassphrase('');
    setFriendlyName('');
  }

  async function onSign(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedAttribute || !pkcs12File || passphrase.length === 0 || scapSign.isPending) return;
    setSignError(null);
    try {
      const [contentBase64, pkcs12Base64] = await Promise.all([
        loadContentBase64(),
        fileToBase64(pkcs12File),
      ]);
      const response = await scapSign.mutateAsync({
        citizen_id: citizenId.trim(),
        full_name: fullName.trim() || undefined,
        provider_id: selectedAttribute.provider_id,
        attribute_name: selectedAttribute.name,
        content_base64: contentBase64,
        environment: 'preprod',
        signer: {
          kind: 'soft_pkcs12',
          pkcs12_base64: pkcs12Base64,
          passphrase,
          friendly_name: friendlyName.trim() || undefined,
        },
      });
      clearSigner(); // consumed — drop the secret immediately
      setResult(response);
      toast.success(t('signing.scap.result.title'));
    } catch (err) {
      clearSigner(); // consumed — drop the secret even on failure
      setSignError(err);
      // 409 = the API is not co-located with the private key (browser / remote server).
      if (err instanceof ApiError && err.status === 409) setCoLocationBlocked(true);
      toast.error(err);
    } finally {
      scapSign.reset();
    }
  }

  function onDownload() {
    if (!result) return;
    const bytes = base64ToBytes(result.signature_base64);
    saveBlobAs({
      blob: new Blob([bytes as BlobPart], { type: 'application/pkcs7-signature' }),
      filename: 'assinatura-scap.p7s',
      contentType: 'application/pkcs7-signature',
      preferBrowserSavePicker: true,
    })
      .then((saveResult: SaveBlobResult) => {
        if (saveResult.kind === 'cancelled') toast.info(saveBlobResultMessage(saveResult));
        else toast.success(saveBlobResultMessage(saveResult));
      })
      .catch((err) => toast.error(err));
  }

  return (
    <div className="stack--tight">
      <InlineWarning tone="info" title={t('signing.scap.title')}>
        {t('signing.scap.intro')}
      </InlineWarning>

      <form className="form" onSubmit={onLookup}>
        <div className="form__grid">
          <Field
            label={t('signing.scap.citizen.label')}
            htmlFor="scap-citizen"
            hint={t('signing.scap.citizen.hint')}
          >
            <Input
              id="scap-citizen"
              type="text"
              autoComplete="off"
              value={citizenId}
              onChange={(event) => setCitizenId(event.target.value)}
            />
          </Field>
          <Field label={t('signing.scap.fullName.label')} htmlFor="scap-full-name">
            <Input
              id="scap-full-name"
              type="text"
              autoComplete="off"
              value={fullName}
              onChange={(event) => setFullName(event.target.value)}
            />
          </Field>
        </div>
        <div className="rowline">
          <Button
            type="submit"
            variant="secondary"
            icon={<Icon.FileText />}
            disabled={!citizenId.trim() || loadingLookup}
          >
            {loadingLookup ? t('signing.scap.loadingAttributes') : t('signing.scap.loadAttributes')}
          </Button>
          <Badge tone="warn">{t('signing.scap.transport.mock')}</Badge>
        </div>
        {attributes.error ? <ErrorNote error={attributes.error} /> : null}
      </form>

      {loadingLookup ? <Skeleton height="4rem" /> : null}

      {attributes.data && attributeList.length === 0 ? (
        <InlineWarning tone="info" title={t('signing.scap.title')}>
          {t('signing.scap.attributes.empty')}
        </InlineWarning>
      ) : null}

      {attributeList.length > 0 ? (
        <div className="stack--tight">
          {providerList.length > 0 ? (
            <p className="field__hint">
              {t('signing.scap.attribute.provider', {
                provider: providerList.map((p) => p.name).join(', '),
              })}
            </p>
          ) : null}
          <p className="card__label">{t('signing.scap.attributes.legend')}</p>
          <ul className="plain-list stack--tight">
            {attributeList.map((attribute) => {
              const key = attributeKey(attribute);
              const isSelected = key === selected;
              const validity = attributeValidity(attribute, t);
              return (
                <li key={key}>
                  <div
                    className={`signing-provider${isSelected ? ' signing-provider--selected' : ''}`}
                  >
                    <div className="signing-provider__copy">
                      <div className="signing-provider__titleline">
                        <strong>{attribute.name}</strong>
                        {/* Declared before signing: the mock transport never verifies. */}
                        <CapacityStatus verified={false} />
                      </div>
                      <p>
                        {t('signing.scap.attribute.provider', {
                          provider: attribute.provider_name,
                        })}
                      </p>
                      {validity ? <p className="field__hint">{validity}</p> : null}
                      {attribute.sub_attributes.length > 0 ? (
                        <p className="field__hint">
                          {attribute.sub_attributes
                            .map((sub) => `${sub.name}: ${sub.value}`)
                            .join(' · ')}
                        </p>
                      ) : null}
                    </div>
                    <div className="signing-provider__action">
                      <Button
                        type="button"
                        variant={isSelected ? 'primary' : 'secondary'}
                        icon={isSelected ? <Icon.Check /> : undefined}
                        aria-pressed={isSelected}
                        onClick={() => {
                          setSelected(key);
                          setResult(null);
                        }}
                      >
                        {isSelected
                          ? t('signing.scap.attribute.selected')
                          : t('signing.scap.attribute.select')}
                      </Button>
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}

      {coLocationBlocked ? (
        <InlineWarning tone="info" title={t('signing.tool.coLocation.title')}>
          {t('signing.tool.coLocation.body')}
        </InlineWarning>
      ) : null}

      {selectedAttribute && !coLocationBlocked ? (
        <form className="form" onSubmit={onSign}>
          <p className="card__label">{t('signing.tool.signer.legend')}</p>
          <p className="field__hint">{t('signing.tool.content.note')}</p>
          <div className="form__grid">
            <Field
              label={t('signing.tool.signer.file.label')}
              htmlFor="scap-pkcs12-file"
              hint={t('signing.tool.signer.file.hint')}
            >
              <Input
                id="scap-pkcs12-file"
                type="file"
                accept=".p12,.pfx,application/x-pkcs12"
                autoComplete="off"
                onChange={(event) => setPkcs12File(event.target.files?.[0] ?? null)}
              />
            </Field>
            <Field
              label={t('signing.tool.signer.passphrase.label')}
              htmlFor="scap-pkcs12-passphrase"
              hint={t('signing.tool.signer.passphrase.hint')}
            >
              <Input
                id="scap-pkcs12-passphrase"
                type="password"
                autoComplete="off"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
              />
            </Field>
            <Field
              label={t('signing.tool.signer.friendlyName.label')}
              htmlFor="scap-pkcs12-friendly-name"
              hint={t('signing.tool.signer.friendlyName.hint')}
            >
              <Input
                id="scap-pkcs12-friendly-name"
                type="text"
                autoComplete="off"
                value={friendlyName}
                onChange={(event) => setFriendlyName(event.target.value)}
              />
            </Field>
          </div>
          {signError ? <ErrorNote error={signError} /> : null}
          <div className="rowline">
            <Button
              type="submit"
              variant="primary"
              icon={<Icon.PenNib />}
              disabled={!pkcs12File || passphrase.length === 0 || scapSign.isPending}
            >
              {scapSign.isPending ? t('signing.scap.signing') : t('signing.scap.sign')}
            </Button>
          </div>
        </form>
      ) : null}

      {result ? (
        <div className="stack--tight">
          <ScapSignResult result={result} />
          <div className="rowline">
            <Button type="button" variant="secondary" icon={<Icon.FileText />} onClick={onDownload}>
              {t('signing.scap.download')}
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function verificationTone(verification: ScapVerification): 'ok' | 'warn' {
  return verification.verified ? 'ok' : 'warn';
}

function ScapSignResult({ result }: { result: ScapSignResponse }) {
  const t = useT();
  return (
    <section className={`signing-status signing-status--${verificationTone(result.verification)}`}>
      <div className="signing-status__icon" aria-hidden="true">
        {result.verification.verified ? <Icon.Check /> : <Icon.Info />}
      </div>
      <div className="signing-status__body">
        <div className="signing-status__topline">
          <p className="signing-kicker">{t('signing.scap.result.status')}</p>
          <CapacityStatus verified={result.verification.verified} />
        </div>
        <p className="signing-status__title">{t('signing.scap.result.title')}</p>
        <dl className="deflist signing-deflist signing-deflist--compact">
          <div>
            <dt>{t('signing.scap.result.attribute')}</dt>
            <dd>
              {result.verification.attribute_name}
              {' · '}
              {result.verification.provider_id}
            </dd>
          </div>
          <div>
            <dt>{t('signing.tool.result.signer')}</dt>
            <dd className="mono">{result.signer_cert_subject ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('signing.tool.result.contentDigest')}</dt>
            <dd>
              <Digest value={result.content_sha256} />
            </dd>
          </div>
          <div className="signing-deflist__wide">
            <dt>{t('signing.tool.legalNotice.title')}</dt>
            <dd>{result.legal_notice}</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
