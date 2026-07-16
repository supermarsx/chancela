import { useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ApiError, api } from '../../api/client';
import {
  useBooks,
  useCreateRepository,
  useCreateZkReadabilityPackage,
  useDeleteRepository,
  useDeleteTenantRepositoryPolicy,
  usePatchRepository,
  usePutTenantRepositoryPolicy,
  useRepositories,
  useTenantRepositoryPolicy,
  useUploadZkObject,
  useZkObjectVersions,
} from '../../api/hooks';
import type {
  Entity,
  KeyCustodyPolicy,
  ReadabilityPackageBody,
  RepositoryEncryptionMode,
  RepositoryPolicy,
  StoredRepositoryPolicy,
  ZkObjectVersionView,
} from '../../api/types';
import { saveBlobAs } from '../../desktop/saveFile';
import { useLocale, useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  Table,
  TextArea,
  Toggle,
} from '../../ui';
import {
  GateButton,
  scopeArchive,
  scopeBook,
  scopeRepository,
  scopeTenant,
  useCan,
} from '../session/permissions';
import { custodyPolicyFromForm, EMPTY_CUSTODY_FORM, type CustodyFormState } from './operatorModels';
import { arrayBufferToBase64, decryptZkObject, encryptZkObject, sha256Hex } from './zkCrypto';

interface RepositoryOperationsProps {
  tenantId: string;
  entities: Entity[];
}

function custodyFormFromPolicy(policy?: KeyCustodyPolicy): CustodyFormState {
  if (!policy) return { ...EMPTY_CUSTODY_FORM };
  return {
    byok: policy.bring_your_own_key,
    webauthn: policy.webauthn_prf_unsealing,
    splitRecovery: policy.split_key_recovery !== null,
    threshold: String(policy.split_key_recovery?.threshold ?? 2),
    shareCount: String(policy.split_key_recovery?.share_count ?? 3),
    custodianLabels: policy.split_key_recovery?.custodian_labels.join(', ') ?? '',
  };
}

function CustodyFields({
  idPrefix,
  value,
  onChange,
}: {
  idPrefix: string;
  value: CustodyFormState;
  onChange: (value: CustodyFormState) => void;
}) {
  const t = useT();
  return (
    <fieldset className="operations-fieldset">
      <legend>{t('operations.repositories.custody.title')}</legend>
      <Toggle
        id={`${idPrefix}-byok`}
        checked={value.byok}
        onChange={(byok) => onChange({ ...value, byok })}
        label={t('operations.repositories.custody.byok')}
      />
      <Toggle
        id={`${idPrefix}-webauthn`}
        checked={value.webauthn}
        onChange={(webauthn) => onChange({ ...value, webauthn })}
        label={t('operations.repositories.custody.webauthn')}
      />
      <Toggle
        id={`${idPrefix}-split`}
        checked={value.splitRecovery}
        onChange={(splitRecovery) => onChange({ ...value, splitRecovery })}
        label={t('operations.repositories.custody.split')}
      />
      {value.splitRecovery ? (
        <div className="operations-form-grid">
          <Field
            label={t('operations.repositories.custody.threshold')}
            htmlFor={`${idPrefix}-threshold`}
          >
            <Input
              id={`${idPrefix}-threshold`}
              type="number"
              min={2}
              step={1}
              value={value.threshold}
              onChange={(event) => onChange({ ...value, threshold: event.target.value })}
            />
          </Field>
          <Field
            label={t('operations.repositories.custody.shareCount')}
            htmlFor={`${idPrefix}-share-count`}
          >
            <Input
              id={`${idPrefix}-share-count`}
              type="number"
              min={2}
              step={1}
              value={value.shareCount}
              onChange={(event) => onChange({ ...value, shareCount: event.target.value })}
            />
          </Field>
          <Field
            label={t('operations.repositories.custody.labels')}
            htmlFor={`${idPrefix}-labels`}
            hint={t('operations.repositories.custody.labels.hint')}
          >
            <Input
              id={`${idPrefix}-labels`}
              value={value.custodianLabels}
              onChange={(event) => onChange({ ...value, custodianLabels: event.target.value })}
            />
          </Field>
        </div>
      ) : null}
      <InlineWarning tone="info">{t('operations.repositories.custody.boundary')}</InlineWarning>
    </fieldset>
  );
}

function TenantPolicyEditor({
  tenantId,
  policy,
}: {
  tenantId: string;
  policy?: { encryption_mode: RepositoryEncryptionMode; custody: KeyCustodyPolicy };
}) {
  const t = useT();
  const put = usePutTenantRepositoryPolicy();
  const remove = useDeleteTenantRepositoryPolicy();
  const [mode, setMode] = useState<RepositoryEncryptionMode>(policy?.encryption_mode ?? 'standard');
  const [custody, setCustody] = useState(() => custodyFormFromPolicy(policy?.custody));
  const [acknowledged, setAcknowledged] = useState(false);
  const [validationError, setValidationError] = useState<Error | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setValidationError(null);
    try {
      await put.mutateAsync({
        tenantId,
        body: {
          encryption_mode: mode,
          custody:
            mode === 'zero_knowledge'
              ? custodyPolicyFromForm(custody)
              : {
                  bring_your_own_key: false,
                  webauthn_prf_unsealing: false,
                  split_key_recovery: null,
                },
          gdpr_obligations_remain: true,
        },
      });
    } catch (error) {
      if (error instanceof ApiError) return;
      setValidationError(error instanceof Error ? error : new Error(String(error)));
    }
  }

  return (
    <form className="form operations-form" onSubmit={(event) => void submit(event)}>
      <Field label={t('operations.repositories.mode')} htmlFor="operations-tenant-policy-mode">
        <Select
          id="operations-tenant-policy-mode"
          value={mode}
          onChange={(event) => setMode(event.target.value as RepositoryEncryptionMode)}
          options={[
            { value: 'standard', label: t('operations.repositories.mode.standard') },
            { value: 'zero_knowledge', label: t('operations.repositories.mode.zk') },
          ]}
        />
      </Field>
      {mode === 'zero_knowledge' ? (
        <CustodyFields idPrefix="operations-tenant-custody" value={custody} onChange={setCustody} />
      ) : null}
      <label className="operations-checkbox operations-checkbox--ack">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        {t('operations.repositories.gdpr.ack')}
      </label>
      {validationError ? <ErrorNote error={validationError} /> : null}
      {put.error ? <ErrorNote error={put.error} /> : null}
      {remove.error ? <ErrorNote error={remove.error} /> : null}
      <div className="form__actions">
        <GateButton
          perm="settings.manage"
          scope={scopeTenant(tenantId)}
          type="submit"
          variant="primary"
          disabled={put.isPending || !acknowledged}
        >
          {t('operations.repositories.policy.save')}
        </GateButton>
        {policy ? (
          <GateButton
            perm="settings.manage"
            scope={scopeTenant(tenantId)}
            type="button"
            variant="ghost"
            disabled={remove.isPending}
            onClick={() => remove.mutate(tenantId)}
          >
            {t('operations.repositories.policy.remove')}
          </GateButton>
        ) : null}
      </div>
    </form>
  );
}

function TenantPolicy({ tenantId }: { tenantId: string }) {
  const t = useT();
  const policy = useTenantRepositoryPolicy(tenantId);
  const absent = policy.error instanceof ApiError && policy.error.status === 404;
  return (
    <Card title={t('operations.repositories.policy.title')}>
      <InlineWarning tone="warn" title={t('operations.repositories.policy.optIn.title')}>
        {t('operations.repositories.policy.optIn.body')}
      </InlineWarning>
      {policy.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
      {policy.error && !absent ? <ErrorNote error={policy.error} /> : null}
      {!policy.isLoading && (!policy.error || absent) ? (
        <TenantPolicyEditor
          key={`${tenantId}:${policy.data?.updated_at ?? 'new'}`}
          tenantId={tenantId}
          policy={policy.data}
        />
      ) : null}
    </Card>
  );
}

function CreateRepository({ tenantId }: { tenantId: string }) {
  const t = useT();
  const create = useCreateRepository();
  const [name, setName] = useState('');
  const [inherit, setInherit] = useState(false);
  const [mode, setMode] = useState<RepositoryEncryptionMode>('standard');
  const [custody, setCustody] = useState<CustodyFormState>({ ...EMPTY_CUSTODY_FORM });
  const [acknowledged, setAcknowledged] = useState(false);
  const [validationError, setValidationError] = useState<Error | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setValidationError(null);
    try {
      await create.mutateAsync({
        tenantId,
        body: inherit
          ? { name: name.trim(), inherit_tenant_policy: true }
          : {
              name: name.trim(),
              inherit_tenant_policy: false,
              encryption_mode: mode,
              custody:
                mode === 'zero_knowledge'
                  ? custodyPolicyFromForm(custody)
                  : {
                      bring_your_own_key: false,
                      webauthn_prf_unsealing: false,
                      split_key_recovery: null,
                    },
              gdpr_obligations_remain: true,
            },
      });
      setName('');
      setAcknowledged(false);
    } catch (error) {
      if (error instanceof ApiError) return;
      setValidationError(error instanceof Error ? error : new Error(String(error)));
    }
  }

  return (
    <Card title={t('operations.repositories.create.title')}>
      <form className="form operations-form" onSubmit={(event) => void submit(event)}>
        <Field label={t('operations.repositories.name')} htmlFor="operations-repository-name">
          <Input
            id="operations-repository-name"
            value={name}
            required
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Toggle
          checked={inherit}
          onChange={setInherit}
          label={t('operations.repositories.inherit')}
        />
        {!inherit ? (
          <>
            <Field label={t('operations.repositories.mode')} htmlFor="operations-repository-mode">
              <Select
                id="operations-repository-mode"
                value={mode}
                onChange={(event) => setMode(event.target.value as RepositoryEncryptionMode)}
                options={[
                  { value: 'standard', label: t('operations.repositories.mode.standard') },
                  { value: 'zero_knowledge', label: t('operations.repositories.mode.zk') },
                ]}
              />
            </Field>
            {mode === 'zero_knowledge' ? (
              <CustodyFields
                idPrefix="operations-new-repository"
                value={custody}
                onChange={setCustody}
              />
            ) : null}
          </>
        ) : null}
        <label className="operations-checkbox operations-checkbox--ack">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          {t('operations.repositories.gdpr.ack')}
        </label>
        {validationError ? <ErrorNote error={validationError} /> : null}
        {create.error ? <ErrorNote error={create.error} /> : null}
        <div className="form__actions">
          <GateButton
            perm="settings.manage"
            scope={scopeTenant(tenantId)}
            type="submit"
            variant="primary"
            icon={<Icon.Plus />}
            disabled={create.isPending || !name.trim() || !acknowledged}
          >
            {t('operations.repositories.create.action')}
          </GateButton>
        </div>
      </form>
    </Card>
  );
}

function ZkObjectDetail({
  tenantId,
  repository,
  object,
  entities,
}: {
  tenantId: string;
  repository: RepositoryPolicy;
  object: ZkObjectVersionView;
  entities: Entity[];
}) {
  const t = useT();
  const can = useCan();
  const books = useBooks();
  const readability = useCreateZkReadabilityPackage();
  const [clientKey, setClientKey] = useState('');
  const [bookId, setBookId] = useState('');
  const [mode, setMode] = useState<ReadabilityPackageBody['mode']>('client_decrypted_archive');
  const [portableJwe, setPortableJwe] = useState('');
  const [instructions, setInstructions] = useState('');
  const [password, setPassword] = useState('');
  const [working, setWorking] = useState(false);
  const [actionError, setActionError] = useState<Error | null>(null);
  const [actionMessage, setActionMessage] = useState('');
  const tenantEntityIds = new Set(
    entities.filter((entity) => entity.tenant_id === tenantId).map((entity) => entity.id),
  );
  const availableBooks = (books.data ?? []).filter((book) => tenantEntityIds.has(book.entity_id));
  const ad = object.manifest.associated_data;
  const archiveScope = scopeArchive(object.archive_id);

  async function fetchCiphertext(): Promise<ArrayBuffer> {
    return api.fetchZkObjectCiphertext(
      tenantId,
      repository.repository_id,
      ad.object_id,
      ad.version,
    );
  }

  async function downloadOpaque() {
    setActionError(null);
    setActionMessage('');
    setWorking(true);
    try {
      const ciphertext = await fetchCiphertext();
      if (
        ciphertext.byteLength !== object.manifest.ciphertext_len ||
        (await sha256Hex(ciphertext)) !== object.manifest.ciphertext_sha256
      ) {
        throw new Error(t('operations.repositories.objects.integrityFailed'));
      }
      await saveBlobAs({
        blob: new Blob([ciphertext], { type: 'application/octet-stream' }),
        filename: `${ad.object_id}-v${ad.version}.zk.bin`,
        contentType: 'application/octet-stream',
      });
      setActionMessage(t('operations.repositories.objects.downloaded'));
    } catch (error) {
      setActionError(error instanceof Error ? error : new Error(String(error)));
    } finally {
      setWorking(false);
    }
  }

  async function decryptAndSave() {
    setActionError(null);
    setActionMessage('');
    setWorking(true);
    try {
      const plaintext = await decryptZkObject(object.manifest, await fetchCiphertext(), clientKey);
      await saveBlobAs({
        blob: new Blob([plaintext], { type: 'application/zip' }),
        filename: `${ad.object_id}-v${ad.version}.zip`,
        contentType: 'application/zip',
        preferBrowserSavePicker: true,
      });
      setActionMessage(t('operations.repositories.objects.decrypted'));
      setClientKey('');
    } catch (error) {
      setActionError(error instanceof Error ? error : new Error(String(error)));
    } finally {
      setWorking(false);
    }
  }

  async function createReadability(event: FormEvent) {
    event.preventDefault();
    setActionError(null);
    setActionMessage('');
    setWorking(true);
    try {
      let body: ReadabilityPackageBody;
      if (mode === 'client_decrypted_archive') {
        const plaintext = await decryptZkObject(
          object.manifest,
          await fetchCiphertext(),
          clientKey,
        );
        body = {
          mode,
          book_id: bookId,
          archive_base64: await arrayBufferToBase64(plaintext),
          archive_sha256: await sha256Hex(plaintext),
          reauth: { password },
        };
      } else {
        body = {
          mode,
          book_id: bookId,
          portable_key_package_jwe: portableJwe.trim(),
          recipient_instructions: instructions.trim(),
          reauth: { password },
        };
      }
      const response = await readability.mutateAsync({
        tenantId,
        repositoryId: repository.repository_id,
        objectId: ad.object_id,
        version: ad.version,
        body,
      });
      await saveBlobAs({
        blob: response.blob,
        filename: `${ad.object_id}-v${ad.version}-readability.zip`,
        contentType: response.blob.type || 'application/zip',
        preferBrowserSavePicker: true,
      });
      setClientKey('');
      setPassword('');
      setPortableJwe('');
      setActionMessage(t('operations.repositories.readability.created'));
    } catch (error) {
      setActionError(error instanceof Error ? error : new Error(String(error)));
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="stack">
      <Card title={t('operations.repositories.objects.detail.title')}>
        <dl className="operations-detail-grid">
          <div>
            <dt>{t('operations.repositories.objects.object')}</dt>
            <dd>{ad.object_id}</dd>
          </div>
          <div>
            <dt>{t('operations.repositories.objects.version')}</dt>
            <dd>{ad.version}</dd>
          </div>
          <div>
            <dt>{t('operations.repositories.objects.bytes')}</dt>
            <dd>{object.manifest.ciphertext_len}</dd>
          </div>
          <div>
            <dt>{t('pdfValidator.field.sha256')}</dt>
            <dd className="operations-code-wrap">{object.manifest.ciphertext_sha256}</dd>
          </div>
        </dl>
        <InlineWarning tone="info">
          {t('operations.repositories.objects.clientBoundary')}
        </InlineWarning>
        <Field label={t('operations.repositories.objects.byok')} htmlFor="operations-object-byok">
          <Input
            id="operations-object-byok"
            type="password"
            autoComplete="off"
            value={clientKey}
            onChange={(event) => setClientKey(event.target.value)}
          />
        </Field>
        {actionError ? <ErrorNote error={actionError} /> : null}
        {actionMessage ? (
          <p className="operations-success" role="status">
            {actionMessage}
          </p>
        ) : null}
        <div className="form__actions">
          <GateButton
            perm="data.export"
            scope={archiveScope}
            type="button"
            disabled={working}
            onClick={() => void downloadOpaque()}
          >
            {t('operations.repositories.objects.downloadOpaque')}
          </GateButton>
          <GateButton
            perm="data.export"
            scope={archiveScope}
            type="button"
            variant="primary"
            disabled={working || !clientKey}
            onClick={() => void decryptAndSave()}
          >
            {t('operations.repositories.objects.decrypt')}
          </GateButton>
        </div>
      </Card>

      <Card title={t('operations.repositories.readability.title')}>
        <InlineWarning tone="warn">{t('operations.repositories.readability.caveat')}</InlineWarning>
        <form className="form operations-form" onSubmit={(event) => void createReadability(event)}>
          <div className="operations-form-grid">
            <Field
              label={t('operations.repositories.readability.mode')}
              htmlFor="operations-readability-mode"
            >
              <Select
                id="operations-readability-mode"
                value={mode}
                onChange={(event) => setMode(event.target.value as ReadabilityPackageBody['mode'])}
                options={[
                  {
                    value: 'client_decrypted_archive',
                    label: t('operations.repositories.readability.mode.decrypted'),
                  },
                  {
                    value: 'encrypted_archive_with_portable_key_package',
                    label: t('operations.repositories.readability.mode.portable'),
                  },
                ]}
              />
            </Field>
            <Field
              label={t('operations.repositories.readability.book')}
              htmlFor="operations-readability-book"
            >
              <select
                id="operations-readability-book"
                className="control control--select"
                value={bookId}
                required
                onChange={(event) => setBookId(event.target.value)}
              >
                <option value="">{t('operations.repositories.readability.book.choose')}</option>
                {availableBooks.map((book) => (
                  <option key={book.id} value={book.id}>
                    {book.id} · {book.kind}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          {mode === 'client_decrypted_archive' ? (
            <Field
              label={t('operations.repositories.objects.byok')}
              htmlFor="operations-readability-byok"
            >
              <Input
                id="operations-readability-byok"
                type="password"
                autoComplete="off"
                value={clientKey}
                required
                onChange={(event) => setClientKey(event.target.value)}
              />
            </Field>
          ) : (
            <>
              <Field
                label={t('operations.repositories.readability.portableJwe')}
                htmlFor="operations-readability-jwe"
                hint={t('operations.repositories.readability.portableJwe.hint')}
              >
                <TextArea
                  id="operations-readability-jwe"
                  value={portableJwe}
                  required
                  spellCheck={false}
                  onChange={(event) => setPortableJwe(event.target.value)}
                />
              </Field>
              <Field
                label={t('operations.repositories.readability.instructions')}
                htmlFor="operations-readability-instructions"
              >
                <TextArea
                  id="operations-readability-instructions"
                  value={instructions}
                  required
                  onChange={(event) => setInstructions(event.target.value)}
                />
              </Field>
            </>
          )}
          <Field
            label={t('operations.repositories.readability.reauth')}
            htmlFor="operations-readability-password"
          >
            <Input
              id="operations-readability-password"
              type="password"
              autoComplete="current-password"
              value={password}
              required
              onChange={(event) => setPassword(event.target.value)}
            />
          </Field>
          {books.error ? <ErrorNote error={books.error} /> : null}
          {readability.error ? <ErrorNote error={readability.error} /> : null}
          <div className="form__actions">
            <GateButton
              perm="book.export"
              scope={scopeBook(bookId)}
              type="submit"
              variant="primary"
              disabled={
                working ||
                !bookId ||
                !password ||
                !can('data.export', archiveScope) ||
                (mode === 'client_decrypted_archive'
                  ? !clientKey
                  : !portableJwe.trim() || !instructions.trim())
              }
            >
              {t('operations.repositories.readability.create')}
            </GateButton>
          </div>
        </form>
      </Card>
    </div>
  );
}

function ZkObjects({
  tenantId,
  repository,
  entities,
}: {
  tenantId: string;
  repository: RepositoryPolicy;
  entities: Entity[];
}) {
  const t = useT();
  const locale = useLocale();
  const [params, setParams] = useSearchParams();
  const objects = useZkObjectVersions(tenantId, repository.repository_id);
  const upload = useUploadZkObject();
  const [file, setFile] = useState<File | null>(null);
  const [objectId, setObjectId] = useState<string>(() => crypto.randomUUID());
  const [version, setVersion] = useState('1');
  const [clientKey, setClientKey] = useState('');
  const [recipient, setRecipient] = useState('primary-custodian');
  const [cryptoError, setCryptoError] = useState<Error | null>(null);
  const selectedKey = params.get('object') ?? '';
  const selected = objects.data?.find(
    (item) =>
      `${item.manifest.associated_data.object_id}:${item.manifest.associated_data.version}` ===
      selectedKey,
  );

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!file) return;
    setCryptoError(null);
    try {
      const encrypted = await encryptZkObject({
        plaintext: await file.arrayBuffer(),
        repositoryId: repository.repository_id,
        objectId: objectId.trim(),
        version: Number(version),
        byokBase64: clientKey,
        recipientId: recipient,
      });
      await upload.mutateAsync({
        tenantId,
        repositoryId: repository.repository_id,
        manifest: encrypted.manifest,
        ciphertext: encrypted.ciphertext,
      });
      setFile(null);
      setClientKey('');
      setObjectId(crypto.randomUUID());
      setVersion('1');
    } catch (error) {
      if (error instanceof ApiError) return;
      setCryptoError(error instanceof Error ? error : new Error(String(error)));
    }
  }

  return (
    <div className="stack">
      <Card title={t('operations.repositories.objects.upload.title')}>
        <InlineWarning
          tone="warn"
          title={t('operations.repositories.objects.upload.boundary.title')}
        >
          {t('operations.repositories.objects.upload.boundary.body')}
        </InlineWarning>
        <form className="form operations-form" onSubmit={(event) => void submit(event)}>
          <Field label={t('operations.repositories.objects.file')} htmlFor="operations-zk-file">
            <Input
              id="operations-zk-file"
              type="file"
              accept=".zip,application/zip,application/octet-stream"
              required
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
          </Field>
          <div className="operations-form-grid">
            <Field
              label={t('operations.repositories.objects.object')}
              htmlFor="operations-zk-object-id"
            >
              <Input
                id="operations-zk-object-id"
                value={objectId}
                required
                onChange={(event) => setObjectId(event.target.value)}
              />
            </Field>
            <Field
              label={t('operations.repositories.objects.version')}
              htmlFor="operations-zk-version"
            >
              <Input
                id="operations-zk-version"
                type="number"
                min={1}
                step={1}
                value={version}
                required
                onChange={(event) => setVersion(event.target.value)}
              />
            </Field>
          </div>
          <div className="operations-form-grid">
            <Field label={t('operations.repositories.objects.byok')} htmlFor="operations-zk-byok">
              <Input
                id="operations-zk-byok"
                type="password"
                autoComplete="off"
                value={clientKey}
                required
                onChange={(event) => setClientKey(event.target.value)}
              />
            </Field>
            <Field
              label={t('operations.repositories.objects.recipient')}
              htmlFor="operations-zk-recipient"
            >
              <Input
                id="operations-zk-recipient"
                value={recipient}
                required
                onChange={(event) => setRecipient(event.target.value)}
              />
            </Field>
          </div>
          {cryptoError ? <ErrorNote error={cryptoError} /> : null}
          {upload.error ? <ErrorNote error={upload.error} /> : null}
          <div className="form__actions">
            <GateButton
              perm="data.backup"
              scope={scopeRepository(repository.repository_id)}
              type="submit"
              variant="primary"
              disabled={
                upload.isPending || !file || !clientKey || !objectId.trim() || !recipient.trim()
              }
            >
              {t('operations.repositories.objects.upload.action')}
            </GateButton>
          </div>
        </form>
      </Card>

      <Card title={t('operations.repositories.objects.title')}>
        {objects.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
        {objects.error ? <ErrorNote error={objects.error} /> : null}
        {objects.data?.length === 0 ? (
          <EmptyState title={t('operations.repositories.objects.empty')} />
        ) : null}
        {objects.data && objects.data.length > 0 ? (
          <Table
            head={
              <tr>
                <th>{t('operations.repositories.objects.object')}</th>
                <th>{t('operations.repositories.objects.version')}</th>
                <th>{t('operations.repositories.objects.bytes')}</th>
                <th>{t('operations.repositories.objects.committed')}</th>
                <th>{t('operations.common.actions')}</th>
              </tr>
            }
          >
            {objects.data.map((item) => {
              const itemAd = item.manifest.associated_data;
              const key = `${itemAd.object_id}:${itemAd.version}`;
              return (
                <tr key={key}>
                  <td>{itemAd.object_id}</td>
                  <td>{itemAd.version}</td>
                  <td>{item.manifest.ciphertext_len}</td>
                  <td>{new Date(item.committed_at).toLocaleString(locale)}</td>
                  <td>
                    <Button
                      type="button"
                      variant={selectedKey === key ? 'primary' : 'secondary'}
                      onClick={() =>
                        setParams((current) => {
                          const next = new URLSearchParams(current);
                          next.set('object', key);
                          return next;
                        })
                      }
                    >
                      {t('operations.common.open')}
                    </Button>
                  </td>
                </tr>
              );
            })}
          </Table>
        ) : null}
      </Card>
      {selected ? (
        <ZkObjectDetail
          key={selectedKey}
          tenantId={tenantId}
          repository={repository}
          object={selected}
          entities={entities}
        />
      ) : null}
    </div>
  );
}

function RepositoryDetail({
  tenantId,
  stored,
  entities,
}: {
  tenantId: string;
  stored: StoredRepositoryPolicy;
  entities: Entity[];
}) {
  const t = useT();
  const patch = usePatchRepository();
  const remove = useDeleteRepository();
  const policy = stored.policy;
  const [name, setName] = useState(policy.name);
  const [inherit, setInherit] = useState(stored.policy_source === 'tenant');
  const [mode, setMode] = useState<RepositoryEncryptionMode>(policy.encryption_mode);
  const [custody, setCustody] = useState(() => custodyFormFromPolicy(policy.custody));
  const [acknowledged, setAcknowledged] = useState(false);
  const [validationError, setValidationError] = useState<Error | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setValidationError(null);
    try {
      await patch.mutateAsync({
        tenantId,
        repositoryId: policy.repository_id,
        body: inherit
          ? { name: name.trim(), inherit_tenant_policy: true }
          : {
              name: name.trim(),
              inherit_tenant_policy: false,
              encryption_mode: mode,
              custody:
                mode === 'zero_knowledge'
                  ? custodyPolicyFromForm(custody)
                  : {
                      bring_your_own_key: false,
                      webauthn_prf_unsealing: false,
                      split_key_recovery: null,
                    },
              gdpr_obligations_remain: true,
            },
      });
      setAcknowledged(false);
    } catch (error) {
      if (error instanceof ApiError) return;
      setValidationError(error instanceof Error ? error : new Error(String(error)));
    }
  }

  return (
    <div className="stack">
      <Card title={t('operations.repositories.detail.title')}>
        <form className="form operations-form" onSubmit={(event) => void submit(event)}>
          <Field
            label={t('operations.repositories.name')}
            htmlFor="operations-repository-edit-name"
          >
            <Input
              id="operations-repository-edit-name"
              value={name}
              required
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <Toggle
            checked={inherit}
            onChange={setInherit}
            label={t('operations.repositories.inherit')}
          />
          {!inherit ? (
            <>
              <Field
                label={t('operations.repositories.mode')}
                htmlFor="operations-repository-edit-mode"
              >
                <Select
                  id="operations-repository-edit-mode"
                  value={mode}
                  onChange={(event) => setMode(event.target.value as RepositoryEncryptionMode)}
                  options={[
                    { value: 'standard', label: t('operations.repositories.mode.standard') },
                    { value: 'zero_knowledge', label: t('operations.repositories.mode.zk') },
                  ]}
                />
              </Field>
              {mode === 'zero_knowledge' ? (
                <CustodyFields
                  idPrefix="operations-edit-repository"
                  value={custody}
                  onChange={setCustody}
                />
              ) : null}
            </>
          ) : null}
          <label className="operations-checkbox operations-checkbox--ack">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />
            {t('operations.repositories.gdpr.ack')}
          </label>
          {validationError ? <ErrorNote error={validationError} /> : null}
          {patch.error ? <ErrorNote error={patch.error} /> : null}
          {remove.error ? <ErrorNote error={remove.error} /> : null}
          <div className="form__actions">
            <GateButton
              perm="settings.manage"
              scope={scopeRepository(policy.repository_id)}
              type="submit"
              variant="primary"
              disabled={patch.isPending || !name.trim() || !acknowledged}
            >
              {t('common.save')}
            </GateButton>
            <GateButton
              perm="settings.manage"
              scope={scopeRepository(policy.repository_id)}
              type="button"
              variant="ghost"
              icon={<Icon.Trash />}
              disabled={remove.isPending}
              onClick={() => remove.mutate({ tenantId, repositoryId: policy.repository_id })}
            >
              {t('operations.repositories.remove')}
            </GateButton>
          </div>
        </form>
      </Card>
      {policy.encryption_mode === 'zero_knowledge' ? (
        <ZkObjects tenantId={tenantId} repository={policy} entities={entities} />
      ) : (
        <InlineWarning tone="info" title={t('operations.repositories.objects.standard.title')}>
          {t('operations.repositories.objects.standard.body')}
        </InlineWarning>
      )}
    </div>
  );
}

export function RepositoryOperations({ tenantId, entities }: RepositoryOperationsProps) {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const repositories = useRepositories(tenantId);
  const requested = params.get('repository') ?? '';
  const selected = repositories.data?.find((item) => item.policy.repository_id === requested);

  return (
    <div className="stack">
      <TenantPolicy tenantId={tenantId} />
      <CreateRepository tenantId={tenantId} />
      <Card title={t('operations.repositories.list.title')}>
        {repositories.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
        {repositories.error ? <ErrorNote error={repositories.error} /> : null}
        {repositories.data?.length === 0 ? (
          <EmptyState title={t('operations.repositories.empty')} />
        ) : null}
        {repositories.data && repositories.data.length > 0 ? (
          <Table
            head={
              <tr>
                <th>{t('operations.repositories.name')}</th>
                <th>{t('operations.repositories.mode')}</th>
                <th>{t('operations.repositories.source')}</th>
                <th>{t('operations.common.actions')}</th>
              </tr>
            }
          >
            {repositories.data.map((item) => (
              <tr key={item.policy.repository_id}>
                <td>{item.policy.name}</td>
                <td>
                  <Badge
                    tone={item.policy.encryption_mode === 'zero_knowledge' ? 'accent' : 'neutral'}
                  >
                    {item.policy.encryption_mode === 'zero_knowledge'
                      ? t('operations.repositories.mode.zk')
                      : t('operations.repositories.mode.standard')}
                  </Badge>
                </td>
                <td>{t(`operations.repositories.source.${item.policy_source}`)}</td>
                <td>
                  <Button
                    type="button"
                    variant={
                      selected?.policy.repository_id === item.policy.repository_id
                        ? 'primary'
                        : 'secondary'
                    }
                    onClick={() =>
                      setParams((current) => {
                        const next = new URLSearchParams(current);
                        next.set('repository', item.policy.repository_id);
                        next.delete('object');
                        return next;
                      })
                    }
                  >
                    {t('operations.common.open')}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        ) : null}
      </Card>
      {selected ? (
        <RepositoryDetail
          key={`${selected.policy.repository_id}:${selected.policy.updated_at}`}
          tenantId={tenantId}
          stored={selected}
          entities={entities}
        />
      ) : null}
    </div>
  );
}
