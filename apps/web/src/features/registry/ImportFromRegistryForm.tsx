/**
 * Create a new entity straight from a certidão permanente (plan t11 §2.7,
 * `POST /v1/entities/import-from-registry`). The operator supplies the código de
 * acesso (and, for the newer registry platform, an e-mail); on success we navigate to
 * the freshly created entity so its imported identification and provenance are shown.
 *
 * The código is a secret: it is held only in transient component state, sent once in
 * the mutation body, and cleared as soon as the request resolves — never persisted,
 * cached or echoed back.
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useImportFromRegistry } from '../../api/hooks';
import { Badge, Button, Card, Field, Icon, Input, useToast } from '../../ui';
import { t as translateNow, useT } from '../../i18n';
import { AccessCodeField } from './AccessCodeField';
import { RegistryErrorNote } from './RegistryErrorNote';
import { registryFieldHelp } from './fieldHelp';

function ImportStatus({
  pending,
  hasError,
  hasCode,
}: {
  pending: boolean;
  hasError: boolean;
  hasCode: boolean;
}) {
  if (pending) {
    return (
      <aside className="registry-import-state registry-import-state--active" role="status">
        <p className="field__label">{translateNow('uiLiteral.importFromRegistryForm.estado')}</p>
        <Badge tone="accent">{translateNow('uiLiteral.importFromRegistryForm.aConsultar')}</Badge>
        <p>
          {translateNow('uiLiteral.importFromRegistryForm.aCertidaoEstaASerConsultadaMantenhaEsta')}
        </p>
      </aside>
    );
  }

  if (hasError) {
    return (
      <aside className="registry-import-state registry-import-state--error">
        <p className="field__label">{translateNow('uiLiteral.importFromRegistryForm.estado')}</p>
        <Badge tone="error">
          {translateNow('uiLiteral.importFromRegistryForm.acaoNecessaria')}
        </Badge>
        <p>{translateNow('uiLiteral.importFromRegistryForm.corrijaOCodigoOuEMailETente')}</p>
      </aside>
    );
  }

  return (
    <aside className="registry-import-state">
      <p className="field__label">{translateNow('uiLiteral.importFromRegistryForm.estado')}</p>
      <Badge tone={hasCode ? 'ok' : 'neutral'}>{hasCode ? 'Pronto' : 'Aguardando código'}</Badge>
      <p>
        {hasCode
          ? 'Pronto para consultar a certidão e criar a entidade.'
          : 'Introduza o código da certidão permanente. O e-mail só é necessário quando pedido pelo registo.'}
      </p>
    </aside>
  );
}

export function ImportFromRegistryForm() {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const importFromRegistry = useImportFromRegistry();
  const [code, setCode] = useState('');
  const [email, setEmail] = useState('');
  const hasCode = code.trim() !== '';

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!hasCode || importFromRegistry.isPending) return;
    importFromRegistry.mutate(
      { code, email: email.trim() || undefined },
      {
        onSuccess: (report) => {
          // Drop the secret code from state the moment it is used, then follow the new
          // entity. R6: the toast survives the navigate-away; R7: the inline
          // RegistryErrorNote below still handles the 422/502 error cases.
          setCode('');
          toast.success(t('toast.registry.imported'));
          navigate(`/entidades/${report.entity.id}`);
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <Card title={t('registry.importCard')}>
      <div className="registry-import-flow">
        <div className="registry-import-flow__main">
          <div className="registry-import-copy">
            <p className="registry-import-copy__eyebrow">
              {t('uiLiteral.importFromRegistryForm.consulta')}
            </p>
            <p className="muted">{t('registry.import.intro')}</p>
          </div>
          <form className="form registry-import-form" onSubmit={onSubmit}>
            <AccessCodeField id="import-code" value={code} onChange={setCode} />
            <Field
              label={t('registry.email.label')}
              htmlFor="import-email"
              hint={t('registry.email.hint')}
              help={registryFieldHelp.email}
            >
              <Input
                id="import-email"
                type="email"
                value={email}
                autoComplete="off"
                onChange={(e) => setEmail(e.target.value)}
                placeholder={t('registry.email.placeholder')}
              />
            </Field>
            {importFromRegistry.error ? (
              <RegistryErrorNote error={importFromRegistry.error} />
            ) : null}
            <div className="form__actions">
              <Button
                type="submit"
                variant="primary"
                icon={<Icon.Tray />}
                disabled={importFromRegistry.isPending || !hasCode}
              >
                {importFromRegistry.isPending
                  ? t('registry.import.consulting')
                  : t('registry.import.submit')}
              </Button>
            </div>
          </form>
        </div>
        <ImportStatus
          pending={importFromRegistry.isPending}
          hasError={Boolean(importFromRegistry.error)}
          hasCode={hasCode}
        />
      </div>
    </Card>
  );
}
