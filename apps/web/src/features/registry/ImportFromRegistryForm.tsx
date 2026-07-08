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
import { Button, Card, Field, Icon, Input, useToast } from '../../ui';
import { useT } from '../../i18n';
import { AccessCodeField } from './AccessCodeField';
import { RegistryErrorNote } from './RegistryErrorNote';

export function ImportFromRegistryForm() {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const importFromRegistry = useImportFromRegistry();
  const [code, setCode] = useState('');
  const [email, setEmail] = useState('');

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
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
      <form className="form" onSubmit={onSubmit}>
        <p className="muted">{t('registry.import.intro')}</p>
        <AccessCodeField id="import-code" value={code} onChange={setCode} />
        <Field
          label={t('registry.email.label')}
          htmlFor="import-email"
          hint={t('registry.email.hint')}
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
        {importFromRegistry.error ? <RegistryErrorNote error={importFromRegistry.error} /> : null}
        <div className="form__actions">
          <Button
            type="submit"
            variant="primary"
            icon={<Icon.Tray />}
            disabled={importFromRegistry.isPending || code.trim() === ''}
          >
            {importFromRegistry.isPending
              ? t('registry.import.consulting')
              : t('registry.import.submit')}
          </Button>
        </div>
      </form>
    </Card>
  );
}
