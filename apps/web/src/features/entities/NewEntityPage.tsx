/**
 * Create an entity by hand (t13 item 1). The manual create form used to sit permanently
 * in the Entidades aside; it now lives on its own editorial route (`/entidades/nova`),
 * reached from a neat button, so the list can run full width. On success we follow the
 * freshly created entity to its detail page. The NIPC field still surfaces the API's 422
 * (bad check digit) inline via the `ApiError` message.
 */
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useCreateEntity } from '../../api/hooks';
import { entityKindLabels, optionsFrom } from '../../api/labels';
import { ENTITY_KINDS, type EntityKind } from '../../api/types';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import {
  Button,
  ButtonLink,
  Card,
  Field,
  Icon,
  InlineWarning,
  Input,
  PageHeader,
  Select,
  Toggle,
  useToast,
} from '../../ui';

export function NewEntityPage() {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const create = useCreateEntity();
  const [name, setName] = useState('');
  const [nipc, setNipc] = useState('');
  const [seat, setSeat] = useState('');
  const [kind, setKind] = useState<EntityKind>('SociedadePorQuotas');
  // §entity-v2 override: create even when the NIPC fails control-digit validation
  // (foreign entities / special registrations). Sends `allow_invalid_nipc: true`.
  const [allowInvalidNipc, setAllowInvalidNipc] = useState(false);

  // With the override on, a bad check digit no longer 422s, so the inline NIPC error only
  // applies to the strict path.
  const nipcError =
    !allowInvalidNipc && create.error instanceof ApiError && create.error.status === 422
      ? create.error.message
      : null;

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    create.mutate(
      { name, nipc, seat, kind, allow_invalid_nipc: allowInvalidNipc },
      {
        onSuccess: (entity) => {
          // R6: the success toast fires even though the handler navigates away — the
          // ToastProvider is above the router. R7: the inline NIPC 422 note stays.
          toast.success(t('toast.entity.created'));
          navigate(`/entidades/${entity.id}`);
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={
          <>
            <Link to="/entidades">{t('entities.crumb')}</Link> · {t('entities.newCrumb')}
          </>
        }
        title={t('entities.newPageTitle')}
      />

      <Card title={t('entities.identificationCard')}>
        <form className="form" onSubmit={onSubmit}>
          <Field label={t('entities.form.name')} htmlFor="ent-name">
            <Input
              id="ent-name"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('entities.form.namePlaceholder')}
            />
          </Field>
          <Field
            label={t('entities.form.nipc')}
            htmlFor="ent-nipc"
            hint={t('entities.form.nipcHint')}
            error={nipcError}
          >
            <Input
              id="ent-nipc"
              required
              inputMode={allowInvalidNipc ? 'text' : 'numeric'}
              value={nipc}
              onChange={(e) => setNipc(e.target.value)}
              placeholder={t('entities.form.nipcPlaceholder')}
            />
          </Field>
          <div className="stack--tight">
            <Toggle
              label={t('entities.form.allowInvalidNipc.label')}
              checked={allowInvalidNipc}
              onChange={setAllowInvalidNipc}
            />
            {allowInvalidNipc ? (
              <InlineWarning tone="warn">{t('entities.form.allowInvalidNipc.hint')}</InlineWarning>
            ) : null}
          </div>
          <Field label={t('entities.form.seat')} htmlFor="ent-seat">
            <Input
              id="ent-seat"
              required
              value={seat}
              onChange={(e) => setSeat(e.target.value)}
              placeholder={t('entities.form.seatPlaceholder')}
            />
          </Field>
          <Field label={t('entities.form.legalForm')} htmlFor="ent-kind">
            <Select
              id="ent-kind"
              value={kind}
              onChange={(e) => setKind(e.target.value as EntityKind)}
              options={optionsFrom(ENTITY_KINDS, entityKindLabels)}
            />
          </Field>
          <div className="form__actions">
            <Button
              type="submit"
              variant="primary"
              icon={<Icon.Plus />}
              disabled={create.isPending}
            >
              {create.isPending ? t('entities.form.creating') : t('entities.form.create')}
            </Button>
            <ButtonLink to="/entidades" variant="ghost" icon={<Icon.Close />}>
              {t('common.cancel')}
            </ButtonLink>
          </div>
        </form>
      </Card>
    </div>
  );
}
