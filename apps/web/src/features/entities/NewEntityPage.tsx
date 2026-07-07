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
import { Button, ButtonLink, Card, Field, Icon, Input, PageHeader, Select } from '../../ui';

export function NewEntityPage() {
  const t = useT();
  const navigate = useNavigate();
  const create = useCreateEntity();
  const [name, setName] = useState('');
  const [nipc, setNipc] = useState('');
  const [seat, setSeat] = useState('');
  const [kind, setKind] = useState<EntityKind>('SociedadePorQuotas');

  const nipcError =
    create.error instanceof ApiError && create.error.status === 422 ? create.error.message : null;

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    create.mutate(
      { name, nipc, seat, kind },
      { onSuccess: (entity) => navigate(`/entidades/${entity.id}`) },
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
              inputMode="numeric"
              value={nipc}
              onChange={(e) => setNipc(e.target.value)}
              placeholder={t('entities.form.nipcPlaceholder')}
            />
          </Field>
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
