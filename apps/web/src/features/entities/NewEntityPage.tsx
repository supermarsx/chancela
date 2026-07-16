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
import { entityFieldHelp } from './fieldHelp';

function normalizeFiscalYearEndInput(input: string): string | null {
  const value = input.trim();
  if (value === '') return null;
  const match = /^(\d{2})-(\d{2})$/.exec(value);
  if (!match) throw new Error('invalid fiscal-year end');
  const month = Number(match[1]);
  const day = Number(match[2]);
  const daysInMonth = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth[month - 1]) {
    throw new Error('invalid fiscal-year end');
  }
  return `${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

export function NewEntityPage() {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const create = useCreateEntity();
  const [name, setName] = useState('');
  const [nipc, setNipc] = useState('');
  const [seat, setSeat] = useState('');
  const [kind, setKind] = useState<EntityKind>('SociedadePorQuotas');
  const [fiscalYearEnd, setFiscalYearEnd] = useState('');
  const [fiscalYearEndError, setFiscalYearEndError] = useState<string | null>(null);
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
    let normalizedFiscalYearEnd: string | null;
    try {
      normalizedFiscalYearEnd = normalizeFiscalYearEndInput(fiscalYearEnd);
      setFiscalYearEndError(null);
    } catch {
      setFiscalYearEndError(t('entities.fiscalYearEnd.invalid'));
      return;
    }
    create.mutate(
      {
        name,
        nipc,
        seat,
        kind,
        allow_invalid_nipc: allowInvalidNipc,
        fiscal_year_end: normalizedFiscalYearEnd,
      },
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
            help={entityFieldHelp.nipc}
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
          <Field label={t('entities.form.seat')} htmlFor="ent-seat" help={entityFieldHelp.seat}>
            <Input
              id="ent-seat"
              required
              value={seat}
              onChange={(e) => setSeat(e.target.value)}
              placeholder={t('entities.form.seatPlaceholder')}
            />
          </Field>
          <Field
            label={t('entities.form.legalForm')}
            htmlFor="ent-kind"
            help={entityFieldHelp.legalForm}
          >
            <Select
              id="ent-kind"
              value={kind}
              onChange={(e) => setKind(e.target.value as EntityKind)}
              options={optionsFrom(ENTITY_KINDS, entityKindLabels)}
            />
          </Field>
          <Field
            label={t('entities.fiscalYearEnd.inputLabel')}
            htmlFor="ent-fiscal-year-end"
            hint={t('entities.fiscalYearEnd.hint')}
            help={entityFieldHelp.fiscalYearEnd}
            error={fiscalYearEndError}
          >
            <Input
              id="ent-fiscal-year-end"
              value={fiscalYearEnd}
              onChange={(e) => {
                setFiscalYearEnd(e.target.value);
                if (fiscalYearEndError) setFiscalYearEndError(null);
              }}
              placeholder={t('entities.fiscalYearEnd.placeholder')}
              maxLength={5}
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
