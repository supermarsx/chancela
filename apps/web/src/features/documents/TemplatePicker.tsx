/**
 * TemplatePicker — surfaces the template(s) bound to an entity family × lifecycle stage
 * (`GET /v1/templates`, plan t48-e6 deliverable 3).
 *
 * Informational for v1: the seal auto-selects the template, so this is not a chooser —
 * it just shows the operator which model will be frozen when the act enters `Signing` (and
 * honestly says "sem modelo disponível" when a family has no template yet). Reads only, so a
 * load error renders inline (no toast, per
 * CONVENTIONS §2).
 */
import type { EntityFamily, LifecycleStage } from '../../api/types';
import { useTemplates } from '../../api/hooks';
import { useT } from '../../i18n';
import { ErrorNote, Skeleton } from '../../ui';
import './documents.css';

export function TemplatePicker({
  family,
  stage,
}: {
  family?: EntityFamily;
  stage: LifecycleStage;
}) {
  const t = useT();
  const templates = useTemplates(family, stage);

  if (templates.isLoading) {
    return <Skeleton height="1.4rem" width="14rem" />;
  }
  if (templates.error) {
    return <ErrorNote error={templates.error} />;
  }
  const list = templates.data ?? [];
  if (list.length === 0) {
    return <p className="muted">{t('documents.template.none')}</p>;
  }
  return (
    <div className="stack--tight">
      <p className="card__label">{t('documents.template.title')}</p>
      <ul className="template-list">
        {list.map((tpl) => (
          <li key={tpl.id} className="template-item">
            <code className="template-item__id">{tpl.id}</code>
            <span className="template-item__locale">
              {t('documents.template.localeLabel', { locale: tpl.locale })}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
