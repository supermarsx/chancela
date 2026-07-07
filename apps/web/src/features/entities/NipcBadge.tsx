/**
 * A subtle warning badge shown next to an entity's NIPC wherever it renders (list, detail)
 * when the identifier was stored without control-digit validation (`nipc_validated: false`,
 * the §entity-v2 override). The compliance panel carries the full server-side warning; this
 * is the at-a-glance flag so an unvalidated NIPC never reads as an ordinary one.
 */
import { useT } from '../../i18n';
import { Badge } from '../../ui';

export function NipcBadge() {
  const t = useT();
  return (
    <Badge tone="warn">
      <span title={t('entities.nipcUnvalidated.aria')}>{t('entities.nipcUnvalidated.badge')}</span>
    </Badge>
  );
}
