import { Link } from 'react-router-dom';
import { EmptyState } from '../ui';
import { useT } from '../i18n';

export function NotFoundPage() {
  const t = useT();
  return (
    <EmptyState title={t('notFound.title')}>
      <p>
        {t('notFound.body')} <Link to="/">{t('notFound.backLink')}</Link>.
      </p>
    </EmptyState>
  );
}
