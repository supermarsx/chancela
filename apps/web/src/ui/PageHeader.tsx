/**
 * The uniform page header (t19-e2 item e). Every top-level page renders its title
 * through this one component so the title scale, the optional breadcrumb, the actions
 * slot and the lede spacing are identical across the app — replacing the ad-hoc mix of
 * bare `.section-title` headings, `.crumbs` + title pairs and `.settings-hero` blocks.
 *
 * Slots:
 *  - `crumbs`  — an optional breadcrumb line above the title (may contain router links).
 *  - `title`   — the page title (kept on `.section-title` so the editorial type scale is
 *                shared; `.page-header` zeroes its stray margins for a consistent rhythm).
 *  - `actions` — optional right-aligned actions (buttons/links) on the title row.
 *  - `lede`    — an optional descriptive paragraph beneath the title.
 *  - `children`— optional extra header content (e.g. a segmented sub-nav) below the lede.
 */
import type { ReactNode } from 'react';

interface PageHeaderProps {
  title: ReactNode;
  crumbs?: ReactNode;
  actions?: ReactNode;
  lede?: ReactNode;
  children?: ReactNode;
}

export function PageHeader({ title, crumbs, actions, lede, children }: PageHeaderProps) {
  return (
    <header className="page-header">
      {crumbs ? <p className="crumbs page-header__crumbs">{crumbs}</p> : null}
      <div className="page-header__bar">
        <h1 className="section-title page-header__title">{title}</h1>
        {actions ? <div className="page-header__actions">{actions}</div> : null}
      </div>
      {lede ? <p className="settings-hero__lede page-header__lede">{lede}</p> : null}
      {children}
    </header>
  );
}
