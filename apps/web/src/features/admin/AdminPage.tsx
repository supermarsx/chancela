/**
 * Administração (t36) — the operations + integrations admin surface at `/admin`.
 *
 * A deliberately thin wrapper: it renders {@link SettingsPage} in its `admin` surface mode.
 * SettingsPage already owns the operations panes, their shared settings working-copy / autosave /
 * save-bar machinery and (in admin mode) the folded-in integrations subtabs, so re-parenting those
 * panes under `/admin` means REUSING that page rather than extracting them — extraction would fork
 * the autosave and save-bar behaviour that t14/t28 just landed there.
 *
 * `AdminPage` exists as its own lazy route module and test target; the admin-surface behaviour
 * itself (forcing the operations section, hiding the Configurações section strip, the `admin.title`
 * header, the integrations subtabs, and the `/settings/operations/*` retired-alias forwarding) lives
 * inside SettingsPage behind the `surface` prop introduced as the t36 contract.
 */
import { SettingsPage } from '../settings/SettingsPage';

export function AdminPage() {
  return <SettingsPage surface="admin" />;
}
