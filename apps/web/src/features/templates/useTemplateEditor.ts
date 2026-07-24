/**
 * The one place that decides what "Novo", "Editar" and "Duplicar" mean for a template.
 *
 * All three are now full-page surfaces rather than modals (t56): the controller navigates, it does
 * not open a dialog. Keeping the decision in a hook means the catalog table and a template's detail
 * page cannot drift from one another.
 *
 * The rulings it encodes:
 *  - CREATE goes to `/templates/new`;
 *  - EDIT of a `user-…` template goes to that template's own full-width edit page;
 *  - EDIT of a BUILT-IN never edits in place — a sealed document records the digest of the spec it
 *    was generated from, so rewriting a shipped template would retroactively change what a past seal
 *    meant. It is diverted to a FORK (a create seeded from the built-in) instead;
 *  - DUPLICATE is always a fork, whatever the source.
 *
 * The create/fork page fetches the source spec + body itself (through the shared export query), so
 * this hook no longer downloads anything — every action is an instant navigation.
 */
import { useNavigate } from 'react-router-dom';
import type { TemplateSummary } from '../../api/types';
import { templateEditPath, templateForkPath, templateNewPath } from './templateRoutes';

export interface TemplateEditorController {
  /** Go to the full-page create surface. */
  create: () => void;
  /** Edit a user template on its own page; a built-in is diverted to a fork. */
  edit: (template: TemplateSummary) => void;
  /** Always a fork (a create seeded from the source), whatever the source. */
  clone: (template: TemplateSummary) => void;
}

export function useTemplateEditor(): TemplateEditorController {
  const navigate = useNavigate();
  return {
    create: () => void navigate(templateNewPath()),
    edit: (template) => {
      // A user template is edited in place on its OWN full-width page; a built-in can only be
      // changed by forking it, so "Editar" on one leads to the seeded create page.
      void navigate(
        template.source === 'user' ? templateEditPath(template.id) : templateForkPath(template.id),
      );
    },
    clone: (template) => void navigate(templateForkPath(template.id)),
  };
}
