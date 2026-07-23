/**
 * The one place that decides what "Editar" and "Duplicar" mean for a template.
 *
 * Both the catalog table and a template's detail page offer the two actions, and both must
 * make the same ruling: a BUILT-IN template is never edited in place — editing it offers a
 * fork into the `user-…` namespace instead. That is not a UI preference. A sealed document
 * records the digest of the spec it was generated from, so rewriting a shipped template would
 * retroactively change what a past seal meant. Keeping the decision in a hook means neither
 * surface can drift from the other.
 *
 * The spec body is not in `TemplateSummary`, so every path here first fetches it through the
 * export endpoint — the only read that returns `blocks`.
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { templateSpecFromExport, useExportTemplate } from '../../api/hooks';
import { templateEditPath } from './templateRoutes';
import type { TemplateSpec, TemplateSummary } from '../../api/types';
import { useToast } from '../../ui';
import { forkTemplateSpec, forkedTemplateId } from './templateFork';

export type TemplateEditorState =
  | { mode: 'create' }
  | { mode: 'edit'; spec: TemplateSpec }
  /** A copy of `sourceId`, not yet saved. `sourceId` may be built-in or user-authored. */
  | { mode: 'fork'; spec: TemplateSpec; sourceId: string; sourceIsBuiltin: boolean };

export interface TemplateEditorController {
  state: TemplateEditorState | null;
  /** A spec download is in flight; the triggering button should read as busy. */
  pending: boolean;
  create: () => void;
  /** Edit a user template in place; a built-in is diverted to a fork. */
  edit: (template: TemplateSummary) => void;
  /** Always a fork, whatever the source. */
  clone: (template: TemplateSummary) => void;
  close: () => void;
}

/**
 * @param existingIds every id already in the catalog, so a fork never collides on save.
 */
export function useTemplateEditor(existingIds: readonly string[]): TemplateEditorController {
  const toast = useToast();
  const navigate = useNavigate();
  const loadSpec = useExportTemplate();
  const [state, setState] = useState<TemplateEditorState | null>(null);

  async function withSpec(id: string, apply: (spec: TemplateSpec) => void) {
    try {
      const download = await loadSpec.mutateAsync(id);
      // The export is the `chancela.template-bundle` envelope (t43), whose spec lives under `.spec`;
      // unwrap it rather than casting the envelope to `TemplateSpec` (that left `rule_pack_id` and
      // `blocks` undefined, crashing the fork editor on `spec.rule_pack_id.trim()`).
      apply(templateSpecFromExport(JSON.parse(download.text)));
    } catch (err) {
      toast.error(err);
    }
  }

  function openFork(template: TemplateSummary) {
    void withSpec(template.id, (spec) =>
      setState({
        mode: 'fork',
        spec: forkTemplateSpec(spec, forkedTemplateId(template.id, existingIds)),
        sourceId: template.id,
        sourceIsBuiltin: template.source !== 'user',
      }),
    );
  }

  return {
    state,
    pending: loadSpec.isPending,
    create: () => setState({ mode: 'create' }),
    edit: (template) => {
      if (template.source !== 'user') {
        openFork(template);
        return;
      }
      // A user template is edited on its OWN full-width page (t109), not in the dialog: its
      // body is canonical BlockSpec JSON and needs the room. The fork path stays a dialog —
      // there the operator is naming a copy, not writing one. The spec is not fetched here
      // any more; the page loads it through the shared `useTemplateSpec` query.
      void navigate(templateEditPath(template.id));
    },
    clone: openFork,
    close: () => setState(null),
  };
}
