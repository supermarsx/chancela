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
import { useExportTemplate } from '../../api/hooks';
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
  const loadSpec = useExportTemplate();
  const [state, setState] = useState<TemplateEditorState | null>(null);

  async function withSpec(id: string, apply: (spec: TemplateSpec) => void) {
    try {
      const download = await loadSpec.mutateAsync(id);
      apply(JSON.parse(download.text) as TemplateSpec);
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
      void withSpec(template.id, (spec) => setState({ mode: 'edit', spec }));
    },
    clone: openFork,
    close: () => setState(null),
  };
}
