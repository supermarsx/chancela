/**
 * Concurrency-safe copy for the standalone template version-history surface.
 *
 * The main locale catalogues and template-editor fallback are shared integration hotspots, so
 * this lane keeps its pt-PT source and English fallback together. The resolver mirrors `useT`.
 */
import { useMemo } from 'react';
import { interpolate, type TParams } from './interpolate';
import { useActiveLocale } from './useT';

export const templatesVersionHistoryPtPT = {
  'templates.versions.title': 'Versões guardadas',
  'templates.versions.caption': 'Histórico de versões guardadas deste modelo',
  'templates.versions.retention':
    'São mantidas até {count} versões. As mais antigas são removidas automaticamente.',
  'templates.versions.empty': 'Ainda não existem versões guardadas.',
  'templates.versions.name': 'Nome',
  'templates.versions.savedAt': 'Guardada em',
  'templates.versions.actor': 'Guardada por',
  'templates.versions.actions': 'Ações',
  'templates.versions.unnamed': 'Versão sem nome',
  'templates.versions.rename': 'Alterar nome',
  'templates.versions.renameLabel': 'Nome da versão',
  'templates.versions.renameHint': 'Até 200 caracteres. Deixe em branco para remover o nome.',
  'templates.versions.renameSave': 'Guardar nome',
  'templates.versions.renamePending': 'A guardar…',
  'templates.versions.renameCancel': 'Cancelar',
  'templates.versions.renameTooLong': 'O nome não pode exceder 200 caracteres.',
  'templates.versions.delete': 'Eliminar versão',
  'templates.versions.deleteTitle': 'Eliminar esta versão guardada?',
  'templates.versions.deleteIntro':
    'Esta versão será removida permanentemente do histórico. O modelo atual não será alterado.',
  'templates.versions.deleteConfirm': 'Eliminar versão',
  'templates.versions.deletePending': 'A eliminar…',
  'templates.versions.restore': 'Repor versão',
  'templates.versions.restoreBlockedTitle': 'Reposição bloqueada',
  'templates.versions.restoreTitle': 'Repor esta versão?',
  'templates.versions.restoreIntro':
    'O conteúdo atual do modelo será substituído por esta versão. O estado reposto será guardado como uma nova versão.',
  'templates.versions.restoreConfirm': 'Repor versão',
  'templates.versions.restorePending': 'A repor…',
  'templates.versions.renamed': 'Nome da versão atualizado.',
  'templates.versions.deleted': 'Versão eliminada.',
  'templates.versions.restored': 'Versão reposta.',
} as const;

export type TemplatesVersionHistoryCopyKey = keyof typeof templatesVersionHistoryPtPT;

export const templatesVersionHistoryEnglish = {
  'templates.versions.title': 'Saved versions',
  'templates.versions.caption': 'Saved version history for this template',
  'templates.versions.retention':
    'Up to {count} versions are kept. The oldest are removed automatically.',
  'templates.versions.empty': 'There are no saved versions yet.',
  'templates.versions.name': 'Name',
  'templates.versions.savedAt': 'Saved at',
  'templates.versions.actor': 'Saved by',
  'templates.versions.actions': 'Actions',
  'templates.versions.unnamed': 'Unnamed version',
  'templates.versions.rename': 'Rename',
  'templates.versions.renameLabel': 'Version name',
  'templates.versions.renameHint': 'Up to 200 characters. Leave blank to remove the name.',
  'templates.versions.renameSave': 'Save name',
  'templates.versions.renamePending': 'Saving…',
  'templates.versions.renameCancel': 'Cancel',
  'templates.versions.renameTooLong': 'The name cannot be longer than 200 characters.',
  'templates.versions.delete': 'Delete version',
  'templates.versions.deleteTitle': 'Delete this saved version?',
  'templates.versions.deleteIntro':
    'This version will be permanently removed from history. The current template will not change.',
  'templates.versions.deleteConfirm': 'Delete version',
  'templates.versions.deletePending': 'Deleting…',
  'templates.versions.restore': 'Restore version',
  'templates.versions.restoreBlockedTitle': 'Restore blocked',
  'templates.versions.restoreTitle': 'Restore this version?',
  'templates.versions.restoreIntro':
    'The current template content will be replaced with this version. The restored state will be recorded as a new version.',
  'templates.versions.restoreConfirm': 'Restore version',
  'templates.versions.restorePending': 'Restoring…',
  'templates.versions.renamed': 'Version name updated.',
  'templates.versions.deleted': 'Version deleted.',
  'templates.versions.restored': 'Version restored.',
} as const satisfies Record<TemplatesVersionHistoryCopyKey, string>;

export function useTemplatesVersionHistoryT(): (
  key: TemplatesVersionHistoryCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? templatesVersionHistoryPtPT : templatesVersionHistoryEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
