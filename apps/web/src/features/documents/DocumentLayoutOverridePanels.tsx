import { useEffect, useMemo, useState } from 'react';
import { useEntity, useSettings, useUpdateBook, useUpdateEntity } from '../../api/hooks';
import type { BookView, DocumentLayoutOverrides, Entity } from '../../api/types';
import { DEFAULT_SETTINGS } from '../../api/types';
import { useT } from '../../i18n';
import { Card, ErrorNote, Icon, InlineWarning, SkeletonDeflist, useToast } from '../../ui';
import { GateButton, scopeBook, scopeEntity, useCan } from '../session/permissions';
import {
  applyDocumentLayoutOverrides,
  DocumentLayoutOverridesEditor,
} from './DocumentLayoutEditor';

function sameOverrides(
  left: DocumentLayoutOverrides | null | undefined,
  right: DocumentLayoutOverrides | null | undefined,
): boolean {
  return JSON.stringify(left ?? null) === JSON.stringify(right ?? null);
}

export function EntityDocumentLayoutPanel({ entity }: { entity: Entity }) {
  const t = useT();
  const settings = useSettings();
  const update = useUpdateEntity(entity.id);
  const toast = useToast();
  const [draft, setDraft] = useState<DocumentLayoutOverrides | undefined>(
    entity.document_layout_override ?? undefined,
  );

  useEffect(() => {
    setDraft(entity.document_layout_override ?? undefined);
  }, [entity.id, entity.document_layout_override]);

  const inherited =
    settings.data?.documents.layout_defaults ?? DEFAULT_SETTINGS.documents.layout_defaults;
  const dirty = !sameOverrides(draft, entity.document_layout_override);

  function save() {
    update.mutate(
      { document_layout_override: draft ?? null },
      {
        onSuccess: (saved) => {
          setDraft(saved.document_layout_override ?? undefined);
          toast.success(t('documentLayout.entity.saved'));
        },
        onError: (error) => toast.error(error),
      },
    );
  }

  return (
    <Card title={t('documentLayout.title')}>
      <InlineWarning tone="info" title={t('documentLayout.inheritance.title')}>
        {t('documentLayout.entity.inheritance.body')}
      </InlineWarning>
      {settings.isLoading ? <SkeletonDeflist /> : null}
      {settings.error ? <ErrorNote error={settings.error} /> : null}
      {update.error ? <ErrorNote error={update.error} /> : null}
      {!settings.isLoading ? (
        <>
          <DocumentLayoutOverridesEditor
            idPrefix={`entity-${entity.id}-document-layout`}
            value={draft}
            inherited={inherited}
            inheritanceLabel={t('documentLayout.source.previousLevels')}
            inheritedValueLabel={t('documentLayout.baseline.instance')}
            disabled={update.isPending}
            onChange={setDraft}
          />
          <div className="form__actions">
            <GateButton
              perm="entity.update"
              scope={scopeEntity(entity.id)}
              type="button"
              variant="primary"
              icon={<Icon.Save />}
              disabled={!dirty || update.isPending}
              onClick={save}
            >
              {update.isPending
                ? t('documentLayout.action.saving')
                : t('documentLayout.action.saveEntity')}
            </GateButton>
          </div>
        </>
      ) : null}
    </Card>
  );
}

export function BookDocumentLayoutPanel({ book }: { book: BookView }) {
  const t = useT();
  const settings = useSettings();
  const can = useCan();
  const canReadEntity = can('entity.read', scopeEntity(book.entity_id));
  const entity = useEntity(book.entity_id, canReadEntity);
  const update = useUpdateBook(book.id);
  const toast = useToast();
  const [draft, setDraft] = useState<DocumentLayoutOverrides | undefined>(
    book.document_layout_override ?? undefined,
  );

  useEffect(() => {
    setDraft(book.document_layout_override ?? undefined);
  }, [book.id, book.document_layout_override]);

  const instance =
    settings.data?.documents.layout_defaults ?? DEFAULT_SETTINGS.documents.layout_defaults;
  const inherited = useMemo(
    () => applyDocumentLayoutOverrides(instance, entity.data?.document_layout_override),
    [entity.data?.document_layout_override, instance],
  );
  const dirty = !sameOverrides(draft, book.document_layout_override);
  const loading = settings.isLoading || (canReadEntity && entity.isLoading);

  function save() {
    update.mutate(
      { document_layout_override: draft ?? null },
      {
        onSuccess: (saved) => {
          setDraft(saved.document_layout_override ?? undefined);
          toast.success(t('documentLayout.book.saved'));
        },
        onError: (error) => toast.error(error),
      },
    );
  }

  return (
    <Card title={t('documentLayout.title')}>
      <InlineWarning tone="info" title={t('documentLayout.inheritance.title')}>
        {t('documentLayout.book.inheritance.body')}
      </InlineWarning>
      {!canReadEntity ? (
        <InlineWarning tone="warn" title={t('documentLayout.entity.hidden.title')}>
          {t('documentLayout.entity.hidden.body')}
        </InlineWarning>
      ) : null}
      {loading ? <SkeletonDeflist /> : null}
      {settings.error ? <ErrorNote error={settings.error} /> : null}
      {entity.error ? <ErrorNote error={entity.error} /> : null}
      {update.error ? <ErrorNote error={update.error} /> : null}
      {!loading ? (
        <>
          <DocumentLayoutOverridesEditor
            idPrefix={`book-${book.id}-document-layout`}
            value={draft}
            inherited={inherited}
            inheritanceLabel={t('documentLayout.source.previousLevels')}
            inheritedValueLabel={t('documentLayout.baseline.instanceEntity')}
            disabled={update.isPending}
            onChange={setDraft}
          />
          <div className="form__actions">
            <GateButton
              perm="book.open"
              scope={scopeBook(book.id)}
              type="button"
              variant="primary"
              icon={<Icon.Save />}
              disabled={!dirty || update.isPending}
              onClick={save}
            >
              {update.isPending
                ? t('documentLayout.action.saving')
                : t('documentLayout.action.saveBook')}
            </GateButton>
          </div>
        </>
      ) : null}
    </Card>
  );
}
