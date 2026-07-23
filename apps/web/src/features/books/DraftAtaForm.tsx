/**
 * Draft a new ata inside an open book (WFL-14, `POST /v1/acts`). Extracted from the book
 * detail aside onto its own route (`/books/:id/new-act`) so the book view runs full
 * width (t13 item 7). On success it navigates straight to the ata editor for the new act.
 *
 * The optional template picker (t59) surfaces the ata templates that apply to the book's entity
 * family and threads the chosen id into the draft, so the server can seed the new act's editable
 * narrative from that template's default body. It is hidden until a real ata template exists for
 * the family, and "Modelo predefinido" leaves the id out (the server resolves the family default).
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useBook, useDraftAct, useEntity, useTemplates } from '../../api/hooks';
import { meetingChannelLabels, optionsFrom } from '../../api/labels';
import { useT } from '../../i18n';
import { useDraftAtaT } from '../../i18n/draftAtaFallback';
import { MEETING_CHANNELS, type MeetingChannel } from '../../api/types';
import { Button, ErrorNote, Field, Icon, Input, Select, useToast } from '../../ui';

export function DraftAtaForm({ bookId }: { bookId: string }) {
  const t = useT();
  const dt = useDraftAtaT();
  const toast = useToast();
  const navigate = useNavigate();
  const draft = useDraftAct();
  const [title, setTitle] = useState('');
  const [channel, setChannel] = useState<MeetingChannel>('Physical');
  const [templateId, setTemplateId] = useState('');

  // Resolve the book's entity family so the picker offers only the ata templates that apply to it
  // (the server 422s a family/stage-mismatched id at draft). Both reads are informational and the
  // picker stays hidden until a real ata template exists for the family — never a blocking step.
  const book = useBook(bookId);
  const entityId = book.data?.entity_id ?? '';
  const entity = useEntity(entityId);
  const family = entity.data?.family;
  const templates = useTemplates(family, 'Ata', family != null);
  const ataTemplates = templates.data ?? [];

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    draft.mutate(
      {
        book_id: bookId,
        title,
        channel,
        // Omit the field entirely on the default choice, so the wire stays byte-identical to a
        // pre-t59 draft and the server resolves the family default.
        ...(templateId ? { template_id: templateId } : {}),
      },
      {
        onSuccess: (act) => {
          toast.success(t('toast.ata.created'));
          navigate(`/acts/${act.id}`);
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <Field label={t('acts.titulo')} htmlFor="ata-title">
        <Input
          id="ata-title"
          required
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder={t('acts.tituloPlaceholder')}
        />
      </Field>
      <Field label={t('acts.canal')} htmlFor="ata-channel">
        <Select
          id="ata-channel"
          value={channel}
          onChange={(e) => setChannel(e.target.value as MeetingChannel)}
          options={optionsFrom(MEETING_CHANNELS, meetingChannelLabels)}
        />
      </Field>
      {ataTemplates.length > 0 ? (
        <Field label={dt('acts.template.label')} htmlFor="ata-template" hint={dt('acts.template.hint')}>
          <Select
            id="ata-template"
            value={templateId}
            onChange={(e) => setTemplateId(e.target.value)}
            options={[
              { value: '', label: dt('acts.template.default') },
              ...ataTemplates.map((tpl) => ({ value: tpl.id, label: tpl.id })),
            ]}
          />
        </Field>
      ) : null}
      {draft.error ? <ErrorNote error={draft.error} /> : null}
      <div className="form__actions">
        <Button type="submit" variant="primary" icon={<Icon.Plus />} disabled={draft.isPending}>
          {draft.isPending ? t('acts.creating') : t('acts.newAta')}
        </Button>
      </div>
    </form>
  );
}
