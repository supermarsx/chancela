/**
 * Draft a new ata inside an open book (WFL-14, `POST /v1/acts`). Extracted from the book
 * detail aside onto its own route (`/books/:id/new-act`) so the book view runs full
 * width (t13 item 7). On success it navigates straight to the ata editor for the new act.
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDraftAct } from '../../api/hooks';
import { meetingChannelLabels, optionsFrom } from '../../api/labels';
import { useT } from '../../i18n';
import { MEETING_CHANNELS, type MeetingChannel } from '../../api/types';
import { Button, ErrorNote, Field, Icon, Input, Select, useToast } from '../../ui';

export function DraftAtaForm({ bookId }: { bookId: string }) {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const draft = useDraftAct();
  const [title, setTitle] = useState('');
  const [channel, setChannel] = useState<MeetingChannel>('Physical');

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    draft.mutate(
      { book_id: bookId, title, channel },
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
      {draft.error ? <ErrorNote error={draft.error} /> : null}
      <div className="form__actions">
        <Button type="submit" variant="primary" icon={<Icon.Plus />} disabled={draft.isPending}>
          {draft.isPending ? t('acts.creating') : t('acts.newAta')}
        </Button>
      </div>
    </form>
  );
}
