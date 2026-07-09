/**
 * The reusable "create a user" form (plan t50 W2). Extracted verbatim from the old inline
 * `CreateUserForm` on `UsersPage` so it can be mounted in BOTH the settings users
 * section (authenticated create) AND, later, the signed-out
 * entry-screen bootstrap path (t50 W3). It owns the field state, the client-side username
 * validation that mirrors the server, and the inline 409-duplicate surface; it does NOT
 * decide what happens after a successful create — the parent's `onCreated(user)` handler
 * owns the toast + navigation (or, for the bootstrap path, the follow-on passwordless
 * sign-in). This keeps the form honest and identical in every host.
 */
import { useState } from 'react';
import { useCreateUser } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import { Button, ErrorNote, Field, Icon, Input, useToast } from '../../ui';
import { isValidUsername, usernameError } from './username';
import type { UserView } from '../../api/types';

export function UserCreateForm({
  onCreated,
  submitLabel,
  autoFocus,
}: {
  /** Called with the freshly created user; the host owns the toast + navigation. */
  onCreated: (user: UserView) => void;
  /** Override the submit label (defaults to `users.create.submit`). */
  submitLabel?: string;
  /** Focus the username field on mount (dedicated create screen wants this). */
  autoFocus?: boolean;
}) {
  const t = useT();
  const toast = useToast();
  const create = useCreateUser();
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const fieldError = usernameError(username);

  // Surface a server duplicate (409) inline against the username field.
  const conflict =
    create.error instanceof ApiError && create.error.status === 409 ? create.error.message : null;

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!isValidUsername(username)) return;
    create.mutate(
      { username, display_name: displayName.trim() || undefined, email: email.trim() || undefined },
      {
        onSuccess: (user) => {
          // R7: the inline 409 duplicate note against the field stays; the host toasts
          // the success + navigates.
          setUsername('');
          setDisplayName('');
          setEmail('');
          onCreated(user);
        },
        // R7: a non-conflict failure keeps its inline ErrorNote below AND toasts.
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <Field
        label={t('users.field.username.label')}
        htmlFor="user-username"
        hint={t('users.field.username.hint')}
        error={fieldError ?? conflict}
      >
        <Input
          id="user-username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder={t('users.field.username.placeholder')}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          autoFocus={autoFocus}
        />
      </Field>
      <Field label={t('users.field.displayName.label')} htmlFor="user-display">
        <Input
          id="user-display"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder={t('users.field.displayName.placeholder')}
          autoComplete="off"
        />
      </Field>
      <Field label={t('registry.email.label')} htmlFor="user-email">
        <Input
          id="user-email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder={t('registry.email.placeholder')}
          autoComplete="email"
        />
      </Field>
      {create.error && !conflict ? <ErrorNote error={create.error} /> : null}
      <div className="form__actions">
        <Button
          type="submit"
          variant="primary"
          icon={<Icon.Plus />}
          disabled={create.isPending || !isValidUsername(username)}
        >
          {create.isPending
            ? t('users.create.submitting')
            : (submitLabel ?? t('users.create.submit'))}
        </Button>
      </div>
    </form>
  );
}
