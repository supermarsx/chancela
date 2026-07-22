/**
 * Copy for the two t95-P2 sign-in walls: the **two-step-verification challenge** (Screen A, a
 * transient sub-state of `SignIn`, signed-out) and the **required-action wall** (Screen B, in
 * `AuthGate`, signed-in — change-password or enrol-2FA).
 *
 * **Why this module owns its keys instead of spreading into the catalogs** — same reason as
 * `serverEnvFallback.ts` / `notificationsRetentionFallback.ts`: the 14 locale catalogs
 * (`i18n/locales/*.ts` + `reviewedIdenticalValues.ts`) are under a single-writer serial lock for the
 * batch, so t21 is not permitted the usual "one import + one spread line per locale" wiring. This
 * module owns its keys end to end and exposes its own locale-aware resolver ({@link useAuthWallT}).
 * The screens read copy through it exactly as they would through `useT`, so nothing in the shared
 * catalog moves and the catalog-leak / literal-copy gates never see these strings. If the lock later
 * releases, folding these in is a mechanical spread and the screens switch to `t()` with no copy
 * changes. pt-PT is the source; every other locale falls back to English (remaining locales are a
 * deferred translation pass).
 *
 * **Copy rules honoured here.**
 * 1. **No claim of a legal requirement.** Both walls say plainly *why this account* must act (a
 *    temporary/admin-set password; the account is configured to require a second factor). Neither
 *    asserts the law obliges it.
 * 2. **Never surface a raw 401.** A wrong challenge or activation code is a credential-proof failure:
 *    the copy is an inline, field-level reject ("código incorreto"), never a sign-out or a routing
 *    message. The server cannot tell a wrong code from a spent/expired one (uniform 401), so the copy
 *    stays honest — a single reject plus a persistent escape.
 * 3. Follows the i18n agreement rules (no noun dropped into an inflected sentence); no anglicisms;
 *    the challenge `code` is a credential and never appears in copy.
 */
import { useMemo } from 'react';
import { useActiveLocale } from '../../i18n/useT';
import { interpolate, type TParams } from '../../i18n/interpolate';

export const authWallPtPT = {
  // ── Screen A — desafio de verificação em dois passos (SignIn, deslogado) ──────────────
  'signin.challenge.title': 'Verificação em dois passos',
  'signin.challenge.intro':
    'A sua conta está protegida com um segundo fator. Introduza o código atual da sua aplicação de autenticação para concluir a sessão.',
  'signin.challenge.codeLabel': 'Código de verificação',
  'signin.challenge.codePlaceholder': '000000',
  // Mostrado apenas quando o desafio aceita códigos de recuperação (methods inclui backup_code).
  'signin.challenge.backupHint':
    'Se não tiver acesso à aplicação, pode introduzir aqui um dos seus códigos de recuperação.',
  'signin.challenge.confirm': 'Confirmar',
  'signin.challenge.confirming': 'A confirmar…',
  // Rejeição inline para o 401 uniforme (código errado, gasto ou expirado — indistinguíveis).
  'signin.challenge.badCode': 'Código incorreto. Tente novamente.',
  // Após o limite local de tentativas: o desafio já não é válido, volta-se à palavra-passe.
  'signin.challenge.restart':
    'Demasiadas tentativas. Introduza novamente a palavra-passe para recomeçar.',
  // Se o desafio expirar (contagem decrescente opcional a chegar a zero).
  'signin.challenge.expired':
    'O pedido expirou. Introduza novamente a palavra-passe para recomeçar.',
  // Escape persistente de volta ao formulário de palavra-passe (abandona o desafio).
  'signin.challenge.back': 'Voltar',
  // Troca de conta em sessão (CurrentUserPicker): o seletor não tem passo de segundo fator — a
  // conta de destino usa-o, por isso a troca conclui-se a partir do ecrã de início de sessão.
  'signin.challenge.switcherUnsupported':
    'Esta conta usa verificação em dois passos. Termine a sessão e inicie-a a partir do ecrã de início de sessão.',

  // ── Screen B — parede de ação obrigatória (AuthGate, logado) ──────────────────────────
  // Escape comum a ambas as paredes: quem não consiga concluir não fica preso.
  'session.wall.signOut': 'Terminar sessão',

  // Parede: alterar a palavra-passe (required_action = change_password).
  'session.wall.changePassword.title': 'Defina a sua palavra-passe',
  'session.wall.changePassword.intro':
    'A sua conta foi criada com uma palavra-passe temporária definida por um administrador. Defina a sua palavra-passe antes de continuar.',
  'session.wall.changePassword.currentLabel': 'Palavra-passe atual',
  'session.wall.changePassword.newLabel': 'Nova palavra-passe',
  'session.wall.changePassword.confirmLabel': 'Confirmar a nova palavra-passe',
  'session.wall.changePassword.submit': 'Guardar a palavra-passe',
  'session.wall.changePassword.submitting': 'A guardar…',
  'session.wall.changePassword.mismatch': 'As palavras-passe não coincidem.',
  // 401 de prova de credencial: rejeição inline no campo da palavra-passe atual, nunca um logout.
  'session.wall.changePassword.badCurrent': 'Palavra-passe atual incorreta.',
  'session.wall.changePassword.error': 'Não foi possível alterar a palavra-passe.',

  // Parede: ativar o segundo fator (required_action = enrol_two_factor).
  'session.wall.enrol.title': 'Ative a verificação em dois passos',
  'session.wall.enrol.intro':
    'A sua conta tem de estar protegida com verificação em dois passos e ainda não tem nenhuma configurada. Configure-a para continuar.',
  'session.wall.enrol.scanHint':
    'Leia este código QR com a sua aplicação de autenticação. Se não conseguir ler, introduza a chave manualmente.',
  'session.wall.enrol.secretLabel': 'Chave (introdução manual)',
  'session.wall.enrol.codeLabel': 'Código da aplicação de autenticação',
  'session.wall.enrol.confirm': 'Ativar',
  'session.wall.enrol.confirming': 'A ativar…',
  // 401 de prova de credencial ao confirmar: rejeição inline, nunca um logout.
  'session.wall.enrol.badCode': 'Código incorreto. Tente novamente.',
  'session.wall.enrol.error': 'Não foi possível ativar a verificação em dois passos.',
  // Códigos de recuperação, apresentados uma única vez após a ativação.
  'session.wall.enrol.backupTitle': 'Códigos de recuperação',
  'session.wall.enrol.backupIntro':
    'Guarde estes códigos num local seguro. Cada um serve uma vez para entrar se perder o acesso à aplicação. Não voltarão a ser apresentados.',
  'session.wall.enrol.done': 'Concluir',
} as const;

/** The key set the t95-P2 sign-in walls resolve. */
export type AuthWallCopyKey = keyof typeof authWallPtPT;

export const authWallEnglish = {
  'signin.challenge.title': 'Two-step verification',
  'signin.challenge.intro':
    'Your account is protected with a second factor. Enter the current code from your authenticator app to finish signing in.',
  'signin.challenge.codeLabel': 'Verification code',
  'signin.challenge.codePlaceholder': '000000',
  'signin.challenge.backupHint':
    'If you cannot reach your app, you can enter one of your recovery codes here instead.',
  'signin.challenge.confirm': 'Confirm',
  'signin.challenge.confirming': 'Confirming…',
  'signin.challenge.badCode': 'Incorrect code. Try again.',
  'signin.challenge.restart': 'Too many attempts. Enter your password again to start over.',
  'signin.challenge.expired': 'This request expired. Enter your password again to start over.',
  'signin.challenge.back': 'Back',
  'signin.challenge.switcherUnsupported':
    'This account uses two-step verification. Sign out and sign in from the sign-in screen.',

  'session.wall.signOut': 'Sign out',

  'session.wall.changePassword.title': 'Set your password',
  'session.wall.changePassword.intro':
    'Your account was created with a temporary password set by an administrator. Set your own password before continuing.',
  'session.wall.changePassword.currentLabel': 'Current password',
  'session.wall.changePassword.newLabel': 'New password',
  'session.wall.changePassword.confirmLabel': 'Confirm the new password',
  'session.wall.changePassword.submit': 'Save password',
  'session.wall.changePassword.submitting': 'Saving…',
  'session.wall.changePassword.mismatch': 'The passwords do not match.',
  'session.wall.changePassword.badCurrent': 'Current password is incorrect.',
  'session.wall.changePassword.error': 'Could not change the password.',

  'session.wall.enrol.title': 'Turn on two-step verification',
  'session.wall.enrol.intro':
    'Your account must be protected with two-step verification and none is set up yet. Set it up to continue.',
  'session.wall.enrol.scanHint':
    'Scan this QR code with your authenticator app. If you cannot scan it, enter the key manually.',
  'session.wall.enrol.secretLabel': 'Key (manual entry)',
  'session.wall.enrol.codeLabel': 'Authenticator app code',
  'session.wall.enrol.confirm': 'Turn on',
  'session.wall.enrol.confirming': 'Turning on…',
  'session.wall.enrol.badCode': 'Incorrect code. Try again.',
  'session.wall.enrol.error': 'Could not turn on two-step verification.',
  'session.wall.enrol.backupTitle': 'Recovery codes',
  'session.wall.enrol.backupIntro':
    'Save these codes somewhere safe. Each one works once to sign in if you lose access to your app. They will not be shown again.',
  'session.wall.enrol.done': 'Done',
} as const satisfies Record<AuthWallCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale the English
 * fallback — the same split the catalog spread would produce, kept here because t21 may not touch the
 * catalogs while they are locked.
 */
export function useAuthWallCopy(): Record<AuthWallCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? authWallPtPT : authWallEnglish;
}

/**
 * The walls' translate hook, shaped like {@link useT}:
 * `const st = useAuthWallT(); st('signin.challenge.title')`. Supports the same `{placeholder}`
 * interpolation as the catalog.
 */
export function useAuthWallT(): (key: AuthWallCopyKey, params?: TParams) => string {
  const copy = useAuthWallCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
