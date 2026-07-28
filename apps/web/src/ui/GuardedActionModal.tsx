/**
 * **The policy-driven front end of the server's guarded-action registry (t68).**
 *
 * `crates/chancela-api/src/confirmation.rs` is the single authority on which actions demand
 * confirmation and how hard each is to proceed with; `GET /v1/confirmation-policy` publishes the
 * resolved verdict per action. Until t68 nothing in the web app read it, so every confirm dialog
 * in the product picked its own strictness by hand — which is exactly the decision the registry
 * exists to own.
 *
 * This module is the one place that turns a policy row into dialog behaviour:
 *
 *  - `strictness` → whether a dialog is required at all, and whether it also demands step-up
 *    re-auth and a byte-exact typed phrase.
 *  - `consequence` → the framing only. `destructive` earns the red treatment; `consequential`
 *    must NOT borrow destructive vocabulary, because mislabelling a legitimate administrative
 *    act trains operators to click through the guards that matter.
 *
 * It composes over {@link ConfirmActionModal} rather than replacing it: that component already
 * owns the phrase field, the step-up field, the focus trap and the 403 → inline-re-auth mapping,
 * and fifteen call sites already use it. What was missing was never the dialog — it was who
 * decides. So a call site now names its action and supplies its copy, and nothing else.
 *
 * # Fail-safe direction while the policy is unknown
 *
 * Three distinct unknowns, deliberately handled differently:
 *
 *  - **Still loading** — a dialog is shown and the confirm button stays disabled. Guessing a
 *    level here could under-gate (render a plain confirm for an action the server floors at
 *    re-auth), so the dialog waits rather than guesses. It is a sub-second wait on a query that
 *    is warm for the whole session.
 *  - **The endpoint failed** — fall back to a plain `confirm`. Falling back to "blocked" would
 *    turn one unreachable endpoint into an unusable product, and falling back to "off" would
 *    silently drop a guard. A confirm step is the honest middle: the server independently
 *    re-enforces every level above `confirm`, and answers a missing proof with a 403 the dialog
 *    already renders inline.
 *  - **The action is absent from the response** — same as a failure, and for the same reason.
 *
 * `confirm` itself is client-side by construction: the server records that there is no
 * observable difference between "the operator accepted a dialog" and "the operator did not", so
 * for a `confirm`-floored action this component IS the gate.
 */
import type { ReactNode } from 'react';
import { useConfirmationPolicy } from '../api/hooks';
import type {
  ConfirmationActionId,
  ConfirmationActionPolicyView,
  ConfirmationStrictness,
} from '../api/types';
import { ConfirmActionModal, type ConfirmActionArgs } from './ConfirmActionModal';

/**
 * The strictness ordering, mirroring the server's `Ord` derive on `ConfirmationStrictness`.
 *
 * **The only place levels are compared in the web app**, matching the server's own rule that
 * `effective_strictness` is the only place they are compared there. A call site that compared
 * them itself would be a second opinion on a single-authority question.
 */
const STRICTNESS_RANK: Record<ConfirmationStrictness, number> = {
  off: 0,
  confirm: 1,
  confirm_with_reauth: 2,
  confirm_with_reauth_and_phrase: 3,
};

/** What the resolved policy means for one action's dialog. */
export interface GuardedActionPolicy {
  /** The resolved row, or `undefined` while unread / absent / unreachable. */
  row?: ConfirmationActionPolicyView;
  /**
   * Whether the operator must pass a dialog before the mutation runs. `false` only when the
   * policy positively resolves the action to `off`.
   */
  gated: boolean;
  /** `true` once the level below is the server's answer rather than the fallback. */
  resolved: boolean;
  /** The effective level, falling back to `confirm` when the policy could not be read. */
  strictness: ConfirmationStrictness;
  /** Whether the dialog must collect a step-up proof. */
  requireReauth: boolean;
  /** The byte-exact phrase to transcribe, when the level demands one. */
  phrase?: string;
  /** Whether destructive framing is honest for this action. */
  danger: boolean;
}

/**
 * Resolve one action's confirmation policy.
 *
 * Exposed separately from the modal because the *decision to open a dialog* belongs to the call
 * site: an action resolved to `off` must mutate on the first click with no dialog at all, and
 * only the call site knows which of its buttons maps to the guarded action (deactivating a user
 * is guarded; reactivating the same user is not an action the registry models).
 */
export function useGuardedActionPolicy(action: ConfirmationActionId): GuardedActionPolicy {
  const policy = useConfirmationPolicy();
  // `?.` on `actions` as well as on `data`: a body that is not the policy shape must degrade to
  // the fallback below like any other failed read, not crash the screen that holds the dialog.
  const row = policy.data?.actions?.find((candidate) => candidate.action === action);
  const strictness: ConfirmationStrictness = row?.effective ?? 'confirm';
  const rank = STRICTNESS_RANK[strictness];
  return {
    row,
    gated: strictness !== 'off',
    // Pending is the only state that is genuinely undecided; an error or an absent row has
    // already fallen back and must not leave the dialog permanently unconfirmable.
    resolved: row !== undefined || !policy.isPending,
    strictness,
    requireReauth: rank >= STRICTNESS_RANK.confirm_with_reauth,
    phrase: rank >= STRICTNESS_RANK.confirm_with_reauth_and_phrase ? row?.phrase : undefined,
    danger: row?.consequence === 'destructive',
  };
}

export interface GuardedActionModalProps {
  /** The server's frozen wire id for the action being confirmed. */
  action: ConfirmationActionId;
  open: boolean;
  onClose: () => void;
  title: string;
  /** Honest explanation of exactly what the action does, in the caller's own copy. */
  intro: ReactNode;
  confirmLabel: string;
  pendingLabel: string;
  /** The parent mutation's in-flight flag. */
  pending?: boolean;
  /** Additional gate the parent controls (e.g. a required reason is non-empty). */
  canConfirm?: boolean;
  /** Parent-specific inputs rendered above the shared gate. */
  children?: ReactNode;
  /**
   * Runs the actual mutation; resolves on success (the dialog then closes), rejects on error.
   *
   * Receives the gathered gate values. A call site whose endpoint accepts a `ConfirmationProof`
   * must thread `reauth` (and the typed phrase, via the endpoint's own field) into the request —
   * the dialog gathers the proof, it does not transmit it.
   */
  onConfirm: (args: ConfirmActionArgs) => Promise<void>;
}

/**
 * A confirm dialog whose strictness and framing come from the server policy for `action`.
 *
 * Deliberately does NOT decide whether to render: `open` stays the caller's, so a caller can
 * skip the dialog entirely for an `off` action (see {@link useGuardedActionPolicy}).
 */
export function GuardedActionModal({
  action,
  canConfirm = true,
  ...rest
}: GuardedActionModalProps) {
  const policy = useGuardedActionPolicy(action);
  return (
    <ConfirmActionModal
      {...rest}
      danger={policy.danger}
      requireReauth={policy.requireReauth}
      phrase={policy.phrase}
      canConfirm={canConfirm && policy.resolved}
      onConfirm={rest.onConfirm}
    />
  );
}
