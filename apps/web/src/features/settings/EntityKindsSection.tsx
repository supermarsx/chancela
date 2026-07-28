/**
 * Which entity legal types this instance may **register** — the Configurações card over
 * `settings.entities.enabled_kinds` (t54 §6.5).
 *
 * ## An admissions policy at the front door, not a statement about the archive
 *
 * Narrowing the list gates **creation only**. It never gates read, list, filter, export or render:
 * entities already registered under a type that is later switched off stay listed and editable,
 * their books and acts keep working, the entities page's kind filter still offers all ten types,
 * and every sealed act is untouched (`EntityKind` is baked into `ActSealMetadata.profile`). The
 * server is the enforcement point — `ensure_entity_kind_enabled` guards both creation paths, the
 * manual `POST /v1/entities` and the certidão-permanente import — so what this card does to the
 * create form is a courtesy, not the control.
 *
 * ## "Todos os tipos" is a named state, never an empty selection (§6.5.1)
 *
 * On the wire `[]` means **every kind**. That reading is load-bearing (it is what makes an existing
 * `settings.json` need no migration and keeps the slice off the wire at its default), but it means
 * the document cannot distinguish "reset to all" from "disable all" — so an administrator who
 * unticked everything expecting *nothing* would get *everything*, an inversion of intent on an
 * access-control decision.
 *
 * The fix is to make the intended state **nameable**, which is what the two radios do: choosing
 * "Todos os tipos" submits `[]` deliberately, and the grid is never the thing that says "all" by
 * accident. Blocking an empty save is the weaker half and is here too, not instead: under "Apenas
 * os tipos selecionados" the last remaining tick cannot be removed, and the refusal points at the
 * radio above rather than leaving the operator to guess. Switching *into* "apenas os selecionados"
 * seeds every type ticked, so a zero-tick draft never exists to be autosaved in the first place.
 *
 * "No kind at all" therefore stays unrepresentable, exactly as the server's own defensive 422 for
 * it says it is.
 *
 * ## Switching a type off that already has records
 *
 * Consequential, not destructive — nothing is deleted, nothing is revoked, only future
 * registrations stop. So it goes through the shared {@link ConfirmActionModal} at t56's **T1 with
 * `danger: false`**: a real acknowledgement, with the record count and the reassurance stated, and
 * none of the red destructive vocabulary. Dressing an ordinary administrative choice as destruction
 * is how operators are trained to click through the guards that matter.
 *
 * The counts come from the entities list the app already loads. If that query is unavailable to the
 * acting user the card simply shows no counts and no acknowledgement gate: an absent count is
 * stated by omission, never guessed at, and the server still refuses a disabled kind either way.
 *
 * ## No family-level "toggle all"
 *
 * §6.5 offered one as sugar. It is deliberately not here: unticking a family in one gesture would
 * either bypass the per-type acknowledgement above — which is binding — or stack up to six modals
 * for one click. Four of the five families hold a single type, where the control would have been a
 * second checkbox for the row directly beneath it. The grouping (which is what makes ten types
 * readable) is kept; only the bulk switch is not.
 */
import { useMemo, useState } from 'react';
import { useEntities } from '../../api/hooks';
import { entityFamilyLabels, entityKindLabels } from '../../api/labels';
import {
  ENTITY_FAMILIES,
  ENTITY_KINDS,
  ENTITY_KIND_FAMILY,
  type EntitiesSettings,
  type EntityKind,
} from '../../api/types';
import { useEntityKindsT } from '../../i18n/entityKindsFallback';
import { Card, ConfirmActionModal } from '../../ui';
import { ColumnToggleGrid } from '../tableColumns/ColumnToggleGrid';

/** The two named states. `all` is `enabled_kinds: []`; `selected` is a non-empty explicit list. */
type Mode = 'all' | 'selected';

/** The types of each family, in the canonical `ENTITY_KINDS` order. */
const FAMILY_KINDS = ENTITY_FAMILIES.map(
  (family) => [family, ENTITY_KINDS.filter((kind) => ENTITY_KIND_FAMILY[kind] === family)] as const,
);

export function EntityKindsSection({
  value,
  onChange,
}: {
  value: EntitiesSettings;
  onChange: (next: EntitiesSettings) => void;
}) {
  const kt = useEntityKindsT();
  const entities = useEntities();
  const [mode, setMode] = useState<Mode>(value.enabled_kinds.length === 0 ? 'all' : 'selected');
  /** Set when a removal was refused for emptying the selection; cleared by the next real change. */
  const [emptyRefused, setEmptyRefused] = useState(false);
  /** The type awaiting the T1 acknowledgement, if any. */
  const [pendingDisable, setPendingDisable] = useState<EntityKind | null>(null);

  // How many registered entities carry each type. `undefined` — not zero — while the list has not
  // resolved or is not readable by this user: "we do not know" and "there are none" are different
  // answers and only one of them may suppress the acknowledgement gate.
  const counts = useMemo<Partial<Record<EntityKind, number>> | undefined>(() => {
    if (!entities.isSuccess) return undefined;
    const tally: Partial<Record<EntityKind, number>> = {};
    for (const entity of entities.data) tally[entity.kind] = (tally[entity.kind] ?? 0) + 1;
    return tally;
  }, [entities.isSuccess, entities.data]);

  // In "todos" the grid is inert and shows every type ticked, because that is what is in force.
  const selected = value.enabled_kinds;
  const isEnabled = (kind: EntityKind) => mode === 'all' || selected.includes(kind);

  const setKinds = (next: readonly EntityKind[]) => {
    setEmptyRefused(false);
    onChange({ enabled_kinds: [...next] });
  };

  const chooseMode = (next: Mode) => {
    if (next === mode) return;
    setMode(next);
    setPendingDisable(null);
    // → todos: `[]`, chosen by name. → apenas: seed with every type, so the operator narrows down
    // from a complete list and no empty intermediate state is ever written to the draft.
    setKinds(next === 'all' ? [] : ENTITY_KINDS);
  };

  const toggleKind = (kind: EntityKind, checked: boolean) => {
    if (mode !== 'selected') return;
    if (checked) {
      setKinds(
        ENTITY_KINDS.filter((candidate) => candidate === kind || selected.includes(candidate)),
      );
      return;
    }
    const next = selected.filter((candidate) => candidate !== kind);
    // Never submit an empty selection as a narrowing: `[]` is the every-kind default, so writing it
    // here would silently mean the opposite of what the operator just did.
    if (next.length === 0) {
      setEmptyRefused(true);
      return;
    }
    if ((counts?.[kind] ?? 0) > 0) {
      setPendingDisable(kind);
      return;
    }
    setKinds(next);
  };

  const pendingCount = pendingDisable ? (counts?.[pendingDisable] ?? 0) : 0;

  return (
    <Card title={kt('entityKinds.card.title')}>
      <div className="form settings-rows">
        <p className="field__hint">{kt('entityKinds.card.hint')}</p>

        <fieldset className="field">
          <legend className="field__label">{kt('entityKinds.mode.legend')}</legend>
          <label className="checkline">
            <input
              type="radio"
              name="entity-kinds-mode"
              checked={mode === 'all'}
              onChange={() => chooseMode('all')}
            />
            {kt('entityKinds.mode.all')}
          </label>
          <p className="field__hint">{kt('entityKinds.mode.all.hint')}</p>
          <label className="checkline">
            <input
              type="radio"
              name="entity-kinds-mode"
              checked={mode === 'selected'}
              onChange={() => chooseMode('selected')}
            />
            {kt('entityKinds.mode.selected')}
          </label>
          <p className="field__hint">{kt('entityKinds.mode.selected.hint')}</p>
        </fieldset>

        {emptyRefused ? (
          <p className="field__error" role="alert">
            {kt('entityKinds.empty.error')}
          </p>
        ) : null}

        <div className="stack--tight" role="group" aria-label={kt('entityKinds.grid.aria')}>
          {FAMILY_KINDS.map(([family, kinds], index) => (
            <div key={family}>
              <p className="field__label">{entityFamilyLabels[family]}</p>
              <ColumnToggleGrid
                columns={kinds}
                showHead={index === 0}
                headers={{
                  name: kt('entityKinds.head.kind'),
                  toggle: kt('entityKinds.head.available'),
                }}
                isVisible={isEnabled}
                isDisabled={() => mode === 'all'}
                onToggle={toggleKind}
                columnLabel={(kind) => entityKindLabels[kind]}
                note={(kind) => {
                  const count = counts?.[kind] ?? 0;
                  if (count === 0) return null;
                  return (
                    <span className="muted">
                      {count === 1
                        ? kt('entityKinds.inUse.badge.one')
                        : kt('entityKinds.inUse.badge.many', { count })}
                    </span>
                  );
                }}
              />
            </div>
          ))}
        </div>
      </div>

      <ConfirmActionModal
        open={pendingDisable !== null}
        onClose={() => setPendingDisable(null)}
        title={kt('entityKinds.inUse.title')}
        danger={false}
        intro={
          <div className="stack--tight">
            <p>
              {pendingCount === 1
                ? kt('entityKinds.inUse.body.one')
                : kt('entityKinds.inUse.body.many', { count: pendingCount })}
            </p>
            <p>{kt('entityKinds.inUse.reassurance')}</p>
          </div>
        }
        confirmLabel={kt('entityKinds.inUse.confirm')}
        pendingLabel={kt('entityKinds.inUse.pending')}
        onConfirm={async () => {
          const kind = pendingDisable;
          if (!kind) return;
          setKinds(selected.filter((candidate) => candidate !== kind));
        }}
      />
    </Card>
  );
}
