/**
 * A single top-bar overflow dropdown (t42) — the burger that holds the primary tabs, and the
 * "more" menu that holds the utility glyphs, are both this component with different items.
 *
 * The app has no shared Menu/Popover primitive; the established convention is a hand-rolled popover
 * per surface (see {@link import('../features/session/CurrentUserPicker').CurrentUserPicker} and
 * {@link import('../features/notifications/NotificationBell').NotificationBell}). This mirrors that
 * proven pattern — an `aria-haspopup="menu"` trigger, a `role="menu"` panel of `role="menuitem"`
 * links, a full-screen backdrop for outside-click, Escape-to-close, roving arrow-key focus, and
 * focus returned to the trigger on close — factored once so the two triggers stay identical rather
 * than being invented twice.
 *
 * It is driven entirely by its `items` prop, so a control added to the bar's arrays (e.g. a later
 * admin glyph) flows into the overflow menu with no change here.
 *
 * Motion: the panel's entrance is a CSS animation on `.topbar__menu-panel`, which collapses to an
 * instant show under both global kill-switches (`prefers-reduced-motion` and `[data-safe-mode]`),
 * so no reduced-motion handling is needed in this file.
 */
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { NavLink } from 'react-router-dom';

export interface TopbarMenuItem {
  to: string;
  /** The resolved, translated, accessible label — also the visible text. */
  label: string;
  /** Optional leading glyph (the utility menu shows one; the tab burger does not). */
  icon?: ReactNode;
  /** Exact-match routing, as `NavLink`'s `end`. */
  end?: boolean;
  /** Whether this item addresses the current page (drives `aria-current` + the lit state). */
  active: boolean;
}

interface TopbarMenuProps {
  /** Accessible name for both the trigger button and the menu. */
  label: string;
  /** The trigger glyph (burger or more-dots). */
  icon: ReactNode;
  items: TopbarMenuItem[];
  /** Which edge the panel aligns to — `start` for the left-hand burger, `end` for the right. */
  align?: 'start' | 'end';
  /** Whether the current page lives behind this menu, so the trigger lights like an active tab. */
  active?: boolean;
  testId?: string;
}

export function TopbarMenu({
  label,
  icon,
  items,
  align = 'start',
  active = false,
  testId,
}: TopbarMenuProps) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const close = useCallback((returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) triggerRef.current?.focus();
  }, []);

  /** The `role="menuitem"` links currently rendered in the open panel. */
  const menuItems = useCallback((): HTMLElement[] => {
    const root = menuRef.current;
    if (!root) return [];
    return Array.from(root.querySelectorAll<HTMLElement>('[role="menuitem"]'));
  }, []);

  // Close on Escape (and stop it bubbling to any outer Escape handler), returning focus to the
  // trigger so the keyboard user is not stranded.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        close(true);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, close]);

  // On open, move focus to the active item (or the first) — the ARIA menu pattern's initial focus.
  useEffect(() => {
    if (!open) return;
    const els = menuItems();
    if (els.length === 0) return;
    const current = els.find((el) => el.getAttribute('aria-current') === 'page');
    (current ?? els[0]).focus();
  }, [open, menuItems]);

  // Roving focus: Arrow keys step between items (wrapping), Home/End jump to the ends.
  function onMenuKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    const { key } = e;
    if (key !== 'ArrowDown' && key !== 'ArrowUp' && key !== 'Home' && key !== 'End') return;
    const els = menuItems();
    if (els.length === 0) return;
    e.preventDefault();
    const at = els.indexOf(document.activeElement as HTMLElement);
    let next: number;
    if (key === 'Home') next = 0;
    else if (key === 'End') next = els.length - 1;
    else if (key === 'ArrowDown') next = at < 0 ? 0 : (at + 1) % els.length;
    else next = at < 0 ? els.length - 1 : (at - 1 + els.length) % els.length;
    els[next].focus();
  }

  return (
    <div className="topbar__menu">
      <button
        ref={triggerRef}
        type="button"
        data-testid={testId}
        className={`topbar__menu-trigger topbar__icon btn btn--ghost btn--icon btn--iconOnly${
          active ? ' is-active' : ''
        }`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="btn__icon" aria-hidden="true">
          {icon}
        </span>
      </button>

      {open ? (
        <>
          <div className="topbar__menu-backdrop" aria-hidden="true" onClick={() => close(false)} />
          <div
            ref={menuRef}
            className="topbar__menu-panel"
            role="menu"
            aria-label={label}
            data-align={align}
            onKeyDown={onMenuKeyDown}
          >
            {items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                role="menuitem"
                aria-current={item.active ? 'page' : undefined}
                className={`topbar__menu-item${item.active ? ' is-active' : ''}`}
                onClick={() => close(false)}
              >
                {item.icon ? (
                  <span className="topbar__menu-item-icon btn__icon" aria-hidden="true">
                    {item.icon}
                  </span>
                ) : null}
                <span className="topbar__menu-item-label">{item.label}</span>
              </NavLink>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}
