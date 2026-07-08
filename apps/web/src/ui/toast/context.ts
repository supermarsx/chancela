/**
 * The toast context. Kept in its own module (separate from the provider component) so
 * both `ToastProvider` and `useToast` import the same reference without a circular file
 * dependency, and so the provider file can stay Fast-Refresh-clean (component-only).
 *
 * The default is `null`: `useToast()` reads it and throws when no provider is mounted,
 * which fails loud during development rather than silently dropping notifications.
 */
import { createContext } from 'react';
import type { ToastHandle } from './types';

export const ToastContext = createContext<ToastHandle | null>(null);
