/**
 * The toast accessor hook. Returns the stable {@link ToastHandle} from the nearest
 * {@link ToastProvider}. Throws when no provider is mounted (fail loud) so a missing
 * provider surfaces in development instead of silently swallowing notifications.
 */
import { useContext } from 'react';
import { ToastContext } from './context';
import type { ToastHandle } from './types';

export function useToast(): ToastHandle {
  const handle = useContext(ToastContext);
  if (!handle) {
    throw new Error('useToast must be used within a <ToastProvider>');
  }
  return handle;
}
