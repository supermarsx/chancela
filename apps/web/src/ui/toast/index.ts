/**
 * Public toast surface (frozen contract, plan t44 §3.1). Consumers import from here:
 *
 *   import { useToast } from '../../ui/toast';
 *   const toast = useToast();
 *   toast.success(t('toast.entity.created'));
 *   try { await mutate(); } catch (e) { toast.error(e); }
 *
 * `ToastProvider` is mounted once, above the router, in `app/providers.tsx`.
 */
export { ToastProvider } from './ToastProvider';
export { useToast } from './useToast';
export type { ToastHandle, ToastOptions, ToastVariant } from './types';
