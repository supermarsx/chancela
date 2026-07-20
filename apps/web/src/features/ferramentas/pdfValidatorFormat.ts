/**
 * Pure presentation helpers for the PDF/PAdES validation report.
 *
 * They live outside `PdfSignatureValidatorPanel` so that the result table can use them
 * without the panel and the table importing each other. The panel re-exports them, which
 * is the surface the existing helper tests import.
 */
import type { PdfValidationStatus } from '../../api/types';
import type { TFunction } from '../../i18n';

export function formatPdfValidatorBytes(value: number, t: TFunction): string {
  if (!Number.isFinite(value) || value < 0) return t('pdfValidator.size.unknown');
  if (value < 1024) return `${value} bytes`;
  const units = ['KB', 'MB', 'GB'];
  let amount = value;
  let unit = 'bytes';
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  return `${amount.toFixed(amount < 10 ? 1 : 0)} ${unit}`;
}

export function pdfValidatorBoolText(value: boolean, t: TFunction): string {
  return value ? t('common.yes') : t('common.no');
}

export function pdfValidationStatusTone(
  status: PdfValidationStatus,
): 'neutral' | 'ok' | 'warn' | 'error' {
  if (status === 'valid') return 'ok';
  if (status === 'invalid') return 'error';
  if (status === 'indeterminate') return 'warn';
  return 'neutral';
}

export function pdfValidationStatusLabel(status: PdfValidationStatus, t: TFunction): string {
  if (status === 'valid') return t('pdfValidator.status.valid');
  if (status === 'invalid') return t('pdfValidator.status.invalid');
  if (status === 'indeterminate') return t('pdfValidator.status.indeterminate');
  return t('pdfValidator.status.unsigned');
}

export function pdfValidationFindingTone(severity: string): 'neutral' | 'warn' | 'error' {
  if (severity === 'error') return 'error';
  if (severity === 'warning') return 'warn';
  return 'neutral';
}

export function pdfValidationEvidenceTone(status: string): 'neutral' | 'ok' | 'warn' | 'error' {
  const normalized = status.toLowerCase();
  if (normalized === 'valid' || normalized === 'available') return 'ok';
  if (normalized.includes('invalid') || normalized.includes('failed')) return 'error';
  if (normalized.includes('indeterminate') || normalized.includes('unavailable')) return 'warn';
  if (normalized.includes('unsupported') || normalized.includes('gap')) return 'warn';
  return 'neutral';
}
