/**
 * Presentation helpers for the Chancela shell.
 *
 * `formatAtaNumber` renders the sequential ata number that the domain core assigns
 * when an act is sealed within its book (WFL-12). Numbering is per-book and never
 * reused; here we only format an already-assigned value for display in the active locale.
 */
import { t } from './i18n';

export function formatAtaNumber(sequence: number, year: number): string {
  if (!Number.isInteger(sequence) || sequence < 1) {
    throw new RangeError('Ata number must be a positive integer');
  }
  if (!Number.isInteger(year) || year < 1) {
    throw new RangeError('Year must be a positive integer');
  }
  const padded = String(sequence).padStart(4, '0');
  return t('format.ataNumber', { padded, year });
}
