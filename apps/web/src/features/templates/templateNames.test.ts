import { describe, expect, it } from 'vitest';
import {
  hasTemplateName,
  templateBaseId,
  templateDisplayName,
  templateName,
  templateVersion,
} from './templateNames';

describe('template display names', () => {
  it('names the template from the reported id and keeps the version parseable', () => {
    expect(templateDisplayName('assoc-ata-conselho-fiscal/v1')).toBe('Reunião do conselho fiscal');
    expect(templateBaseId('assoc-ata-conselho-fiscal/v1')).toBe('assoc-ata-conselho-fiscal');
    expect(templateVersion('assoc-ata-conselho-fiscal/v1')).toBe('v1');
  });

  it('covers every family of the built-in catalog', () => {
    expect(templateDisplayName('csc-ata-cessao-quotas/v1')).toBe('Ata de cessão de quotas');
    expect(templateDisplayName('condominio-ata-assembleia/v1')).toBe(
      'Ata de assembleia de condóminos',
    );
    expect(templateDisplayName('cooperativa-termo-abertura/v1')).toBe(
      'Termo de abertura do livro de atas',
    );
    expect(templateDisplayName('fundacao-certidao-ata/v1')).toBe('Certidão de ata');
  });

  it('carries the name across a future version of the same document type', () => {
    // Keyed on the base id, so a `/v2` inherits rather than silently falling back.
    expect(templateDisplayName('csc-ata-aprovacao-contas/v2')).toBe('Ata de aprovação de contas');
    expect(templateVersion('csc-ata-aprovacao-contas/v2')).toBe('v2');
  });

  it('falls back to the id for user-authored and unknown templates', () => {
    expect(hasTemplateName('user-minha-minuta/v1')).toBe(false);
    expect(templateName('user-minha-minuta/v1')).toBeUndefined();
    // Legible, never blank and never "undefined" — the id is what the template API keys on.
    expect(templateDisplayName('user-minha-minuta/v1')).toBe('user-minha-minuta/v1');
    expect(templateDisplayName('csc-ata-inventada-amanha/v9')).toBe('csc-ata-inventada-amanha/v9');
  });

  it('degrades on malformed ids instead of throwing', () => {
    expect(templateDisplayName('')).toBe('');
    expect(templateDisplayName('   ')).toBe('   ');
    expect(templateVersion('no-version-here')).toBeUndefined();
    expect(templateBaseId('  assoc-certidao-ata/v1  ')).toBe('assoc-certidao-ata');
  });
});
