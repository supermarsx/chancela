import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { PermissionScope } from '../../api/types';

const hookData = vi.hoisted(() => ({
  entities: [
    { id: 'E1', tenant_id: 'T1', name: 'Entidade Um' },
    { id: 'E2', tenant_id: 'T2', name: 'Entidade Dois' },
  ],
  books: [
    { id: 'B1', entity_id: 'E1', purpose: 'Assembleias gerais' },
    { id: 'B2', entity_id: 'E2', purpose: null },
  ],
}));

vi.mock('../../api/hooks', () => ({
  useEntities: () => ({ data: hookData.entities }),
  useBooks: () => ({ data: hookData.books }),
}));

import { ScopePicker } from './ScopePicker';

afterEach(cleanup);
beforeEach(() => {
  hookData.entities = [
    { id: 'E1', tenant_id: 'T1', name: 'Entidade Um' },
    { id: 'E2', tenant_id: 'T2', name: 'Entidade Dois' },
  ];
  hookData.books = [
    { id: 'B1', entity_id: 'E1', purpose: 'Assembleias gerais' },
    { id: 'B2', entity_id: 'E2', purpose: null },
  ];
});

function renderPicker(value: PermissionScope, onChange = vi.fn()) {
  return {
    onChange,
    ...render(<ScopePicker value={value} onChange={onChange} idPrefix="scope-test" />),
  };
}

describe('ScopePicker complete scope contract', () => {
  it('offers every frozen scope kind and derives selectable tenants from entities', () => {
    const { onChange } = renderPicker({ kind: 'global' });
    const kind = screen.getByLabelText('Âmbito') as HTMLSelectElement;
    expect([...kind.options].map((option) => option.value)).toEqual([
      'global',
      'tenant',
      'entity',
      'book',
      'act',
      'folder',
      'template_library',
      'archive',
      'integration',
      'repository',
    ]);

    fireEvent.change(kind, { target: { value: 'tenant' } });
    expect(onChange).toHaveBeenCalledWith({ kind: 'tenant', id: 'T1' });
  });

  it('backfills stale tenant, entity, and book ids only from loaded resources', async () => {
    const tenant = renderPicker({ kind: 'tenant', id: 'missing' });
    await waitFor(() => expect(tenant.onChange).toHaveBeenCalledWith({ kind: 'tenant', id: 'T1' }));
    tenant.unmount();

    const entity = renderPicker({ kind: 'entity', id: 'missing' });
    await waitFor(() => expect(entity.onChange).toHaveBeenCalledWith({ kind: 'entity', id: 'E1' }));
    entity.unmount();

    const book = renderPicker({ kind: 'book', id: 'missing' });
    await waitFor(() => expect(book.onChange).toHaveBeenCalledWith({ kind: 'book', id: 'B1' }));
  });

  it('emits entity and book choices with their human resource labels', () => {
    const entity = renderPicker({ kind: 'entity', id: 'E1' });
    const entitySelect = screen.getByLabelText('Escolher entidade') as HTMLSelectElement;
    expect([...entitySelect.options].map((option) => option.text)).toEqual([
      'Entidade Um',
      'Entidade Dois',
    ]);
    fireEvent.change(entitySelect, { target: { value: 'E2' } });
    expect(entity.onChange).toHaveBeenCalledWith({ kind: 'entity', id: 'E2' });
    entity.unmount();

    const book = renderPicker({ kind: 'book', id: 'B1' });
    const bookSelect = screen.getByLabelText('Escolher livro') as HTMLSelectElement;
    expect([...bookSelect.options].map((option) => option.text)).toEqual([
      'Assembleias gerais',
      'B2',
    ]);
    fireEvent.change(bookSelect, { target: { value: 'B2' } });
    expect(book.onChange).toHaveBeenCalledWith({ kind: 'book', id: 'B2' });
  });

  it('keeps unsupported resource ids explicit instead of inventing a parent relation', () => {
    const { onChange } = renderPicker({ kind: 'template_library', id: '' });
    const resource = screen.getByLabelText('Identificador do recurso');
    fireEvent.change(resource, { target: { value: 'library-uuid' } });
    expect(onChange).toHaveBeenCalledWith({ kind: 'template_library', id: 'library-uuid' });
    expect(screen.getByText(/hierarquia autorizada/)).toBeTruthy();
  });
});
