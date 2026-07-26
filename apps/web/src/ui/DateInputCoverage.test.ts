import { describe, expect, it } from 'vitest';

const FEATURE_SOURCES = import.meta.glob('../features/**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

const DATE_CONTROL = /<(?<component>input|Input)\b(?=[^>]*\btype\s*=\s*["']date["'])[^>]*>/giu;

describe('shared date input adoption', () => {
  it('routes every production date-only control through Input and its adjacent Today action', () => {
    const nativeDateInputs: string[] = [];
    let sharedDateInputs = 0;

    for (const [path, rawSource] of Object.entries(FEATURE_SOURCES)) {
      const source = rawSource.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/^\s*\/\/.*$/gmu, '');
      for (const match of source.matchAll(DATE_CONTROL)) {
        if (match.groups?.component === 'Input') sharedDateInputs += 1;
        else nativeDateInputs.push(path);
      }
    }

    expect(sharedDateInputs).toBeGreaterThan(0);
    expect(nativeDateInputs).toEqual([]);
  });
});
