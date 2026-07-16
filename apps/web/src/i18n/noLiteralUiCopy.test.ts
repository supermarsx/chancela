/**
 * Static JSX copy gate (UX-20 / apps/web/CONVENTIONS.md §8).
 *
 * Production TSX must route visible copy and accessibility names through the typed catalog. The
 * scanner deliberately targets JSX text plus string-valued user-facing props; it ignores code
 * samples and the two pre-i18n crash fallbacks documented by the convention.
 */
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;
const EXCLUDED_FILES = new Set(['CrashScreen.tsx', 'ErrorBoundary.tsx']);
const USER_FACING_ATTRIBUTES = new Set([
  'aria-label',
  'alt',
  'description',
  'emptyBody',
  'emptyTitle',
  'hint',
  'label',
  'lede',
  'placeholder',
  'title',
]);

// Project mark, data-format samples, and protocol tokens: these carry no translatable UI copy.
const REVIEWED_NEUTRAL_LITERALS = new Set([
  '-&gt;',
  '->',
  'ASiC',
  'C',
  'Chancela',
  'GenTime',
  'JSON',
  'PDF',
  'PT',
  'QTST',
  'eidas',
  's',
]);

function basename(file: string): string {
  return file.slice(file.lastIndexOf('/') + 1);
}

function normalizedCopy(value: string): string {
  return value.replace(/\s+/gu, ' ').trim();
}

function isInsideCode(node: ts.Node): boolean {
  for (let current = node.parent; current; current = current.parent) {
    if (
      ts.isJsxElement(current) &&
      ts.isIdentifier(current.openingElement.tagName) &&
      current.openingElement.tagName.text === 'code'
    ) {
      return true;
    }
  }
  return false;
}

function isReviewedNonCopy(value: string, node: ts.Node): boolean {
  if (value === '' || !/\p{L}/u.test(value) || REVIEWED_NEUTRAL_LITERALS.has(value)) return true;
  if (isInsideCode(node)) return true;
  // Rendered boolean/claim field names are evidence-schema tokens, not prose. Requiring an
  // underscore plus a delimiter avoids accidentally exempting an ordinary lowercase word.
  if (value.includes('_') && /[:=]/u.test(value)) return true;
  return false;
}

function location(sourceFile: ts.SourceFile, node: ts.Node): string {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return `${sourceFile.fileName.replace(/^\.\.\//u, '')}:${start.line + 1}:${start.character + 1}`;
}

describe('literal UI copy gate', () => {
  it('routes visible JSX copy and accessibility props through frozen translation keys', () => {
    const violations: string[] = [];

    for (const [file, source] of Object.entries(PRODUCTION_SOURCES)) {
      if (/\.(?:test|spec)\.tsx$/u.test(file) || EXCLUDED_FILES.has(basename(file))) continue;
      const sourceFile = ts.createSourceFile(
        file,
        source,
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TSX,
      );

      function inspect(node: ts.Node): void {
        if (ts.isJsxText(node)) {
          const value = normalizedCopy(node.text);
          if (!isReviewedNonCopy(value, node)) {
            violations.push(`${location(sourceFile, node)} JSX text ${JSON.stringify(value)}`);
          }
        } else if (
          ts.isJsxAttribute(node) &&
          ts.isIdentifier(node.name) &&
          USER_FACING_ATTRIBUTES.has(node.name.text) &&
          node.initializer &&
          ts.isStringLiteral(node.initializer)
        ) {
          const value = normalizedCopy(node.initializer.text);
          if (!isReviewedNonCopy(value, node)) {
            violations.push(
              `${location(sourceFile, node)} ${node.name.text}=${JSON.stringify(value)}`,
            );
          }
        } else if (
          ts.isJsxExpression(node) &&
          node.expression &&
          ts.isStringLiteralLike(node.expression)
        ) {
          const value = normalizedCopy(node.expression.text);
          if (!isReviewedNonCopy(value, node)) {
            violations.push(
              `${location(sourceFile, node)} JSX expression ${JSON.stringify(value)}`,
            );
          }
        }
        ts.forEachChild(node, inspect);
      }

      inspect(sourceFile);
    }

    expect(violations, violations.join('\n')).toEqual([]);
  }, 15_000);
});
