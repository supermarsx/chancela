/**
 * Structural guards on the `InlineWarning` dismiss capability (t75).
 *
 * The capability makes the *default* safe — a banner with no `notice` key has no dismiss control
 * and no registry entry. These rules police the other direction: what a banner that DOES name a
 * key is allowed to be. They encode the criterion the team adopted for opting one in:
 *
 *   dismissable only if (a) it renders unconditionally — it is not reporting a state — and
 *   (b) hiding it loses nothing unreachable elsewhere;
 *   with one-time secrets, incomplete-results warnings, no-claim disclaimers and
 *   `aria-describedby` targets as automatic disqualifiers.
 *
 * (a) and (b) need a human. Two of the disqualifiers do not, and those are the two mechanised here.
 *
 * This walks the TypeScript AST rather than the source text on purpose. The question "is this
 * disclaimer inside a dismissable banner?" is about containment, and a line-based search cannot see
 * containment — it would match a `noClaims` key three elements away from the banner that will
 * actually hide it, and miss one nested two levels deep inside the banner that will.
 */
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

interface Offence {
  file: string;
  line: number;
  detail: string;
}

/** Every `<InlineWarning …>` in a production file, with its opening tag and its full subtree. */
function eachInlineWarning(
  visit: (
    opening: ts.JsxOpeningLikeElement,
    node: ts.Node,
    file: string,
    source: ts.SourceFile,
  ) => void,
): void {
  for (const [file, source] of Object.entries(PRODUCTION_SOURCES)) {
    if (/\.(?:test|spec)\.tsx$/u.test(file)) continue;
    const parsed = ts.createSourceFile(
      file,
      source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TSX,
    );
    const inspect = (node: ts.Node): void => {
      const opening = ts.isJsxElement(node)
        ? node.openingElement
        : ts.isJsxSelfClosingElement(node)
          ? node
          : undefined;
      if (opening && ts.isIdentifier(opening.tagName) && opening.tagName.text === 'InlineWarning') {
        visit(opening, node, file, parsed);
      }
      ts.forEachChild(node, inspect);
    };
    inspect(parsed);
  }
}

function attribute(opening: ts.JsxOpeningLikeElement, name: string): ts.JsxAttribute | undefined {
  return opening.attributes.properties.find(
    (property): property is ts.JsxAttribute =>
      ts.isJsxAttribute(property) && ts.isIdentifier(property.name) && property.name.text === name,
  );
}

/** The attribute's value when it is a plain string literal (`tone="info"`), else undefined. */
function literalValue(attr: ts.JsxAttribute | undefined): string | undefined {
  const initializer = attr?.initializer;
  if (initializer && ts.isStringLiteral(initializer)) return initializer.text;
  if (
    initializer &&
    ts.isJsxExpression(initializer) &&
    initializer.expression &&
    ts.isStringLiteralLike(initializer.expression)
  ) {
    return initializer.expression.text;
  }
  return undefined;
}

function lineOf(node: ts.Node, source: ts.SourceFile): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

describe('InlineWarning dismiss capability — structural guards', () => {
  it('never lets a dismissable banner carry a fail-closed tone', () => {
    const offences: Offence[] = [];
    eachInlineWarning((opening, _node, file, source) => {
      const notice = attribute(opening, 'notice');
      if (!notice) return;
      const tone = literalValue(attribute(opening, 'tone'));
      if (tone !== 'info') {
        offences.push({
          file,
          line: lineOf(opening, source),
          detail: `notice=${literalValue(notice) ?? '?'} with tone=${tone ?? 'warn (default)'}`,
        });
      }
    });

    expect(
      offences,
      'A banner an operator may permanently hide is, by definition, not reporting a blocking ' +
        'state — so it is toned `info`. A warn/error banner that acquired a notice key is either ' +
        'miscoloured or must not be dismissable; decide which, do not silence this.',
    ).toEqual([]);
  });

  it('never lets a no-claims disclaimer sit inside a dismissable banner', () => {
    const offences: Offence[] = [];
    eachInlineWarning((opening, node, file, source) => {
      if (!attribute(opening, 'notice')) return;
      const inspect = (child: ts.Node): void => {
        if (ts.isStringLiteralLike(child) && /noclaim/i.test(child.text)) {
          offences.push({
            file,
            line: lineOf(child, source),
            detail: `${child.text} is inside a dismissable banner`,
          });
        }
        ts.forEachChild(child, inspect);
      };
      inspect(node);
    });

    expect(
      offences,
      'A statement about what the product does NOT claim inherits the treatment of whatever ' +
        'banner encloses it. Bundled inside a dismissable one it becomes switchable by accident. ' +
        'Give it its own banner with no notice key (see ExternalValidatorReportsPanel).',
    ).toEqual([]);
  });

  it('scans a realistic number of banners, so a broken walker cannot pass vacuously', () => {
    let total = 0;
    let dismissable = 0;
    eachInlineWarning((opening) => {
      total += 1;
      if (attribute(opening, 'notice')) dismissable += 1;
    });
    // Both bounds matter: zero banners would mean the glob or the walker broke, and the whole
    // point of the capability is that opting in stays rare and deliberate.
    expect(total).toBeGreaterThan(200);
    expect(dismissable).toBeGreaterThan(0);
    expect(dismissable).toBeLessThan(20);
  });
});
