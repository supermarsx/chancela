/**
 * The marking that keeps untranslated server prose honest in the ASiC inspector.
 *
 * `resolveAsicFinding` is unit-tested next to the catalog; this file covers the half that lives in
 * the DOM and that nothing else touches: **does an unmapped code actually reach the operator
 * wearing the `Em inglês` badge and `lang="en"`, and does a mapped one avoid both?**
 *
 * That is not cosmetic. The badge is the entire safety mechanism for every code the map does not
 * cover — today that is the whole 25-identifier `AsicDiagnosticBlockerId` vocabulary, which the
 * server pushes into this same list. Without it, English silently passes for localized copy.
 *
 * Nothing here asserts a pt-PT substring. Copy is asserted through the catalog objects, or through
 * the stable `data-finding-text` attribute — a test that typed the sentence in would pass just as
 * happily if the sentence rendered from the wrong locale tier
 * (the rule `BuildProvenanceRows.test.tsx` already follows).
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { Wrapper } from '../../test/utils';
import { ptPT } from '../../i18n/locales/pt-PT';
import type { AsicInspectionFinding } from '../../api/types';
import { FindingsList } from './AsicSignatureInspectorPanel';

afterEach(cleanup);

function finding(over: Partial<AsicInspectionFinding>): AsicInspectionFinding {
  return { severity: 'info', code: 'technical_scope_only', message: 'server English', ...over };
}

/** The `<p>` carrying one finding's sentence, keyed by which arm produced it. */
function sentence(kind: 'translated' | 'framed' | 'untranslated'): HTMLElement {
  const el = document.querySelector(`[data-finding-text="${kind}"]`);
  expect(el, `no finding rendered through the "${kind}" arm`).not.toBeNull();
  return el as HTMLElement;
}

describe('a finding whose code this build knows', () => {
  it('renders the catalog sentence with no English marking anywhere', () => {
    render(
      <Wrapper>
        <FindingsList findings={[finding({ code: 'xades_not_supported' })]} />
      </Wrapper>,
    );

    const p = sentence('translated');
    expect(p.textContent).toBe(ptPT['asicInspector.finding.xades_not_supported']);
    // The server's English is gone, not merely hidden behind it.
    expect(p.textContent).not.toContain('server English');
    expect(p.querySelector('[lang="en"]')).toBeNull();
    expect(screen.queryByText(ptPT['asicInspector.untranslatedBadge'])).toBeNull();
  });

  it('still shows the raw code, which is an identifier and stays untranslated', () => {
    render(
      <Wrapper>
        <FindingsList findings={[finding({ code: 'xades_not_supported' })]} />
      </Wrapper>,
    );
    expect(screen.getByText('xades_not_supported')).toBeTruthy();
  });
});

describe('a finding whose code this build does NOT know', () => {
  // Exactly the shape `append_blocker_findings` produces: a blocker identifier as the code, with
  // the blocker's own English message.
  const unknown = finding({
    severity: 'warning',
    code: 'asic_e_manifest_digest_mismatch',
    message: 'An ASiC-E manifest payload digest did not match the packaged payload bytes.',
  });

  it('marks the sentence lang="en" so a screen reader does not read it as Portuguese', () => {
    render(
      <Wrapper>
        <FindingsList findings={[unknown]} />
      </Wrapper>,
    );
    const marked = sentence('untranslated').querySelector('[lang="en"]');
    expect(marked).not.toBeNull();
    expect(marked?.textContent).toBe(unknown.message);
  });

  it('shows the badge, so English is never passed off as localized copy', () => {
    render(
      <Wrapper>
        <FindingsList findings={[unknown]} />
      </Wrapper>,
    );
    expect(screen.getByText(ptPT['asicInspector.untranslatedBadge'])).toBeTruthy();
  });
});

describe('a finding framed around the validator its own words', () => {
  const reasons =
    'META-INF/signature001.p7s: signed digest does not match packaged payload; ' +
    'META-INF/ASiCManifest.xml: referenced payload content.pdf is absent';
  const framed = finding({
    severity: 'error',
    code: 'asic_invalid_local_technical',
    message: reasons,
  });

  it('marks ONLY the validator reasons as English, not the Portuguese frame', () => {
    render(
      <Wrapper>
        <FindingsList findings={[framed]} />
      </Wrapper>,
    );
    const p = sentence('framed');
    const marked = p.querySelectorAll('[lang="en"]');

    // One marked span, and it is exactly the validator's text — no more, no less. Marking the
    // whole paragraph would misreport the frame; marking nothing is the defect this replaced.
    expect(marked.length).toBe(1);
    expect(marked[0].textContent).toBe(reasons);

    // The frame around it is real prose and is NOT inside the marked span.
    const frame = p.textContent?.replace(reasons, '') ?? '';
    expect(frame.trim().length).toBeGreaterThan(0);
    expect(p.textContent).toBe(
      ptPT['asicInspector.finding.asic_invalid_local_technical'].replace('{reasons}', reasons),
    );
  });

  it('does not badge a framed finding, because the frame really is translated', () => {
    render(
      <Wrapper>
        <FindingsList findings={[framed]} />
      </Wrapper>,
    );
    expect(screen.queryByText(ptPT['asicInspector.untranslatedBadge'])).toBeNull();
  });

  it('degrades to the marked-English arm when the validator sent no reasons', () => {
    render(
      <Wrapper>
        <FindingsList findings={[finding({ code: 'asic_invalid_local_technical', message: '' })]} />
      </Wrapper>,
    );
    // A frame ending in "…pelo validador:" with nothing after it reads as a broken UI and hides
    // that the server sent us nothing.
    expect(document.querySelector('[data-finding-text="framed"]')).toBeNull();
    expect(sentence('untranslated')).toBeTruthy();
  });
});
