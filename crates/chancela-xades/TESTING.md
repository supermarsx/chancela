# `chancela-xades` — testing & interop certification

This document records how the crate's most safety-critical component — the XML canonicalizer that
feeds every XMLDSig/XAdES digest — is certified, and what remains deferred. Honesty over a forced
pass: where a live third-party tool was not available offline, this says so plainly and gives the
exact procedure to run it on a reference machine.

## C14N interop certification

### What the canonicalizer does (scope)

`src/c14n.rs` implements, in-crate over `quick-xml` raw events (prefix-preserving):

- **Exclusive XML Canonicalization 1.0** (`http://www.w3.org/2001/10/xml-exc-c14n#`, with and
  without comments), including the `InclusiveNamespaces` PrefixList — the XAdES/ASiC default.
- **Canonical XML 1.0** (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`, with and without
  comments) — inclusive form needed by some transforms.

It does **not** perform DTD processing: no `<!ATTLIST>` attribute defaulting, no DTD-declared general
entity expansion, and no attribute-type-driven (ID/IDREF/NMTOKENS) whitespace normalization
(`quick-xml` does not expand DTD entities). Any W3C worked example that relies on those features will
legitimately diverge; that is a documented scope limit, not a canonicalizer bug. This is acceptable
because XAdES/ASiC canonicalize `SignedInfo`, `SignedProperties`, and `Reference` targets — subtrees
that in this product's signing pipeline never carry DTD-defaulted attributes or DTD-declared
entities.

### The external oracle

`xmlsec1` and the EU DSS (Java) reference validator were **not available in this offline build
environment**, so **no live third-party tool run backs the committed bytes**. Instead the external
oracle used is **the standard itself** — the W3C RECs, which are offline-auditable:

- W3C **Canonical XML 1.0** REC — `xml-c14n-20010315`.
- W3C **Exclusive XML Canonicalization 1.0** REC — `xml-exc-c14n-20020718`.

Every vector's `.meta.json` now carries an auditable `provenance` string (and a `rule` one-liner),
and `tests/c14n_vectors.rs` fails any vector that lacks one. The vectors fall into two
honestly-labelled classes.

#### Class 1 — verbatim-REC worked examples (transcribed byte-for-byte from a REC section)

These are the strongest anchors: the input **and** expected output are transcribed directly from a
published REC worked example, so the expected bytes are the standard's own bytes.

| Vector | REC source | Notes |
|--------|-----------|-------|
| `v18_rec_3_4_char_modifications` | Canonical XML 1.0 §3.4 | Character modifications / references: CR preserved as `&#xD;`, LF char-ref → literal newline, CDATA folded and re-escaped, attribute-value escaping. Transcribed for the DTD-type-independent elements (`text`, `value`, `compute`, `norm`); the example's `normNames`/`normId` lines are omitted because they depend on DTD-declared NMTOKENS/ID attribute types this canonicalizer does not process. |
| `v19_rec_3_3_ns_attr_ordering` | Canonical XML 1.0 §3.3 | The `e5` element, verbatim: namespace declarations first (default then by prefix), then attributes sorted by (namespace URI, local name). The surrounding example's `e9` element is omitted (DTD ATTLIST default). |
| `v20_rec_3_2_whitespace_content` | Canonical XML 1.0 §3.2 | Whitespace in document content preserved byte-for-byte; only the omitted line is the XML declaration (which canonicalization removes). |

#### Class 2 — hand-derived-from-rule (expected bytes computed by hand from a cited REC rule)

`v01`–`v17` were authored to exercise a specific canonicalization rule; their expected `.out` was
**computed by hand from the cited REC rule, not produced by a third-party tool**. Each `provenance`
string names the exact REC section (Canonical XML 1.0 or Exclusive C14N 1.0) and states this
explicitly. They cover exclusive-C14N unused-namespace pruning (`v05`), prefix pull-down (`v06`),
`InclusiveNamespaces` PrefixList (`v07`), default-namespace retention/undeclaration/pruning
(`v08`,`v09`,`v11`,`v12`), Id-subtree apex rendering under both algorithms (`v13`,`v14`), attribute
sorting and empty-element expansion (`v01`), whitespace preservation (`v02`), text and
attribute-value escaping (`v03`,`v04`), comment strip/keep (`v10`,`v17`), line-ending normalization
with `&#xD;` preservation (`v15`), and in-content PI handling (`v16`). These specifically exercise
the subtle prefix pull-down / default-ns undeclaration surface called out as the top namespace risk.

### Known scope limits (documented, not fixed — `c14n.rs` emit is frozen)

- **Root-level PI/comment whitespace normalization.** Canonical XML 1.0 §3.1 (PIs, comments, and
  nodes outside the document element) was transcribed and **run** against the frozen `c14n.rs`; it
  **diverges** and is therefore intentionally **not committed** as a vector. The divergence is in
  processing-instruction whitespace: the REC normalizes the whitespace between a PI target and its
  data to a single space and strips the trailing whitespace of a data-less PI
  (`<?xml-stylesheet   href=…?>` → `<?xml-stylesheet href=…?>`, `<?pi-without-data     ?>` →
  `<?pi-without-data?>`), whereas this canonicalizer preserves the source whitespace. Root-level
  PI/comment *positioning* (leading/trailing newline placement) is supported and matches the REC.
  This gap does not affect XAdES/ASiC signatures: the canonicalized `SignedInfo`/`SignedProperties`
  cores do not contain such processing instructions. Fixing it would be a `c14n.rs` emit change (PI
  whitespace normalization in the parse/emit path) and, because a c14n emit change ripples into every
  digest, must be adjudicated by the track lead — it was **not** made under this task.
- **DTD-dependent behaviour** (attribute defaulting, ID/NMTOKENS normalization, DTD entity
  expansion) is out of scope as described above.

### Manual conformance procedure (run on a reference machine that HAS `xmlsec1` / EU DSS)

When a machine with `xmlsec1` (and optionally the EU DSS) is available, a maintainer should
cross-check the committed bytes and a live-signed document. No Java or native runtime dependency is
added to CI; this is a manual, recorded step.

1. **Per-vector C14N cross-check.** For each fixture, canonicalize the input with `xmlsec1` and
   diff against the committed `.out`. Exclusive vs inclusive and with/without comments follow the
   vector's `algorithm`:

   ```sh
   # exclusive, without comments (the XAdES/ASiC default)
   xmlsec1 --c14n-exc   tests/fixtures/c14n/v05_exclusive_prune_unused.in.xml \
     | cmp - tests/fixtures/c14n/v05_exclusive_prune_unused.out

   # inclusive Canonical XML 1.0, without comments
   xmlsec1 --c14n       tests/fixtures/c14n/v20_rec_3_2_whitespace_content.in.xml \
     | cmp - tests/fixtures/c14n/v20_rec_3_2_whitespace_content.out

   # with-comments variants: --c14n-exc-with-comments / --c14n-with-comments
   ```

   For `mode: "id"` vectors, canonicalize the identified subtree (e.g. via an XPath/`--node-id`
   selection of the element carrying `Id="target"`) rather than the whole document. For
   `inclusive_prefixes` vectors, pass the PrefixList to `--inclusive-namespaces`.

2. **End-to-end signature interop.** Produce a XAdES-B/T document from this crate, then verify it
   with an independent validator:

   ```sh
   xmlsec1 --verify --trusted-pem <ca.pem> signed-xades.xml
   ```

   and, as a separate manual step, load the same document into the **EU DSS** demonstration
   validator (Java) and record the report. Interop against EU DSS is a manual conformance step; do
   **not** add a Java dependency to CI.

3. **Record the run** (tool versions + commands + result) in the PR that performs it, and, if any
   byte diverges from a committed `.out`, treat it as a release blocker and escalate to the track
   lead before changing `c14n.rs` (its emit is frozen and shared by every digest).

## XAdES-LTA (E4) — DEFERRED design sketch

v1 keeps `XadesLevel::LTA` returning `XadesError::NotYetSupported`; it is **not** faked-green
anywhere. This is the design stub for the follow-on.

**Goal.** Add `xades:ArchiveTimeStamp` inside `UnsignedSignatureProperties`, computed over the
long-term-validity (LT) material, per **ETSI EN 319 132-1 §5.5.2**.

**Message-imprint order (EN 319 132-1 §5.5.2).** The archive-timestamp data object is formed by
concatenating, in **document order**, the canonicalized octets of:

1. the content actually referenced by each `ds:Reference` of `ds:SignedInfo` (the referenced data
   objects, after their transforms — excluding the `SignedProperties` reference, which is covered
   below), in `SignedInfo` order;
2. `ds:SignedInfo`;
3. `ds:SignatureValue`;
4. `ds:KeyInfo`, if present;
5. every `xades:UnsignedSignatureProperties` child **except** the `ArchiveTimeStamp` being added —
   in document order — i.e. the existing `SignatureTimeStamp` (T), `CertificateValues` and
   `RevocationValues` (LT), any `…RefsTimeStamp`/`SigAndRefsTimeStamp`, and any **prior**
   `ArchiveTimeStamp`(s).

Each canonicalized with the algorithm declared on the timestamp's `ds:CanonicalizationMethod`
(Exclusive C14N by default). The resulting imprint is sent to the TSA (RFC 3161) exactly as the
existing XAdES-T `SignatureTimeStamp` is produced (`src/xades.rs`), and the token is embedded as a
new `xades:ArchiveTimeStamp/xades:EncapsulatedTimeStamp`.

**Where it attaches.** Strictly on the *unsigned* side, after assembly — mirroring how XAdES-T
attaches its timestamp today and never touching the signed core or the immutable two-phase seam
(`prepare_xades → sign_signed_attributes → assemble`). The `UnsignedProperties` container already
leaves the archive-TS slot open (see `src/xades.rs`).

**Precedent to mirror.** The PAdES-LTA DSS/DocTimeStamp/renewal pattern in `chancela-pades`
(t67-e5) and the existing ASiC `ASiCArchiveManifest` + RFC 3161 archive timestamp in
`chancela-signing::asic_sign` (`asic_sign.rs`, the `ASiCArchiveManifest` archive-TS path). The XAdES
archive-TS is the XML analogue of those.

**Renewal (follow-on to the follow-on).** Appending a fresh `ArchiveTimeStamp` over the prior chain
before the current TSA certificate/hash weakens is deferred; v1 (when LTA lands) may emit a single
archive-TS. Renewal automation mirrors PAdES-LTA renewal.

## Algorithm support

RSA-PKCS1-SHA256 and ECDSA on P-256 / P-384 / P-521 with matched SHA-256 / SHA-384 / SHA-512 digests
are supported and round-trip-tested (build → sign → validate) at the `chancela-xades` crate level
(P-384/P-521 are landed by the track lead in E2). The `SignatureMethod`/`DigestMethod` URIs and the
ECDSA `r||s` widths follow the curve. Note that the local PKCS#12 API signer lane remains
RSA-2048 / ECDSA-P256, matching the real Cartão de Cidadão / Chave Móvel Digital key material in
scope; wiring P-384/P-521 through to the PKCS#12 / hardware signer requires a variable-length-digest
signer seam and is a documented follow-on. RSA-PSS and Ed25519/EdDSA `SignatureMethod`s, and
Canonical XML 1.1, remain out of scope for v1.
