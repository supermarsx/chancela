# Testing `chancela-smartcard`

Two tiers, matching the workspace policy (plan §2.4 / §6).

## 1. Default tests — offline, no reader, run in CI

```
cargo test -p chancela-smartcard
```

These cover everything above the PKCS#11 boundary using `MockToken` and the
pure crypto helpers — no card reader, middleware, or network:

- **Card-generation branching** — CC v1 RSA-2048 (`CKM_RSA_PKCS` over a SHA-256
  `DigestInfo`) vs CC v2 P-256 (`CKM_ECDSA` re-encoded to DER `Ecdsa-Sig-Value`).
- **ECDSA re-encoding** — IEEE-P1363 `r‖s` → DER, the DER pass-through path, the
  sign-byte (leading `0x00`) path, and rejection of malformed lengths.
- **Certificate selection** — qualified-signature vs authentication cert chosen
  by `CKA_LABEL`, never by slot index; the un-activated-signature error surface.
- **Algorithm detection** — RSA vs P-256 read from a certificate's SPKI, driven
  by the checked-in public-cert fixtures under `fixtures/`.
- **Reader detection** — `detect()` returns a clean `Result` and never panics,
  whether the box has zero readers, a reader, or no PC/SC service.

### Note on mock signatures

`MockToken` owns no private key, so its signature bytes are **deterministic
placeholders of the correct shape, not cryptographically valid signatures**.
Cryptographic round-trip verification lives in `chancela-cades` (whose tests mint
ephemeral RSA/P-256 keys). This crate proves the plumbing and branching; `cades`
proves the crypto.

### Fixtures (`fixtures/`)

- `cc_v1_signature_rsa2048.der` — self-signed RSA-2048 **public** cert
  (labelled like a CC v1 signature cert).
- `cc_v2_authentication_p256.der` — self-signed P-256 **public** cert
  (labelled like a CC v2 cert).

Only public certificates are checked in — no private keys.

## 2. Hardware tests — real reader + middleware + card, never in CI

Double-gated: behind the `hardware-tests` feature **and** `#[ignore]`.

```
cargo test -p chancela-smartcard --features hardware-tests -- --ignored
```

### Prerequisites

1. A PC/SC card reader connected and the OS smart-card service running
   (Windows: *Smart Card* service; Linux: `pcscd` + `libpcsclite`; macOS:
   built-in).
2. The **Autenticação.gov** middleware installed
   (<https://www.autenticacao.gov.pt/cc-aplicacao>). This provides both the
   PC/SC driver and the PKCS#11 module:
   - Windows `C:\Windows\System32\pteidpkcs11.dll`
   - macOS `/usr/local/lib/libpteidpkcs11.dylib`
   - Linux `/usr/local/lib/libpteidpkcs11.so` (the official Flatpak keeps the
     module inside its sandbox — set `CHANCELA_PTEID_PKCS11_MODULE` to point at
     it, or use OpenSC's `opensc-pkcs11.so`).
3. A Cartão de Cidadão inserted. `sign_with_real_card` triggers the middleware's
   PIN dialog (or, for a contactless CC v2, expects the 6-digit CAN).

### Environment

- `CHANCELA_PTEID_PKCS11_MODULE` — override the module path (defaults per-OS
  above). Required for the Linux Flatpak layout.

### What is covered vs. deferred

| Covered by hardware tests | Deferred (documented follow-up) |
|---|---|
| Reader enumeration, cert listing, real card signing (RSA/ECDSA) | `CKA_ALWAYS_AUTHENTICATE` context-specific re-auth tuning per middleware build |
| NULL-PIN protected-auth-path login | SCAP professional attributes (SIG-04) |

The signature key is `CKA_ALWAYS_AUTHENTICATE`; the current login path issues a
single `C_Login(User, NULL)` and relies on the middleware's protected-auth-path
prompt. If a specific middleware build needs an explicit
`C_Login(CKU_CONTEXT_SPECIFIC)` between `sign_init` and `sign_final`, that is
tuned here against real hardware.
