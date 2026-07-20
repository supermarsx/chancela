//! Live PC/SC reader-detection smoke test (plan §4, t4-e9 acceptance).
//!
//! Runs [`chancela_smartcard::detect`] against the real PC/SC stack on this box
//! and prints a typed result. Acceptance: a clean `Ok(readers)` or a graceful
//! typed `Err` (e.g. `PcscUnavailable` when the Smart Card service is stopped) —
//! it must **never panic**.
//!
//! Run with: `cargo run -p chancela-smartcard --example detect`

fn main() {
    match chancela_smartcard::detect() {
        Ok(readers) if readers.is_empty() => {
            println!("detect() -> Ok([]) : PC/SC available, no readers attached");
        }
        Ok(readers) => {
            println!("detect() -> Ok({} reader(s)):", readers.len());
            for r in readers {
                println!("  - {}", r.name);
            }
        }
        Err(e) => {
            // A typed error is an acceptable outcome (no reader / no service).
            println!("detect() -> Err({e}) : typed, no panic");
        }
    }
}
