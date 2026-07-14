//! SQL **dialect translation** from the store's hand-written SQLite strings to PostgreSQL
//! (wp14 Phase 1, §2.1/§2.2).
//!
//! The store's SQL/DDL is expressed once in the SQLite dialect ([`crate::schema`] + the `Tx`
//! write methods). Rather than maintain a second, hand-copied set of Postgres strings that can
//! silently drift, the Postgres backend derives its DDL from the same [`crate::schema::ALL`]
//! constants through the small, **pure, unit-tested** rewrites in this module, and writes its
//! parameterised statements with `?N` placeholders that [`rewrite_placeholders`] maps to Postgres
//! `$N`. Keeping these rules here (a) makes them testable without a live database — the Phase 1
//! acceptance for the translation logic — and (b) documents exactly how the two dialects differ.
//!
//! Scope of the rules (matches the SQLite-isms enumerated in the plan §1.2):
//! - **`? / ?N` placeholders → `$N`** (the `postgres` crate uses `$1..$N`). See [`rewrite_placeholders`].
//! - **DDL type/modifier mapping** (see [`sqlite_ddl_to_pg`]): `STRICT` table modifier dropped
//!   (Postgres columns are already statically typed), `BLOB` → `BYTEA`, `INTEGER` → `BIGINT`,
//!   `REAL` → `DOUBLE PRECISION`. `TEXT` is kept verbatim (Postgres has `TEXT`), so the
//!   document-in-relational `json`/`links` columns and the RFC-3339 `timestamp`/`created_at` text
//!   columns round-trip byte-identically — the ledger hash preimage is unchanged (§1.2, §4).
//!   `INSERT OR REPLACE` upserts are NOT auto-rewritten (the `ON CONFLICT` target differs per
//!   table); those are written directly in each `Tx` method's Postgres arm.
//!
//! These rules deliberately rely on Chancela's DDL convention that **type keywords are uppercase
//! and column/table identifiers are lowercase**, so a whole-word uppercase token replacement never
//! touches an identifier.

/// Rewrite SQLite positional placeholders (`?`, `?1`, `?2`, …) into PostgreSQL numbered
/// placeholders (`$1`, `$2`, …).
///
/// Both a numbered `?N` (what the store uses everywhere) and a bare `?` are supported: a `?N`
/// becomes `$N` (preserving the author's explicit index), while a bare `?` is assigned the next
/// sequential index. Any `?` inside a single-quoted string literal is left untouched.
#[must_use]
pub fn rewrite_placeholders(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len() + 4);
    let mut i = 0;
    let mut next_auto = 1u32;
    let mut in_string = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '\'' {
            in_string = !in_string;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '?' && !in_string {
            // Collect any explicit numeric index directly following the `?`.
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 {
                out.push('$');
                out.push_str(&sql[i + 1..j]);
                // Keep the auto counter ahead of the highest explicit index so a later bare `?`
                // cannot collide with an already-used number.
                if let Ok(n) = sql[i + 1..j].parse::<u32>() {
                    next_auto = next_auto.max(n + 1);
                }
                i = j;
            } else {
                out.push('$');
                out.push_str(&next_auto.to_string());
                next_auto += 1;
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Translate one SQLite `CREATE TABLE`/`CREATE INDEX` statement into its PostgreSQL twin.
///
/// Applies the whole-DDL type/modifier rules described in the module docs. `CREATE INDEX IF NOT
/// EXISTS` / `CREATE UNIQUE INDEX IF NOT EXISTS` are valid Postgres (≥ 9.5) and pass through
/// unchanged.
///
/// Note (deferred): `imported_document_review_history.id` is a SQLite `INTEGER PRIMARY KEY`
/// (rowid autoincrement). This rewrite maps it to `BIGINT PRIMARY KEY`, which is valid DDL but is
/// **not** auto-incrementing — the review-history write path is currently unsupported on the
/// Postgres backend (it returns [`crate::StoreError::UnsupportedOnPostgres`]); when that path is
/// ported it must switch this column to `BIGINT GENERATED ALWAYS AS IDENTITY`. The ledger
/// `events.seq` is intentionally left `BIGINT PRIMARY KEY` (application-assigned, never a DB
/// sequence — §4).
#[must_use]
pub fn sqlite_ddl_to_pg(ddl: &str) -> String {
    ddl.replace(" STRICT", "")
        .replace("BLOB", "BYTEA")
        .replace("INTEGER", "BIGINT")
        .replace("REAL", "DOUBLE PRECISION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_numbered_placeholders() {
        assert_eq!(
            rewrite_placeholders("INSERT INTO t (a, b) VALUES (?1, ?2)"),
            "INSERT INTO t (a, b) VALUES ($1, $2)"
        );
    }

    #[test]
    fn rewrites_up_to_double_digit_indices() {
        let sql = "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
        let expected = "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
        assert_eq!(rewrite_placeholders(sql), expected);
    }

    #[test]
    fn rewrites_bare_placeholders_sequentially() {
        assert_eq!(
            rewrite_placeholders("SELECT * FROM t WHERE a = ? AND b = ?"),
            "SELECT * FROM t WHERE a = $1 AND b = $2"
        );
    }

    #[test]
    fn leaves_question_marks_inside_string_literals() {
        assert_eq!(
            rewrite_placeholders("SELECT '?' , a WHERE b = ?1"),
            "SELECT '?' , a WHERE b = $1"
        );
    }

    #[test]
    fn maps_create_table_types_and_drops_strict() {
        let sqlite = "\
CREATE TABLE IF NOT EXISTS events (
    seq            INTEGER PRIMARY KEY,
    payload_digest BLOB NOT NULL,
    links          TEXT NOT NULL DEFAULT '[]'
) STRICT;";
        let pg = sqlite_ddl_to_pg(sqlite);
        assert!(pg.contains("seq            BIGINT PRIMARY KEY"), "{pg}");
        assert!(pg.contains("payload_digest BYTEA NOT NULL"), "{pg}");
        assert!(
            pg.contains("links          TEXT NOT NULL DEFAULT '[]'"),
            "{pg}"
        );
        assert!(!pg.contains("STRICT"), "STRICT should be dropped: {pg}");
        assert!(!pg.contains("BLOB"), "BLOB should be mapped: {pg}");
        assert!(!pg.contains("INTEGER"), "INTEGER should be mapped: {pg}");
    }

    #[test]
    fn maps_real_to_double_precision() {
        assert_eq!(
            sqlite_ddl_to_pg("confidence     REAL,"),
            "confidence     DOUBLE PRECISION,"
        );
    }

    #[test]
    fn create_index_passes_through_unchanged() {
        let idx = "CREATE INDEX IF NOT EXISTS idx_events_scope ON events (scope);";
        assert_eq!(sqlite_ddl_to_pg(idx), idx);
    }

    #[test]
    fn every_schema_ddl_translates_without_leftover_sqlite_isms() {
        for stmt in crate::schema::ALL {
            let pg = sqlite_ddl_to_pg(stmt);
            assert!(!pg.contains("STRICT"), "leftover STRICT in: {pg}");
            assert!(!pg.contains("BLOB"), "leftover BLOB in: {pg}");
            // `INTEGER`/`REAL` uppercase type keywords must all be gone.
            assert!(!pg.contains("INTEGER"), "leftover INTEGER in: {pg}");
            assert!(!pg.contains(" REAL"), "leftover REAL in: {pg}");
        }
    }
}
