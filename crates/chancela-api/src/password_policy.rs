//! Password strength policy (t68).
//!
//! A single, server-authoritative definition of what makes a **compliant** sign-in password, plus
//! the validation that enforces it on every password-**setting** path and the read-only view the web
//! renders as a live requirement checklist (`GET /v1/session/password-policy`). Keeping the rules in
//! one place means the client checklist can mirror the server EXACTLY — the endpoint returns the same
//! parameters this module validates against.
//!
//! ## Rules (t68, user-specified)
//! - length ≥ [`MIN_LENGTH`]
//! - contains a lowercase AND an uppercase ASCII letter AND a digit AND a special (punctuation) char
//! - must NOT contain the account's username (case-insensitive, incl. a modest leetspeak normalise)
//! - must NOT be a common password/phrase (a compact embedded [`DENYLIST`])
//! - no run of [`MAX_IDENTICAL_RUN`]+ identical consecutive chars (e.g. `aaaa` / `1111`)
//! - no monotonic run of [`MAX_SEQUENTIAL_RUN`]+ consecutive chars (e.g. `abcde` / `12345`, reversed too)
//!
//! ## Mandatory vs. strength (t68 "make everything mandatory now")
//! Presence is **non-negotiable**: an empty password is always rejected, even when weak passwords are
//! permitted. The strength rules above are what the [`ALLOW_WEAK_PASSWORDS`] toggle relaxes — flip
//! that single boolean and only the mandatory-presence + the caller's baseline length floor remain.
//! The settings-document field that will eventually drive that boolean is deferred to the coordinated
//! web slice (t68-web); for now it is sourced from the constant here (default = enforce).

use serde::Serialize;

use crate::error::ApiError;

/// Minimum length for a compliant (strong) password.
pub const MIN_LENGTH: usize = 10;
/// A run of this many identical consecutive characters is rejected (e.g. `aaaa`, `1111`).
pub const MAX_IDENTICAL_RUN: usize = 4;
/// A monotonic sequential run (e.g. `abcde`, `12345`, or their reverses) of this length is rejected.
pub const MAX_SEQUENTIAL_RUN: usize = 5;

/// Whether weak — but present — passwords are currently permitted.
///
/// Sourced from this constant for now: t68 defers the settings-document toggle (+ its contract
/// fixture + web wiring) to the coordinated web slice to avoid drifting the settings contract while
/// apps/web is being edited. Flipping this single boolean is the entire relax-strength switch;
/// presence stays mandatory regardless (see [`enforce`]). Default `false` ⇒ strong passwords required.
pub const ALLOW_WEAK_PASSWORDS: bool = false;

/// Stable rule identifiers — a machine key the web can switch on, decoupled from the PT copy.
pub mod rule {
    pub const LENGTH: &str = "length";
    pub const LOWERCASE: &str = "lowercase";
    pub const UPPERCASE: &str = "uppercase";
    pub const DIGIT: &str = "digit";
    pub const SPECIAL: &str = "special";
    pub const NOT_USERNAME: &str = "not_username";
    pub const NOT_COMMON: &str = "not_common";
    pub const NO_REPEATS: &str = "no_repeats";
    pub const NO_SEQUENTIAL: &str = "no_sequential";
    pub const PRESENT: &str = "present";
}

/// One failed requirement, returned in the `422` body so the client can point at the exact rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasswordRuleFailure {
    /// A stable [`rule`] identifier.
    pub code: &'static str,
    /// A human, PT description of the requirement that was not met.
    pub requirement: String,
}

/// A requirement descriptor for the read-only policy view (a live checklist row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasswordRuleView {
    pub code: &'static str,
    pub requirement: String,
}

/// The active ruleset, returned by `GET /v1/session/password-policy`. Self-contained in
/// chancela-api (no contracts/** fixture — the web fixture+type land with the consuming web slice).
#[derive(Debug, Clone, Serialize)]
pub struct PasswordPolicyView {
    pub min_length: usize,
    pub require_lowercase: bool,
    pub require_uppercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub forbid_username: bool,
    pub forbid_common: bool,
    /// Reject a run of this many identical consecutive characters.
    pub max_identical_run: usize,
    /// Reject a monotonic run of this many consecutive characters.
    pub max_sequential_run: usize,
    /// Whether weak (but present) passwords are currently permitted. Presence is mandatory regardless.
    pub allow_weak_passwords: bool,
    /// Ordered, human requirement descriptors mirroring exactly what [`enforce`] checks.
    pub rules: Vec<PasswordRuleView>,
}

/// The requirement copy for `rule` `code` (single source of truth for both the failures and the view).
fn requirement_text(code: &str) -> String {
    match code {
        rule::LENGTH => format!("pelo menos {MIN_LENGTH} caracteres"),
        rule::LOWERCASE => "pelo menos uma letra minúscula".to_owned(),
        rule::UPPERCASE => "pelo menos uma letra maiúscula".to_owned(),
        rule::DIGIT => "pelo menos um algarismo".to_owned(),
        rule::SPECIAL => "pelo menos um caractere especial".to_owned(),
        rule::NOT_USERNAME => "não pode conter o nome de utilizador".to_owned(),
        rule::NOT_COMMON => "não pode ser uma palavra-passe comum".to_owned(),
        rule::NO_REPEATS => {
            format!("sem {MAX_IDENTICAL_RUN} ou mais caracteres iguais seguidos")
        }
        rule::NO_SEQUENTIAL => {
            format!("sem {MAX_SEQUENTIAL_RUN} ou mais caracteres consecutivos seguidos")
        }
        rule::PRESENT => "a palavra-passe é obrigatória".to_owned(),
        other => other.to_owned(),
    }
}

/// The strength rules, in checklist order. Presence is enforced separately (it is mandatory even when
/// the strength rules are relaxed) so it is not part of this list.
const STRENGTH_RULES: &[&str] = &[
    rule::LENGTH,
    rule::LOWERCASE,
    rule::UPPERCASE,
    rule::DIGIT,
    rule::SPECIAL,
    rule::NOT_USERNAME,
    rule::NOT_COMMON,
    rule::NO_REPEATS,
    rule::NO_SEQUENTIAL,
];

/// The active policy as a serialisable view for the read-only endpoint.
pub fn policy_view() -> PasswordPolicyView {
    PasswordPolicyView {
        min_length: MIN_LENGTH,
        require_lowercase: true,
        require_uppercase: true,
        require_digit: true,
        require_special: true,
        forbid_username: true,
        forbid_common: true,
        max_identical_run: MAX_IDENTICAL_RUN,
        max_sequential_run: MAX_SEQUENTIAL_RUN,
        allow_weak_passwords: ALLOW_WEAK_PASSWORDS,
        rules: STRENGTH_RULES
            .iter()
            .map(|&code| PasswordRuleView {
                code,
                requirement: requirement_text(code),
            })
            .collect(),
    }
}

/// Whether `code`'s strength rule passes for `password` against `username`.
fn rule_passes(code: &str, password: &str, username: &str) -> bool {
    match code {
        rule::LENGTH => password.chars().count() >= MIN_LENGTH,
        rule::LOWERCASE => password.chars().any(|c| c.is_ascii_lowercase()),
        rule::UPPERCASE => password.chars().any(|c| c.is_ascii_uppercase()),
        rule::DIGIT => password.chars().any(|c| c.is_ascii_digit()),
        // A "special" is any non-alphanumeric, non-whitespace character (ASCII punctuation and beyond).
        rule::SPECIAL => password
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace()),
        rule::NOT_USERNAME => !contains_username(password, username),
        rule::NOT_COMMON => !is_common(password),
        rule::NO_REPEATS => !has_identical_run(password, MAX_IDENTICAL_RUN),
        rule::NO_SEQUENTIAL => !has_sequential_run(password, MAX_SEQUENTIAL_RUN),
        _ => true,
    }
}

/// Evaluate every strength rule, returning the ones that FAILED (empty ⇒ fully compliant). Does not
/// consider [`ALLOW_WEAK_PASSWORDS`] or presence — [`enforce`] layers those on top.
pub fn failed_rules(password: &str, username: &str) -> Vec<PasswordRuleFailure> {
    STRENGTH_RULES
        .iter()
        .filter(|&&code| !rule_passes(code, password, username))
        .map(|&code| PasswordRuleFailure {
            code,
            requirement: requirement_text(code),
        })
        .collect()
}

/// Enforce the policy on a candidate `password` for the account named `username`.
///
/// Presence is mandatory **always**: an empty candidate is rejected even when `allow_weak` is true.
/// When `allow_weak` is true the strength rules are skipped (a present-but-weak password is accepted);
/// otherwise every rule in [`failed_rules`] must pass. On failure returns
/// [`ApiError::PasswordPolicy`] (a `422` carrying the per-rule failures).
pub fn enforce(password: &str, username: &str, allow_weak: bool) -> Result<(), ApiError> {
    if password.is_empty() {
        return Err(ApiError::PasswordPolicy {
            message: "a palavra-passe é obrigatória".to_owned(),
            failures: vec![PasswordRuleFailure {
                code: rule::PRESENT,
                requirement: requirement_text(rule::PRESENT),
            }],
        });
    }
    if allow_weak {
        return Ok(());
    }
    let failures = failed_rules(password, username);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ApiError::PasswordPolicy {
            message: "a palavra-passe não cumpre os requisitos de segurança".to_owned(),
            failures,
        })
    }
}

// --- Rule helpers ----------------------------------------------------------------------------

/// A modest leetspeak → plain normalisation, applied to BOTH sides of the username check and to the
/// common-password check so `4melia` matches `amelia` and `P4ssw0rd` matches `password`.
fn leet(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            '@' => 'a',
            '$' => 's',
            '!' => 'i',
            '+' => 't',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// Whether `password` contains `username` (case-insensitive), directly or after a leetspeak normalise.
/// Usernames shorter than 3 chars are ignored (too short to be a meaningful containment signal).
fn contains_username(password: &str, username: &str) -> bool {
    let user = username.trim().to_ascii_lowercase();
    if user.chars().count() < 3 {
        return false;
    }
    let pw = password.to_ascii_lowercase();
    if pw.contains(&user) {
        return true;
    }
    leet(password).contains(&leet(&user))
}

/// Whether `password` is a common password/phrase — an exact match (after normalising) against the
/// embedded [`DENYLIST`]. Substrings are deliberately NOT matched (a compound passphrase that merely
/// contains a common word is not itself common), but trailing digits/punctuation are trimmed so
/// `password123!` is caught.
fn is_common(password: &str) -> bool {
    let lower = password.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches(|c: char| !c.is_ascii_alphabetic());
    let candidates = [
        lower.clone(),
        leet(&lower),
        trimmed.to_owned(),
        leet(trimmed),
    ];
    // Linear scan: a few hundred entries × 4 candidate forms, run only on a password-set — negligible,
    // and it frees the list from a hand-maintained sort invariant.
    candidates.iter().any(|c| DENYLIST.contains(&c.as_str()))
}

/// Whether any character repeats identically `run` or more times in a row (e.g. `aaaa` for run 4).
fn has_identical_run(password: &str, run: usize) -> bool {
    let mut count = 1usize;
    let mut prev: Option<char> = None;
    for c in password.chars() {
        if Some(c) == prev {
            count += 1;
            if count >= run {
                return true;
            }
        } else {
            count = 1;
            prev = Some(c);
        }
    }
    false
}

/// Whether any monotonic run of consecutive code points (ascending or descending by 1) reaches
/// `run` in length (e.g. `abcde`, `12345`, and their reverses `edcba`, `54321`).
fn has_sequential_run(password: &str, run: usize) -> bool {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < run {
        return false;
    }
    let (mut asc, mut desc) = (1usize, 1usize);
    for w in chars.windows(2) {
        let (a, b) = (w[0] as i32, w[1] as i32);
        asc = if b - a == 1 { asc + 1 } else { 1 };
        desc = if a - b == 1 { desc + 1 } else { 1 };
        if asc >= run || desc >= run {
            return true;
        }
    }
    false
}

/// A compact denylist of the most common passwords/phrases (for [`is_common`]). A few hundred
/// entries — enough to reject the passwords that dominate breach corpora without shipping a megabyte
/// wordlist. Lowercase; order is irrelevant (matched by a linear scan).
static DENYLIST: &[&str] = &[
    "000000",
    "0000000",
    "00000000",
    "111111",
    "1111111",
    "11111111",
    "112233",
    "121212",
    "123123",
    "1234",
    "12345",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "123321",
    "12341234",
    "131313",
    "142536",
    "147258369",
    "1q2w3e",
    "1q2w3e4r",
    "1q2w3e4r5t",
    "1qaz2wsx",
    "222222",
    "232323",
    "246810",
    "danger",
    "654321",
    "666666",
    "696969",
    "654321",
    "753951",
    "777777",
    "789456",
    "789456123",
    "888888",
    "987654321",
    "999999",
    "aaaaaa",
    "abc123",
    "abcabc",
    "abcd1234",
    "abcdef",
    "abcdefg",
    "access",
    "admin",
    "admin123",
    "adobe123",
    "amanda",
    "andrea",
    "andrew",
    "angel",
    "angels",
    "animal",
    "anthony",
    "apple",
    "arsenal",
    "asdasd",
    "asdf",
    "asdf1234",
    "asdfasdf",
    "asdfgh",
    "asdfghjkl",
    "ashley",
    "asshole",
    "austin",
    "azerty",
    "badboy",
    "bailey",
    "banana",
    "baseball",
    "batman",
    "beach",
    "bear",
    "beautiful",
    "beauty",
    "believe",
    "bella",
    "biteme",
    "blahblah",
    "blessed",
    "blink182",
    "blue",
    "bond007",
    "booboo",
    "boomer",
    "brandon",
    "brian",
    "bubbles",
    "buddy",
    "buster",
    "butterfly",
    "calvin",
    "camaro",
    "carlos",
    "caroline",
    "casper",
    "changeme",
    "charles",
    "charlie",
    "cheese",
    "chelsea",
    "chicken",
    "chocolate",
    "chris",
    "cocacola",
    "coffee",
    "computer",
    "cookie",
    "cool",
    "cooper",
    "corvette",
    "cosmos",
    "cowboy",
    "cowboys",
    "crystal",
    "cutie",
    "daniel",
    "danielle",
    "dallas",
    "dolphin",
    "dolphins",
    "donald",
    "dragon",
    "dreams",
    "eagle",
    "eagles",
    "edward",
    "elephant",
    "eminem",
    "estrela",
    "family",
    "fernando",
    "ferrari",
    "flower",
    "football",
    "forever",
    "freedom",
    "friends",
    "fuckyou",
    "gandalf",
    "gateway",
    "george",
    "ginger",
    "gizmo",
    "golden",
    "golfer",
    "google",
    "grace",
    "green",
    "guitar",
    "gundam",
    "hammer",
    "hannah",
    "happy",
    "harley",
    "heather",
    "hello",
    "hello123",
    "helpme",
    "hockey",
    "hola",
    "hope",
    "hottie",
    "house",
    "hunter",
    "iloveu",
    "iloveyou",
    "internet",
    "iverson",
    "jackson",
    "jaguar",
    "jasmine",
    "jasper",
    "jennifer",
    "jessica",
    "jesus",
    "john",
    "johnny",
    "jordan",
    "jordan23",
    "joseph",
    "joshua",
    "juice",
    "julian",
    "junior",
    "justin",
    "killer",
    "king",
    "kitten",
    "kitty",
    "knight",
    "ladies",
    "letmein",
    "liberty",
    "lightning",
    "lily",
    "linkedin",
    "little",
    "london",
    "loulou",
    "love",
    "lovely",
    "loveme",
    "lover",
    "loveyou",
    "lucky",
    "madison",
    "maggie",
    "magic",
    "manager",
    "marina",
    "marlboro",
    "martin",
    "master",
    "matrix",
    "matthew",
    "maverick",
    "maxwell",
    "melissa",
    "mercedes",
    "merlin",
    "mexico",
    "michael",
    "michelle",
    "mickey",
    "midnight",
    "mike",
    "miller",
    "money",
    "monkey",
    "monster",
    "morgan",
    "mother",
    "mountain",
    "muffin",
    "mustang",
    "naruto",
    "nascar",
    "nathan",
    "nation",
    "naughty",
    "nelson",
    "nemesis",
    "nevada",
    "nicholas",
    "nicole",
    "ninja",
    "nirvana",
    "oliver",
    "olivia",
    "orange",
    "packers",
    "panther",
    "panties",
    "paris",
    "parker",
    "pass",
    "passw0rd",
    "password",
    "password1",
    "password12",
    "password123",
    "patrick",
    "peaches",
    "peanut",
    "pepper",
    "phoenix",
    "pikachu",
    "player",
    "please",
    "pokemon",
    "pookie",
    "porsche",
    "power",
    "prince",
    "princess",
    "purple",
    "pussy",
    "qazwsx",
    "qwe123",
    "qweasd",
    "qweasdzxc",
    "qwer1234",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "rabbit",
    "rachel",
    "racing",
    "rainbow",
    "raiders",
    "ranger",
    "rangers",
    "rebecca",
    "richard",
    "robert",
    "rock",
    "rocket",
    "rockstar",
    "rocky",
    "rockyou",
    "ronaldo",
    "root",
    "rose",
    "runner",
    "rush2112",
    "russia",
    "samantha",
    "sammy",
    "samsung",
    "sandra",
    "saturn",
    "scooby",
    "scooter",
    "scorpio",
    "scorpion",
    "secret",
    "sexy",
    "shadow",
    "shannon",
    "shelby",
    "sierra",
    "silver",
    "simple",
    "skittles",
    "slayer",
    "smokey",
    "snoopy",
    "soccer",
    "sophie",
    "sparky",
    "spider",
    "spiderman",
    "spirit",
    "squirt",
    "star",
    "stars",
    "startrek",
    "starwars",
    "steelers",
    "steven",
    "sticky",
    "summer",
    "sunflower",
    "sunny",
    "sunshine",
    "superman",
    "swimming",
    "sydney",
    "taylor",
    "teamo",
    "teddy",
    "temp",
    "tennis",
    "test",
    "test123",
    "testing",
    "thomas",
    "thunder",
    "tiger",
    "tigger",
    "tinkerbell",
    "toyota",
    "trained",
    "travis",
    "trinity",
    "trombone",
    "trustno1",
    "tucker",
    "tweety",
    "unicorn",
    "united",
    "vampire",
    "vanessa",
    "victor",
    "victoria",
    "viking",
    "vincent",
    "violet",
    "warrior",
    "welcome",
    "welcome1",
    "welcome123",
    "whatever",
    "william",
    "willie",
    "wilson",
    "winner",
    "winter",
    "wizard",
    "wolf",
    "wolverine",
    "xavier",
    "xxxxxx",
    "yamaha",
    "yankees",
    "yellow",
    "young",
    "zaq12wsx",
    "zombie",
    "zxcvbn",
    "zxcvbnm",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compliant_password_passes() {
        assert!(enforce("Segur0-Chave7!", "amelia.marques", false).is_ok());
        assert!(failed_rules("Segur0-Chave7!", "amelia.marques").is_empty());
    }

    #[test]
    fn empty_is_rejected_even_when_weak_allowed() {
        let err = enforce("", "amelia", true).unwrap_err();
        match err {
            ApiError::PasswordPolicy { failures, .. } => {
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].code, rule::PRESENT);
            }
            other => panic!("expected PasswordPolicy, got {other:?}"),
        }
    }

    #[test]
    fn weak_but_present_passes_only_when_allowed() {
        // A weak (but present) password: too short, no upper/digit/special.
        assert!(enforce("abc", "amelia", true).is_ok());
        assert!(enforce("abc", "amelia", false).is_err());
    }

    #[test]
    fn each_rule_can_fail_independently() {
        let codes = |pw: &str, user: &str| -> Vec<&'static str> {
            failed_rules(pw, user).into_iter().map(|f| f.code).collect()
        };
        assert!(codes("Sh0rt!", "amelia").contains(&rule::LENGTH));
        assert!(codes("SEGUR0-CHAVE7!", "amelia").contains(&rule::LOWERCASE));
        assert!(codes("segur0-chave7!", "amelia").contains(&rule::UPPERCASE));
        assert!(codes("Segur-Chaveee!", "amelia").contains(&rule::DIGIT));
        assert!(codes("Segur0Chave7X", "amelia").contains(&rule::SPECIAL));
        // Username containment, incl. leetspeak (4melia ⇒ amelia).
        assert!(codes("Amelia-Chave7!", "amelia").contains(&rule::NOT_USERNAME));
        assert!(codes("X4melia-Chave7!", "amelia").contains(&rule::NOT_USERNAME));
        // Common password (with trailing digits/punctuation trimmed).
        assert!(codes("Password123!", "amelia").contains(&rule::NOT_COMMON));
        // 4+ identical run.
        assert!(codes("Seguraaaa7!", "amelia").contains(&rule::NO_REPEATS));
        // 5+ sequential run (ascending letters, and descending digits).
        assert!(codes("Xabcde-7!Qq", "amelia").contains(&rule::NO_SEQUENTIAL));
        assert!(codes("X54321-Ab!q", "amelia").contains(&rule::NO_SEQUENTIAL));
    }

    #[test]
    fn sequential_boundary_four_ok_five_fails() {
        // 4 consecutive is allowed; 5 is not (both directions).
        assert!(!has_sequential_run("1234", MAX_SEQUENTIAL_RUN));
        assert!(has_sequential_run("12345", MAX_SEQUENTIAL_RUN));
        assert!(has_sequential_run("edcba", MAX_SEQUENTIAL_RUN));
    }

    #[test]
    fn policy_view_reports_the_enforced_parameters() {
        let v = policy_view();
        assert_eq!(v.min_length, MIN_LENGTH);
        assert!(v.require_uppercase && v.require_special);
        assert!(
            !v.allow_weak_passwords,
            "default must enforce strong passwords"
        );
        assert_eq!(v.rules.len(), STRENGTH_RULES.len());
    }
}
