//! # Portuguese numerals written out in words (pt-PT)
//!
//! Portuguese notarial and corporate drafting writes a quantity as the digits followed by the same
//! quantity in words, in parentheses: **`100 (cem) páginas`**. This module renders the words half,
//! across the four numeral classes European Portuguese actually has — **cardinal**, **ordinal**,
//! **fractional** and **multiplicative** — plus a small [`plural_filter`] for making the *counted
//! noun* agree.
//!
//! ```jinja
//! {{ page_capacity }} ({{ page_capacity | in_words }}) páginas
//! {{ n }} ({{ n | in_words(gender="f") }}) sócias
//! a {{ n | in_words(form="ordinal", gender="f") }} ata
//! {{ n }} {{ n | plural("página", "páginas") }}
//! ```
//!
//! The filter returns **only the words**, lower-case, with no digits, no parentheses and no
//! surrounding noun. Defaults are `form="cardinal"`, `gender="m"`, `number="singular"`.
//!
//! ## ⚠ Never apply a numeral filter to an identifier
//!
//! These filters cannot tell a *quantity* from an *identifier*, and spelling an identifier out is
//! wrong. **Never** apply one to a NIPC/NIF (`503 456 789`), a legal-diploma number (`Decreto-Lei
//! n.º 268/94`), an article/number/paragraph reference (`artigo 31.º`), a year, a book or act
//! sequence number, a page number or a certificate serial.
//!
//! The article case deserves spelling out, because `form="ordinal"` makes it *look* served and it
//! is not. Portuguese reads legal-reference numerals — artigos, capítulos, séculos, sovereigns and
//! popes — **as ordinals only up to ten, and as cardinals from eleven onwards**. `artigo 31.º` is
//! read *artigo trinta e um*, never "artigo trigésimo primeiro"; `século XXI` is *século vinte e
//! um*; `Luís XIV` is *Luís catorze*. So `31 | in_words(form="ordinal")` yields `trigésimo
//! primeiro`, which is a correct ordinal and the **wrong reading of an article number**. Leave
//! article numbers as digits.
//!
//! These filters are for **counted quantities and positions in a sequence**: page capacities,
//! pages used, headcounts, vote counts, annex counts, and "a segunda ata", "o terceiro livro".
//!
//! ## Gender — masculine, feminine, and `indeterminate`
//!
//! Only these forms inflect for gender, and this module inflects exactly these:
//!
//! - cardinals: `um`/`uma`, `dois`/`duas`, and the hundreds `duzentos`/`duzentas` …
//!   `novecentos`/`novecentas`;
//! - ordinals: every component, throughout (`primeiro`/`primeira`, `milésima trecentésima …`);
//! - the fractional `meio`/`meia`, and nothing else in that class.
//!
//! `três`, `quatro` … `nove`, the whole 10–19 block, every ten (`vinte` … `noventa`), `cem`,
//! `cento` and `mil` are invariable.
//!
//! **`gender="i"` (indeterminate) renders the masculine forms — deliberately, and it is not a
//! silent alias.** Portuguese has no neuter: the language lost it, and the masculine is the
//! unmarked form that fills every gender-less slot. That covers three real situations this
//! codebase meets — naming the number itself (`o número dois`, and *números* are masculine nouns),
//! counting with no noun attached (`um, dois, três`), and a mixed-gender group (`os dois sócios`,
//! where Portuguese convention takes the masculine). `"i"` exists so an author who genuinely has no
//! noun can say so in the template instead of asserting a masculine they do not mean; the rendered
//! string is identical to `"m"`, and there is no pt-PT construction in which it would differ.
//!
//! Two gender traps that are easy to get wrong:
//!
//! - **`mil` is invariable but what precedes it is not.** The counted noun's gender reaches
//!   through: `duas mil páginas`, `duzentas mil páginas`, `vinte e uma mil páginas`.
//! - **`milhão`/`milhões` is a masculine *noun*, not a numeral**, so it never agrees with the
//!   counted noun: `duzentos milhões de páginas`, never "duzentas milhões". The millions class is
//!   always rendered masculine here whatever `gender` says, while `gender` still governs the mil
//!   and units classes of the same number.
//!
//! ## Number — what actually inflects, and what does not
//!
//! `number="plural"` is accepted only where the numeral itself has a plural:
//!
//! - **ordinals** do: `as primeiras atas`, `os vigésimos primeiros`. Every component agrees.
//! - **fractionals** do, agreeing with the numerator: `dois terços`, `três quartos`. The `avos`
//!   form is invariable (`um doze avos`, `sete doze avos`), so plural is accepted and changes
//!   nothing — the word genuinely does not move.
//! - **cardinals** do **not**. `mil` is invariable, and `milhão`/`milhões` follows the *value*, not
//!   a parameter — 1 000 000 renders `um milhão` and 2 000 000 renders `dois milhões` with no help
//!   from the caller. `number="plural"` on a cardinal is therefore rejected rather than ignored.
//! - **multiplicatives** do not: the noun series (`o dobro`, `o triplo`) is invariable.
//!
//! ## The counted noun (`1 página` vs `2 páginas`) — served, but only safely
//!
//! Pluralising an arbitrary Portuguese noun is not something this module will guess at. The plurals
//! are irregular enough (`ação`→`ações`, `papel`→`papéis`, `contrato-promessa`→`contratos-promessa`)
//! that a morphology engine would eventually put a wrong word into a signed instrument, which is
//! exactly the failure this codebase forbids.
//!
//! What is safe is letting the **author supply both forms** and having the numeral pick:
//!
//! ```jinja
//! O livro compõe-se de {{ n }} ({{ n | in_words(gender="f") }}) {{ n | plural("página", "páginas") }}.
//! ```
//!
//! [`plural_filter`] selects the singular **only when the count is exactly 1** — Portuguese puts
//! zero in the plural (`zero páginas`), and so is every other value including `mil` and `um
//! milhão de`. Prefer this over `{% if n == 1 %}…{% else %}…{% endif %}`: it is one expression,
//! both forms sit side by side for review, and it cannot fall through a mis-written guard. Note in
//! particular that minijinja's `is defined` test is `!is_undefined()`, so it is **true for a
//! `none`** — `{% elif n is defined %}` does *not* skip an unset `Option`, and the value will reach
//! the numeral filter and fail the render. Use `is not none`.
//!
//! ## Forms
//!
//! ### `cardinal` (default) — 0 … 999 999 999
//!
//! The `e` conjunction, from [Ciberdúvidas](https://ciberduvidas.iscte-iul.pt/consultorio/perguntas/a-conjuncao-e-nos-numerais/31900)
//! (following Paul Teyssier and Cunha & Cintra). Inside a class of three digits it is
//! unconditional — `cento e vinte`, `cento e dois`, `vinte e um`. Between classes:
//!
//! > The conjunction links the **two rightmost classes that carry an expressed (non-zero) value**,
//! > and only those, when the lower of the two is under one hundred or is an exact multiple of one
//! > hundred. At every higher class boundary there is no conjunction.
//!
//! | number | words | why |
//! |---|---|---|
//! | 1 020 | `mil e vinte` | remainder 20 is under 100 |
//! | 1 100 | `mil e cem` | remainder 100 is an exact hundred |
//! | 1 200 | `mil e duzentos` | remainder 200 is an exact hundred |
//! | 1 230 | `mil duzentos e trinta` | remainder 230 is neither |
//! | 4 226 | `quatro mil duzentos e vinte e seis` | remainder 226 is neither |
//! | 2 300 000 | `dois milhões e trezentos mil` | lowest expressed class is 300 (mil) |
//! | 1 200 300 | `um milhão duzentos mil e trezentos` | only the *last* boundary takes `e` |
//!
//! The "two rightmost expressed classes" clause is what stops 1 200 300 from acquiring a second
//! class-level `e` ("um milhão **e** duzentos mil **e** trezentos"), which is wrong; a rule applied
//! independently at every boundary produces that error. Ciberdúvidas presents an inter-class comma
//! as a *frequent* practice, not a prescribed one, so a plain space is emitted — the words land in
//! a parenthetical beside the digits, where an interior comma reads as a digit-group separator.
//!
//! **100 exactly is `cem`**, never `cento`; `cento` is the combining form for 101–199. `mil` takes
//! no `um` — `mil`, not "um mil".
//!
//! ### `ordinal` — 1 … 1999
//!
//! Composed by juxtaposing the ordinal of each place value, **with no `e`**: 1432 →
//! `milésimo quadringentésimo trigésimo segundo`. All of `primeiro` … `nono`, the tens `décimo` …
//! `nonagésimo`, the hundreds `centésimo` … `nongentésimo` and `milésimo` are irregular Latinate
//! forms and are tabulated, not derived.
//!
//! Where pt has two accepted spellings this module fixes the Latinate one for internal consistency:
//! `trecentésimo` (also written *tricentésimo*), `sexcentésimo` (also *seiscentésimo*),
//! `nongentésimo` (also *noningentésimo*). `septuagésimo` keeps its `p`.
//!
//! **Support stops at 1999, deliberately.** A bare `milésimo` prefix is uncontested, but from
//! 2000.º the form is genuinely unsettled — [Ciberdúvidas](https://ciberduvidas.iscte-iul.pt/consultorio/perguntas/a-forma-por-extenso-de-2000-e-de-outros-ordinais/16428)
//! records `dois milésimo` (Teyssier), `dois milésimos` and `segundo milésimo` as competing
//! attested forms. Picking one silently would put a contested word into a signed instrument, and
//! nothing this product numbers — atas, livros, assembleias — reaches 2000.
//!
//! ### `fractional` — 2 … 999 999 999
//!
//! The denominator's name. The formation rule, from
//! [Ciberdúvidas](https://ciberduvidas.iscte-iul.pt/consultorio/perguntas/numeros-fraccionarios/11493)
//! and the standard grammars: `meio` and `terço` are suppletive; otherwise the fractional is the
//! **ordinal when that ordinal is a single word** (`quarto`, `décimo`, `vigésimo`, `centésimo`,
//! `milésimo`, `milionésimo`), and the **cardinal followed by `avos`** when the ordinal is a
//! compound (`onze avos`, `treze avos`, `vinte e três avos`, `cento e quinze avos`). `avos`
//! generalised from Latin *octavus* and is used from eleven upwards.
//!
//! Only `meio`/`meia` inflects for gender; every other fractional is a masculine noun and stays
//! masculine whatever the counted noun is (`dois terços das ações`, never "duas terças"), so
//! `gender="f"` on anything but 2 is rejected rather than ignored. `metade` is a common feminine
//! synonym for `meio` and is *not* emitted — it is a noun with different syntax (`metade das
//! ações`, not "metade ações"), so the template writes it literally when it wants it.
//!
//! ### `multiplicative` — 2 … 12, and 100
//!
//! The **substantive** series: `dobro`, `triplo`, `quádruplo`, `quíntuplo`, `sêxtuplo`, `sétuplo`,
//! `óctuplo`, `nónuplo`, `décuplo`, `undécuplo`, `duodécuplo`, `cêntuplo`. Invariable masculine
//! nouns — `o dobro da caução`. The series is closed: it does not extend, so 13 and 99 are
//! rejected rather than coined.
//!
//! Portuguese also has a parallel **adjectival** series (`duplo`/`dupla`, `tríplice`,
//! `quádruplo`/`quádrupla`) which *does* inflect. This module deliberately serves only the
//! substantive series, because choosing between `o dobro` and `duplo` is a syntactic decision about
//! the surrounding sentence that a filter cannot see — and emitting the wrong one produces
//! ungrammatical legal text. A template needing the adjective writes it literally.
//!
//! ## Categories deliberately **not** implemented
//!
//! - **Collectives** (`par`, `dezena`, `dúzia`, `quinzena`, `centena`, `milhar`, `grosa`). They are
//!   nouns over a tiny non-productive domain, they require `de` plus the counted noun (`uma dezena
//!   de sócios`), and — decisively — in ordinary usage they are **approximate**: *uma dezena de
//!   pessoas* means *about ten*. A legal instrument states an exact count, so rendering an exact
//!   number as a collective would weaken the very assertion the instrument exists to make. A
//!   template that genuinely wants "dúzia" writes it literally.
//! - **Roman numerals.** Different problem, and in this codebase they appear on identifiers
//!   (`Capítulo IV`, `século XXI`) which must not be spelled out at all.
//! - **Currency extenso** (`mil euros e vinte cêntimos`). It needs a second unit, a rounding
//!   policy and a `de` rule, and belongs in whatever writes monetary amounts — not here.
//!
//! ## pt-PT, not pt-BR
//!
//! European Portuguese throughout. The forms that differ:
//!
//! | | pt-PT (used here) | pt-BR (**not** used) |
//! |---|---|---|
//! | 14 | `catorze` | `quatorze` |
//! | 16 | `dezasseis` | `dezesseis` |
//! | 17 | `dezassete` | `dezessete` |
//! | 19 | `dezanove` | `dezenove` |
//! | ×9 | `nónuplo` | `nônuplo` |
//! | 10⁹ | `mil milhões` | `bilhão` |
//! | 10¹² | `bilião` | `trilhão` |
//!
//! The last two rows are why the cardinal range stops below 10⁹, and they are worse than a spelling
//! difference: pt-PT uses the **long scale**, where `bilião` is 10¹², while pt-BR uses the short
//! scale, where `bilhão` is 10⁹. The same word names two magnitudes a thousandfold apart. Any
//! rendering at or above 10⁹ has to commit to a scale, and getting it wrong in a signed instrument
//! misstates a number by three orders of magnitude — so the range stops short of it instead.
//! (`bilião`/`biliões` would inflect for number exactly as `milhão`/`milhões` does, if it were ever
//! in range.) If a pt-BR catalog is ever needed it gets its own filter or an explicit locale
//! parameter; this one must not silently serve both, because the divergence is invisible in the
//! output to anyone who does not already know which variant they are reading.
//!
//! ## Rejection is the contract
//!
//! Everything outside a form's range, and every parameter a form cannot honour, is a **render
//! error** — never a partial, approximate or silently-defaulted rendering. This text goes into a
//! signed legal instrument, so an unrepresentable value must stop the render rather than emit a
//! plausible-looking wrong word. Rejected: negatives; out-of-range values (per form, each with its
//! own reason); non-integers (a float, a numeric string, `none`/`null` from an unset `Option`, an
//! undefined variable, a list, a map); an unknown `form`, `gender` or `number`; an unexpected
//! keyword argument; and `gender="f"` or `number="plural"` on a form that cannot inflect that way.

use std::fmt;

use minijinja::value::{Kwargs, Value as JinjaValue};
use minijinja::{Error as JinjaError, ErrorKind};

/// Largest cardinal: 999 999 999. Support stops below 10⁹ because pt-PT's long scale (`bilião` =
/// 10¹²) and pt-BR's short scale (`bilhão` = 10⁹) disagree by a factor of a thousand there.
pub const MAX_CARDINAL: i128 = 999_999_999;

/// Largest ordinal: 1999. From 2000.º the pt form is unsettled — see the module doc.
pub const MAX_ORDINAL: i128 = 1_999;

/// Largest multiplicative below the isolated `cêntuplo`; the series is closed at `duodécuplo`.
pub const MAX_MULTIPLICATIVE: i128 = 12;

/// Which class of numeral to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Form {
    /// `um`, `cem`, `mil e duzentos` — a counted quantity. The default.
    #[default]
    Cardinal,
    /// `primeiro`, `décimo segundo`, `milésimo quadringentésimo trigésimo segundo` — a position.
    Ordinal,
    /// `meio`, `terço`, `quarto`, `onze avos` — the name of a denominator.
    Fractional,
    /// `dobro`, `triplo`, `cêntuplo` — the substantive multiplicative series.
    Multiplicative,
}

impl fmt::Display for Form {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Form::Cardinal => "cardinal",
            Form::Ordinal => "ordinal",
            Form::Fractional => "fractional",
            Form::Multiplicative => "multiplicative",
        })
    }
}

/// Grammatical gender of the noun the numeral relates to, for the forms that inflect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Gender {
    /// `um`, `dois`, `duzentos`, `primeiro` — the default.
    #[default]
    Masculine,
    /// `uma`, `duas`, `duzentas`, `primeira`.
    Feminine,
    /// No noun to agree with: the number named as itself, bare counting, or a mixed-gender group.
    /// Renders the masculine forms — Portuguese has no neuter, and the masculine is its unmarked
    /// form. See the module doc; this is a documented ruling, not an accidental alias.
    Indeterminate,
}

impl Gender {
    /// Whether the feminine forms are wanted. `Indeterminate` folds into masculine here, which is
    /// the single place that ruling takes effect.
    fn is_feminine(self) -> bool {
        matches!(self, Gender::Feminine)
    }
}

/// Grammatical number of the numeral itself — not of the counted noun.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GrammaticalNumber {
    /// The default.
    #[default]
    Singular,
    /// `primeiras`, `terços`. Rejected on forms that have no plural.
    Plural,
}

/// Why a value or parameter combination cannot be rendered. Every variant is a hard failure; none
/// has a "best effort" rendering, by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NumeralError {
    /// A negative value.
    #[error(
        "cannot write {value} as a {form} numeral: a counted quantity is never negative \
         (these filters render page counts, headcounts and positions — check the context value)"
    )]
    Negative {
        /// The offending value.
        value: i128,
        /// The form that was requested.
        form: Form,
    },
    /// Outside the form's supported range.
    #[error(
        "cannot write {value} as a {form} numeral: supported range is {min}..={max} — {reason}"
    )]
    OutOfRange {
        /// The offending value.
        value: i128,
        /// The form that was requested.
        form: Form,
        /// Inclusive lower bound.
        min: i128,
        /// Inclusive upper bound.
        max: i128,
        /// Why the bound is where it is.
        reason: &'static str,
    },
    /// A value inside the range that the form still has no word for.
    #[error("there is no {form} numeral for {value} in Portuguese: {reason}")]
    NoSuchNumeral {
        /// The offending value.
        value: i128,
        /// The form that was requested.
        form: Form,
        /// Why no word exists.
        reason: &'static str,
    },
    /// `gender="f"` on something that has no feminine.
    #[error("the {form} numeral for {value} does not inflect for gender: {reason}")]
    GenderNotInflected {
        /// The value whose word is invariable.
        value: i128,
        /// The form that was requested.
        form: Form,
        /// Why it is invariable.
        reason: &'static str,
    },
    /// `number="plural"` on something that has no plural.
    #[error("the {form} numeral does not inflect for number: {reason}")]
    NumberNotInflected {
        /// The form that was requested.
        form: Form,
        /// Why it is invariable.
        reason: &'static str,
    },
}

// --- cardinal tables ----------------------------------------------------------------------------

const UNITS: [&str; 10] = [
    "zero", "um", "dois", "três", "quatro", "cinco", "seis", "sete", "oito", "nove",
];

/// 10–19, the irregular block. `catorze`, `dezasseis`, `dezassete` and `dezanove` are the pt-PT
/// forms; pt-BR writes `quatorze`, `dezesseis`, `dezessete`, `dezenove`.
const TEN_TO_NINETEEN: [&str; 10] = [
    "dez",
    "onze",
    "doze",
    "treze",
    "catorze",
    "quinze",
    "dezasseis",
    "dezassete",
    "dezoito",
    "dezanove",
];

/// Indexed by the tens digit; 0 and 1 are unreachable (0–19 are handled above). Invariable.
const TENS: [&str; 10] = [
    "",
    "",
    "vinte",
    "trinta",
    "quarenta",
    "cinquenta",
    "sessenta",
    "setenta",
    "oitenta",
    "noventa",
];

/// Indexed by the hundreds digit. Slot 1 is `cento`, the *combining* form; exactly 100 is `cem` and
/// is special-cased in [`group`]. `quinhentos` is the irregular one.
const HUNDREDS_M: [&str; 10] = [
    "",
    "cento",
    "duzentos",
    "trezentos",
    "quatrocentos",
    "quinhentos",
    "seiscentos",
    "setecentos",
    "oitocentos",
    "novecentos",
];

const HUNDREDS_F: [&str; 10] = [
    "",
    "cento",
    "duzentas",
    "trezentas",
    "quatrocentas",
    "quinhentas",
    "seiscentas",
    "setecentas",
    "oitocentas",
    "novecentas",
];

// --- ordinal tables -----------------------------------------------------------------------------

const ORD_UNITS: [&str; 10] = [
    "", "primeiro", "segundo", "terceiro", "quarto", "quinto", "sexto", "sétimo", "oitavo", "nono",
];

const ORD_TENS: [&str; 10] = [
    "",
    "décimo",
    "vigésimo",
    "trigésimo",
    "quadragésimo",
    "quinquagésimo",
    "sexagésimo",
    "septuagésimo",
    "octogésimo",
    "nonagésimo",
];

/// `trecentésimo`, `sexcentésimo` and `nongentésimo` also occur as *tricentésimo*,
/// *seiscentésimo* and *noningentésimo*; the Latinate series is fixed here for consistency.
const ORD_HUNDREDS: [&str; 10] = [
    "",
    "centésimo",
    "ducentésimo",
    "trecentésimo",
    "quadringentésimo",
    "quingentésimo",
    "sexcentésimo",
    "septingentésimo",
    "octingentésimo",
    "nongentésimo",
];

const ORD_THOUSAND: &str = "milésimo";

/// Reachable only through [`fractional`] — ordinals themselves stop at 1999.
const ORD_MILLION: &str = "milionésimo";

/// The substantive multiplicative series, indexed from 2. `nónuplo` is the pt-PT spelling; pt-BR
/// writes `nônuplo`. The series is closed — there is no word for 13.
const MULTIPLICATIVES: [&str; 11] = [
    "dobro",
    "triplo",
    "quádruplo",
    "quíntuplo",
    "sêxtuplo",
    "sétuplo",
    "óctuplo",
    "nónuplo",
    "décuplo",
    "undécuplo",
    "duodécuplo",
];

const CENTUPLE: &str = "cêntuplo";

// --- public API ---------------------------------------------------------------------------------

/// Render `n` in the requested form. This is what the `in_words` filter calls.
pub fn in_words(
    n: i128,
    form: Form,
    gender: Gender,
    number: GrammaticalNumber,
) -> Result<String, NumeralError> {
    match form {
        Form::Cardinal => {
            if number == GrammaticalNumber::Plural {
                return Err(NumeralError::NumberNotInflected {
                    form,
                    reason: "`mil` is invariable and `milhão`/`milhões` follows the value itself, \
                             so a cardinal has no plural to select",
                });
            }
            cardinal(n, gender)
        }
        Form::Ordinal => ordinal(n, gender, number),
        Form::Fractional => fractional(n, gender, number),
        Form::Multiplicative => multiplicative(n, gender, number),
    }
}

/// A counted quantity: `zero`, `cem`, `mil e duzentos`, `um milhão`. Range 0..=[`MAX_CARDINAL`].
///
/// ```
/// use chancela_templates::numerals::{cardinal, Gender};
///
/// assert_eq!(cardinal(100, Gender::Masculine).unwrap(), "cem");
/// assert_eq!(cardinal(2, Gender::Feminine).unwrap(), "duas");
/// assert_eq!(cardinal(1230, Gender::Masculine).unwrap(), "mil duzentos e trinta");
/// assert!(cardinal(-1, Gender::Masculine).is_err());
/// ```
pub fn cardinal(n: i128, gender: Gender) -> Result<String, NumeralError> {
    let form = Form::Cardinal;
    if n < 0 {
        return Err(NumeralError::Negative { value: n, form });
    }
    if n > MAX_CARDINAL {
        return Err(NumeralError::OutOfRange {
            value: n,
            form,
            min: 0,
            max: MAX_CARDINAL,
            reason: "support stops below 1 000 000 000 because pt-PT's long scale (`bilião` = \
                     10¹²) and pt-BR's short scale (`bilhão` = 10⁹) name different magnitudes \
                     there, and rendering either would silently pick a scale",
        });
    }
    if n == 0 {
        return Ok(UNITS[0].to_string());
    }
    let n = n as u32;

    let millions = n / 1_000_000;
    let thousands = (n / 1_000) % 1_000;
    let units = n % 1_000;

    // The classes that carry an expressed value, most significant first, each paired with its own
    // three-digit value — the conjunction rule keys off the *value* of the lowest expressed class,
    // not off the whole remainder.
    let mut classes: Vec<(u32, String)> = Vec::with_capacity(3);
    if millions > 0 {
        // `milhão`/`milhões` is a masculine noun, so this class never takes the counted noun's
        // gender: `duzentos milhões de páginas`, never "duzentas milhões".
        let words = if millions == 1 {
            "um milhão".to_string()
        } else {
            format!("{} milhões", group(millions, Gender::Masculine))
        };
        classes.push((millions, words));
    }
    if thousands > 0 {
        // `mil` takes no `um` — "mil", never "um mil". Above one thousand the multiplier does agree
        // with the counted noun (`duas mil páginas`, `duzentas mil páginas`).
        let words = if thousands == 1 {
            "mil".to_string()
        } else {
            format!("{} mil", group(thousands, gender))
        };
        classes.push((thousands, words));
    }
    if units > 0 {
        classes.push((units, group(units, gender)));
    }

    let last = classes.len() - 1;
    let mut out = String::new();
    for (i, (value, words)) in classes.iter().enumerate() {
        if i > 0 {
            // The conjunction joins the two rightmost expressed classes only, and only when the
            // lower of the two is under one hundred or is an exact multiple of one hundred.
            let conjoin = i == last && (*value < 100 || value % 100 == 0);
            out.push_str(if conjoin { " e " } else { " " });
        }
        out.push_str(words);
    }
    Ok(out)
}

/// A position in a sequence: `primeiro`, `décimo segundo`, `milésimo quadringentésimo trigésimo
/// segundo`. Range 1..=[`MAX_ORDINAL`]; components are juxtaposed with **no** `e`.
///
/// ```
/// use chancela_templates::numerals::{ordinal, Gender, GrammaticalNumber::*};
///
/// assert_eq!(ordinal(2, Gender::Feminine, Singular).unwrap(), "segunda");
/// assert_eq!(ordinal(1, Gender::Feminine, Plural).unwrap(), "primeiras");
/// assert_eq!(
///     ordinal(1432, Gender::Masculine, Singular).unwrap(),
///     "milésimo quadringentésimo trigésimo segundo"
/// );
/// ```
pub fn ordinal(n: i128, gender: Gender, number: GrammaticalNumber) -> Result<String, NumeralError> {
    let form = Form::Ordinal;
    if n < 0 {
        return Err(NumeralError::Negative { value: n, form });
    }
    if n == 0 {
        return Err(NumeralError::NoSuchNumeral {
            value: 0,
            form,
            reason: "ordinals name a position in a sequence and Portuguese sequences start at \
                     `primeiro` — there is no zeroth",
        });
    }
    if n > MAX_ORDINAL {
        return Err(NumeralError::OutOfRange {
            value: n,
            form,
            min: 1,
            max: MAX_ORDINAL,
            reason: "from 2000.º the pt form is unsettled — `dois milésimo`, `dois milésimos` and \
                     `segundo milésimo` are all attested, and this library will not pick one for a \
                     signed instrument",
        });
    }

    let n = n as u32;
    let mut parts: Vec<&'static str> = Vec::with_capacity(4);
    // n <= 1999, so there is at most one `milésimo` and it never takes a multiplier.
    if n >= 1_000 {
        parts.push(ORD_THOUSAND);
    }
    let rest = n % 1_000;
    let hundreds = (rest / 100) as usize;
    if hundreds > 0 {
        parts.push(ORD_HUNDREDS[hundreds]);
    }
    let tens = ((rest % 100) / 10) as usize;
    if tens > 0 {
        parts.push(ORD_TENS[tens]);
    }
    let units = (rest % 10) as usize;
    if units > 0 {
        parts.push(ORD_UNITS[units]);
    }

    // Every component is an adjective and every component agrees.
    let inflected: Vec<String> = parts
        .iter()
        .map(|w| inflect_o_stem(w, gender, number))
        .collect();
    Ok(inflected.join(" "))
}

/// The name of a denominator: `meio`, `terço`, `quarto`, `vigésimo`, `onze avos`. Range
/// 2..=[`MAX_CARDINAL`].
///
/// ```
/// use chancela_templates::numerals::{fractional, Gender, GrammaticalNumber::*};
///
/// assert_eq!(fractional(2, Gender::Feminine, Singular).unwrap(), "meia");
/// assert_eq!(fractional(3, Gender::Masculine, Plural).unwrap(), "terços");
/// assert_eq!(fractional(11, Gender::Masculine, Singular).unwrap(), "onze avos");
/// ```
pub fn fractional(
    n: i128,
    gender: Gender,
    number: GrammaticalNumber,
) -> Result<String, NumeralError> {
    let form = Form::Fractional;
    if n < 0 {
        return Err(NumeralError::Negative { value: n, form });
    }
    if n == 0 {
        return Err(NumeralError::NoSuchNumeral {
            value: 0,
            form,
            reason: "a denominator of zero is not a fraction",
        });
    }
    if n == 1 {
        return Err(NumeralError::NoSuchNumeral {
            value: 1,
            form,
            reason: "1/1 is the whole, not a fraction — Portuguese has no fracionário for one; \
                     write `inteiro` or the quantity itself",
        });
    }
    if n > MAX_CARDINAL {
        return Err(NumeralError::OutOfRange {
            value: n,
            form,
            min: 2,
            max: MAX_CARDINAL,
            reason: "the `avos` form is built on the cardinal, so it inherits the cardinal range",
        });
    }

    // `meio` is the one fractional that is an adjective and agrees in gender.
    if n == 2 {
        return Ok(inflect_o_stem("meio", gender, number));
    }
    // Everything below is a masculine noun: `dois terços das ações`, never "duas terças".
    if gender.is_feminine() {
        return Err(NumeralError::GenderNotInflected {
            value: n,
            form,
            reason: "every fractional but `meio`/`meia` is a masculine noun and keeps the \
                     masculine whatever it counts (`dois terços das ações`); drop `gender`, or \
                     write `metade` literally if that is what you meant",
        });
    }
    if n == 3 {
        return Ok(inflect_o_stem("terço", gender, number));
    }
    match single_word_ordinal(n) {
        // The ordinal doubles as the fractional whenever it is a single word.
        Some(word) => Ok(inflect_o_stem(word, gender, number)),
        // Otherwise: cardinal + `avos`, which is invariable in both gender and number
        // (`um doze avos`, `sete doze avos`).
        None => Ok(format!("{} avos", cardinal(n, Gender::Masculine)?)),
    }
}

/// The substantive multiplicative series: `dobro`, `triplo`, … `duodécuplo`, and `cêntuplo`.
/// Invariable masculine nouns over a closed domain — 2..=[`MAX_MULTIPLICATIVE`], plus 100.
///
/// ```
/// use chancela_templates::numerals::{multiplicative, Gender, GrammaticalNumber::*};
///
/// assert_eq!(multiplicative(2, Gender::Masculine, Singular).unwrap(), "dobro");
/// assert_eq!(multiplicative(100, Gender::Masculine, Singular).unwrap(), "cêntuplo");
/// assert!(multiplicative(13, Gender::Masculine, Singular).is_err());
/// ```
pub fn multiplicative(
    n: i128,
    gender: Gender,
    number: GrammaticalNumber,
) -> Result<String, NumeralError> {
    let form = Form::Multiplicative;
    if n < 0 {
        return Err(NumeralError::Negative { value: n, form });
    }
    if gender.is_feminine() {
        return Err(NumeralError::GenderNotInflected {
            value: n,
            form,
            reason: "the substantive multiplicatives are invariable masculine nouns (`o dobro da \
                     caução`); the inflecting adjectival series (`dupla`, `tríplice`) is a \
                     different word set and is not served here",
        });
    }
    if number == GrammaticalNumber::Plural {
        return Err(NumeralError::NumberNotInflected {
            form,
            reason: "the substantive multiplicatives are invariable",
        });
    }
    match n {
        100 => Ok(CENTUPLE.to_string()),
        2..=MAX_MULTIPLICATIVE => Ok(MULTIPLICATIVES[(n - 2) as usize].to_string()),
        0 | 1 => Err(NumeralError::NoSuchNumeral {
            value: n,
            form,
            reason: "the multiplicative series starts at `dobro` (2) — multiplying by one or zero \
                     has no multiplicative numeral",
        }),
        _ => Err(NumeralError::NoSuchNumeral {
            value: n,
            form,
            reason: "the series is closed at `duodécuplo` (12) with `cêntuplo` (100) standing \
                     alone; there is no Portuguese word here to coin",
        }),
    }
}

// --- internals ----------------------------------------------------------------------------------

/// One cardinal class of three digits, `1..=999`, with the unconditional intra-class `e`.
fn group(n: u32, gender: Gender) -> String {
    debug_assert!((1..=999).contains(&n), "group() takes 1..=999, got {n}");

    // Exactly one hundred is `cem`; 101–199 use the combining form `cento e …`. This is the classic
    // error, and it is the value this domain uses most (a book's default page capacity).
    if n == 100 {
        return "cem".to_string();
    }

    let hundreds = (n / 100) as usize;
    let rest = n % 100;
    let table = if gender.is_feminine() {
        HUNDREDS_F
    } else {
        HUNDREDS_M
    };

    match (hundreds, rest) {
        (0, _) => under_hundred(rest, gender),
        (h, 0) => table[h].to_string(),
        (h, r) => format!("{} e {}", table[h], under_hundred(r, gender)),
    }
}

/// `1..=99`.
fn under_hundred(n: u32, gender: Gender) -> String {
    debug_assert!(
        (1..=99).contains(&n),
        "under_hundred() takes 1..=99, got {n}"
    );
    match n {
        1..=9 => unit(n, gender).to_string(),
        10..=19 => TEN_TO_NINETEEN[(n - 10) as usize].to_string(),
        _ => {
            let tens = TENS[(n / 10) as usize];
            match n % 10 {
                0 => tens.to_string(),
                u => format!("{tens} e {}", unit(u, gender)),
            }
        }
    }
}

/// `1..=9`. Only `um` and `dois` inflect.
fn unit(n: u32, gender: Gender) -> &'static str {
    match (n, gender.is_feminine()) {
        (1, true) => "uma",
        (2, true) => "duas",
        _ => UNITS[n as usize],
    }
}

/// The ordinal for `n` **if it is a single word** — the test the fractional formation rule turns
/// on. Single-word ordinals are 1–9, the exact tens, the exact hundreds, 1000 and 1 000 000;
/// everything else is a compound (`décimo primeiro`) and takes the `avos` form instead.
fn single_word_ordinal(n: i128) -> Option<&'static str> {
    match n {
        1..=9 => Some(ORD_UNITS[n as usize]),
        n if n < 100 && n % 10 == 0 => Some(ORD_TENS[(n / 10) as usize]),
        n if n < 1_000 && n % 100 == 0 => Some(ORD_HUNDREDS[(n / 100) as usize]),
        1_000 => Some(ORD_THOUSAND),
        1_000_000 => Some(ORD_MILLION),
        _ => None,
    }
}

/// Inflect a word whose citation form ends in `-o` (every ordinal, plus `meio` and `terço`) for
/// gender and number: `primeiro` → `primeira` / `primeiros` / `primeiras`.
fn inflect_o_stem(word: &str, gender: Gender, number: GrammaticalNumber) -> String {
    debug_assert!(
        word.ends_with('o'),
        "inflect_o_stem() expects an -o stem, got {word:?}"
    );
    let stem = &word[..word.len() - 1];
    let suffix = match (gender.is_feminine(), number) {
        (false, GrammaticalNumber::Singular) => "o",
        (false, GrammaticalNumber::Plural) => "os",
        (true, GrammaticalNumber::Singular) => "a",
        (true, GrammaticalNumber::Plural) => "as",
    };
    format!("{stem}{suffix}")
}

// --- minijinja filters ----------------------------------------------------------------------

/// `{{ n | in_words }}`, `{{ n | in_words(gender="f") }}`,
/// `{{ n | in_words(form="ordinal", gender="f", number="plural") }}`.
///
/// Everything it cannot render exactly is a render error — see the module doc.
pub(crate) fn in_words_filter(value: JinjaValue, kwargs: Kwargs) -> Result<String, JinjaError> {
    let form = form_arg(&kwargs)?;
    let gender = gender_arg(&kwargs)?;
    let number = number_arg(&kwargs)?;
    // Catches a misspelled or unexpected keyword (`in_words(genero="f")`) instead of ignoring it
    // and rendering the default.
    kwargs.assert_all_used()?;
    let n = integer_arg(&value, "in_words")?;
    in_words(n, form, gender, number).map_err(invalid_operation)
}

/// `{{ n | plural("página", "páginas") }}` — the author supplies both forms and the count picks.
///
/// Portuguese takes the singular **only** at exactly 1: `zero páginas`, `uma página`, `duas
/// páginas`, `mil páginas`. Nothing is guessed — see the module doc for why noun morphology is not
/// this module's job.
pub(crate) fn plural_filter(
    value: JinjaValue,
    singular: String,
    plural: String,
) -> Result<String, JinjaError> {
    let n = integer_arg(&value, "plural")?;
    Ok(if n == 1 { singular } else { plural })
}

fn invalid_operation(e: NumeralError) -> JinjaError {
    JinjaError::new(ErrorKind::InvalidOperation, e.to_string())
}

fn form_arg(kwargs: &Kwargs) -> Result<Form, JinjaError> {
    let raw: Option<String> = kwargs.get("form")?;
    match raw.as_deref() {
        None | Some("cardinal") => Ok(Form::Cardinal),
        Some("ordinal") => Ok(Form::Ordinal),
        Some("fractional") => Ok(Form::Fractional),
        Some("multiplicative") => Ok(Form::Multiplicative),
        Some(other) => Err(JinjaError::new(
            ErrorKind::InvalidOperation,
            format!(
                "`in_words` got form={other:?}; expected \"cardinal\" (the default), \"ordinal\", \
                 \"fractional\" or \"multiplicative\". Collectives (`dezena`, `dúzia`) are \
                 deliberately not served — they read as approximations, which a legal instrument \
                 must not do; write them literally."
            ),
        )),
    }
}

fn gender_arg(kwargs: &Kwargs) -> Result<Gender, JinjaError> {
    let raw: Option<String> = kwargs.get("gender")?;
    match raw.as_deref() {
        None | Some("m") => Ok(Gender::Masculine),
        Some("f") => Ok(Gender::Feminine),
        Some("i") => Ok(Gender::Indeterminate),
        Some(other) => Err(JinjaError::new(
            ErrorKind::InvalidOperation,
            format!(
                "`in_words` got gender={other:?}; expected \"m\" (masculine, the default), \"f\" \
                 (feminine) or \"i\" (indeterminate — no noun to agree with; renders the masculine \
                 because Portuguese has no neuter)"
            ),
        )),
    }
}

fn number_arg(kwargs: &Kwargs) -> Result<GrammaticalNumber, JinjaError> {
    let raw: Option<String> = kwargs.get("number")?;
    match raw.as_deref() {
        None | Some("singular") => Ok(GrammaticalNumber::Singular),
        Some("plural") => Ok(GrammaticalNumber::Plural),
        Some(other) => Err(JinjaError::new(
            ErrorKind::InvalidOperation,
            format!(
                "`in_words` got number={other:?}; expected \"singular\" (the default) or \"plural\""
            ),
        )),
    }
}

/// Accept only a real integer. A float — even `100.0` — a numeric string, `none`, an undefined
/// variable or a container is refused rather than coerced: a quantity that reached the template in
/// the wrong shape is a context bug, and guessing at it would put a guess into a signed instrument.
fn integer_arg(value: &JinjaValue, filter: &str) -> Result<i128, JinjaError> {
    if value.is_integer()
        && let Ok(n) = i128::try_from(value.clone())
    {
        return Ok(n);
    }
    Err(JinjaError::new(
        ErrorKind::InvalidOperation,
        format!(
            "`{filter}` needs an integer quantity, got {} ({value}) — it renders counted \
             quantities and will not guess at a non-integer",
            value.kind()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::GrammaticalNumber::{Plural, Singular};
    use super::*;

    /// Shorthand: masculine cardinal.
    fn m(n: i128) -> String {
        cardinal(n, Gender::Masculine).expect("in range")
    }

    /// Shorthand: feminine cardinal.
    fn f(n: i128) -> String {
        cardinal(n, Gender::Feminine).expect("in range")
    }

    /// Shorthand: indeterminate cardinal.
    fn i(n: i128) -> String {
        cardinal(n, Gender::Indeterminate).expect("in range")
    }

    // === cardinals ==============================================================================

    #[test]
    fn zero_and_the_first_two() {
        assert_eq!(m(0), "zero");
        assert_eq!(f(0), "zero", "zero does not inflect");
        assert_eq!(m(1), "um");
        assert_eq!(f(1), "uma");
        assert_eq!(m(2), "dois");
        assert_eq!(f(2), "duas");
    }

    #[test]
    fn units_three_to_nine_do_not_inflect() {
        for (n, w) in [
            (3, "três"),
            (4, "quatro"),
            (5, "cinco"),
            (6, "seis"),
            (7, "sete"),
            (8, "oito"),
            (9, "nove"),
        ] {
            assert_eq!(m(n), w);
            assert_eq!(f(n), w, "{n} must not inflect");
        }
    }

    /// The irregular 10–19 block, in the **pt-PT** forms. `catorze`/`dezasseis`/`dezassete`/
    /// `dezanove` here; pt-BR's `quatorze`/`dezesseis`/`dezessete`/`dezenove` must never appear.
    #[test]
    fn ten_to_nineteen_are_the_pt_pt_forms() {
        let expected = [
            (10, "dez"),
            (11, "onze"),
            (12, "doze"),
            (13, "treze"),
            (14, "catorze"),
            (15, "quinze"),
            (16, "dezasseis"),
            (17, "dezassete"),
            (18, "dezoito"),
            (19, "dezanove"),
        ];
        for (n, w) in expected {
            assert_eq!(m(n), w);
            assert_eq!(f(n), w, "the teens do not inflect");
        }
    }

    #[test]
    fn no_pt_br_forms_anywhere_in_range() {
        for bad in ["quatorze", "dezesseis", "dezessete", "dezenove", "bilh"] {
            for n in [14, 16, 17, 19, 114, 216, 1017, 900_019] {
                assert!(!m(n).contains(bad), "{n} rendered a pt-BR form: {}", m(n));
            }
        }
    }

    #[test]
    fn tens_and_tens_with_units() {
        for (n, w) in [
            (20, "vinte"),
            (30, "trinta"),
            (40, "quarenta"),
            (50, "cinquenta"),
            (60, "sessenta"),
            (70, "setenta"),
            (80, "oitenta"),
            (90, "noventa"),
        ] {
            assert_eq!(m(n), w);
            assert_eq!(f(n), w, "the tens do not inflect");
        }
        assert_eq!(m(21), "vinte e um");
        assert_eq!(f(21), "vinte e uma");
        assert_eq!(m(22), "vinte e dois");
        assert_eq!(f(22), "vinte e duas");
        assert_eq!(m(99), "noventa e nove");
        assert_eq!(f(99), "noventa e nove");
    }

    /// The classic error: 100 exactly is `cem`, never `cento`. This is the value the domain uses
    /// most — a book's default page capacity is 100, and it renders into the termo de abertura.
    #[test]
    fn one_hundred_is_cem_not_cento() {
        assert_eq!(m(100), "cem");
        assert_eq!(f(100), "cem", "`cem` is invariable");
        assert_eq!(i(100), "cem");
        assert_eq!(m(101), "cento e um");
        assert_eq!(f(101), "cento e uma");
        assert_eq!(m(102), "cento e dois");
        assert_eq!(f(102), "cento e duas");
        assert_eq!(m(110), "cento e dez");
        assert_eq!(m(120), "cento e vinte");
        assert_eq!(m(121), "cento e vinte e um");
        assert_eq!(m(199), "cento e noventa e nove");
    }

    /// The book's default page capacity, exactly as the termo de abertura renders it.
    #[test]
    fn default_page_capacity_reads_correctly() {
        assert_eq!(format!("{} ({}) páginas", 100, m(100)), "100 (cem) páginas");
    }

    #[test]
    fn hundreds_inflect() {
        for (n, mw, fw) in [
            (200, "duzentos", "duzentas"),
            (300, "trezentos", "trezentas"),
            (400, "quatrocentos", "quatrocentas"),
            (500, "quinhentos", "quinhentas"),
            (600, "seiscentos", "seiscentas"),
            (700, "setecentos", "setecentas"),
            (800, "oitocentos", "oitocentas"),
            (900, "novecentos", "novecentas"),
        ] {
            assert_eq!(m(n), mw);
            assert_eq!(f(n), fw);
        }
        assert_eq!(m(201), "duzentos e um");
        assert_eq!(f(201), "duzentas e uma");
        assert_eq!(m(999), "novecentos e noventa e nove");
        assert_eq!(f(999), "novecentas e noventa e nove");
    }

    /// `mil` takes no `um`, and it is invariable — but the multiplier in front of it agrees with
    /// the counted noun.
    #[test]
    fn thousands() {
        assert_eq!(m(1_000), "mil", "never `um mil`");
        assert_eq!(f(1_000), "mil");
        assert_eq!(m(2_000), "dois mil");
        assert_eq!(f(2_000), "duas mil");
        assert_eq!(m(10_000), "dez mil");
        assert_eq!(m(21_000), "vinte e um mil");
        assert_eq!(f(21_000), "vinte e uma mil");
        assert_eq!(m(100_000), "cem mil");
        assert_eq!(m(200_000), "duzentos mil");
        assert_eq!(f(200_000), "duzentas mil");
        assert_eq!(m(999_000), "novecentos e noventa e nove mil");
    }

    /// The class-boundary conjunction. See the module doc for the convention and its source.
    #[test]
    fn conjunction_between_classes() {
        // Remainder under one hundred → `e`.
        assert_eq!(m(1_001), "mil e um");
        assert_eq!(f(1_001), "mil e uma");
        assert_eq!(m(1_020), "mil e vinte");
        assert_eq!(m(1_030), "mil e trinta");
        assert_eq!(m(1_099), "mil e noventa e nove");
        // Remainder an exact hundred → `e`.
        assert_eq!(m(1_100), "mil e cem");
        assert_eq!(m(1_200), "mil e duzentos");
        assert_eq!(f(1_200), "mil e duzentas");
        assert_eq!(m(1_300), "mil e trezentos");
        assert_eq!(m(1_400), "mil e quatrocentos");
        // Remainder neither → no `e` at the class boundary, but the intra-class `e` stays.
        assert_eq!(m(1_101), "mil cento e um");
        assert_eq!(m(1_230), "mil duzentos e trinta");
        assert_eq!(m(1_234), "mil duzentos e trinta e quatro");
        assert_eq!(m(4_226), "quatro mil duzentos e vinte e seis");
        assert_eq!(m(1_945), "mil novecentos e quarenta e cinco");
    }

    #[test]
    fn millions() {
        assert_eq!(m(1_000_000), "um milhão");
        assert_eq!(m(2_000_000), "dois milhões");
        assert_eq!(m(1_000_020), "um milhão e vinte");
        assert_eq!(m(1_000_100), "um milhão e cem");
        assert_eq!(m(1_001_000), "um milhão e mil");
        assert_eq!(m(2_300_000), "dois milhões e trezentos mil");
        assert_eq!(
            m(2_236_321),
            "dois milhões duzentos e trinta e seis mil trezentos e vinte e um"
        );
        assert_eq!(
            m(1_234_567),
            "um milhão duzentos e trinta e quatro mil quinhentos e sessenta e sete"
        );
    }

    /// Only the *last* class boundary may take the conjunction. Applying the test independently at
    /// every boundary would wrongly produce "um milhão **e** duzentos mil e trezentos".
    #[test]
    fn only_the_last_class_boundary_takes_the_conjunction() {
        let words = m(1_200_300);
        assert_eq!(words, "um milhão duzentos mil e trezentos");
        assert_eq!(words.matches(" e ").count(), 1);
    }

    /// `milhão`/`milhões` is a masculine noun: it never agrees with the counted noun, while the mil
    /// and units classes of the same number still do.
    #[test]
    fn millions_stay_masculine_under_feminine_gender() {
        assert_eq!(f(2_000_000), "dois milhões", "never `duas milhões`");
        assert_eq!(f(200_000_000), "duzentos milhões", "never `duzentas`");
        assert_eq!(
            f(2_000_002),
            "dois milhões e duas",
            "the units class still inflects"
        );
        assert_eq!(
            f(2_002_000),
            "dois milhões e duas mil",
            "the mil class still inflects"
        );
    }

    #[test]
    fn top_of_the_supported_cardinal_range() {
        assert_eq!(m(MAX_CARDINAL), m(999_999_999));
        assert_eq!(
            m(999_999_999),
            "novecentos e noventa e nove milhões novecentos e noventa e nove mil \
             novecentos e noventa e nove"
        );
        assert_eq!(
            f(999_999_999),
            "novecentos e noventa e nove milhões novecentas e noventa e nove mil \
             novecentas e noventa e nove",
            "millions masculine, mil and units feminine, in one number"
        );
    }

    /// Nothing in range panics, nothing renders empty, nothing renders a stray separator. Walks the
    /// whole 0..=9999 block exhaustively plus a stride over the rest of the range.
    #[test]
    fn every_cardinal_in_range_renders_cleanly() {
        let sweep = (0..=9_999).chain((10_000..=MAX_CARDINAL as u32).step_by(7_919));
        for n in sweep {
            for gender in [Gender::Masculine, Gender::Feminine, Gender::Indeterminate] {
                let w = cardinal(n as i128, gender).expect("in range");
                assert!(!w.is_empty(), "{n} rendered empty");
                assert_eq!(w, w.trim(), "{n} rendered with edge whitespace: {w:?}");
                assert!(!w.contains("  "), "{n} rendered a double space: {w:?}");
                assert!(!w.contains(" e e "), "{n} rendered a doubled `e`: {w:?}");
                assert!(
                    w.chars().all(|c| c.is_lowercase() || c == ' '),
                    "{n} rendered non-lower-case: {w:?}"
                );
                // A *leading* `um mil` is the error — pt says plain `mil`. `quarenta e um mil` is
                // correct, and the trailing space keeps `um milhão` out of the match.
                assert!(
                    w != "um mil" && !w.starts_with("um mil "),
                    "{n} rendered a leading `um mil`, which pt does not say: {w:?}"
                );
                assert!(
                    !w.contains("cento mil") && !w.contains("cento milhões"),
                    "{n} used the combining `cento` where `cem` is required: {w:?}"
                );
            }
        }
    }

    /// A number ending in an exact hundred never uses the combining `cento` at its end.
    #[test]
    fn cem_versus_cento_across_the_range() {
        for k in 0..=999u32 {
            let n = k * 1_000 + 100;
            if n > MAX_CARDINAL as u32 {
                break;
            }
            let w = m(n as i128);
            assert!(w.ends_with("cem"), "{n} must end in `cem`, rendered {w:?}");
        }
    }

    // === indeterminate gender ===================================================================

    /// The documented ruling: `indeterminate` renders the masculine, because Portuguese has no
    /// neuter and the masculine is its unmarked form. Pinned so the ruling cannot drift silently.
    #[test]
    fn indeterminate_renders_the_masculine_throughout() {
        for n in [0, 1, 2, 21, 100, 200, 1_000, 2_000, 1_234_567] {
            assert_eq!(i(n), m(n), "cardinal {n}");
        }
        for n in [1, 2, 11, 100, 1_432] {
            assert_eq!(
                ordinal(n, Gender::Indeterminate, Singular).unwrap(),
                ordinal(n, Gender::Masculine, Singular).unwrap(),
                "ordinal {n}"
            );
        }
        assert_eq!(
            fractional(2, Gender::Indeterminate, Singular).unwrap(),
            "meio",
            "the one gendered fractional still takes the masculine under `i`"
        );
    }

    // === ordinals ===============================================================================

    fn om(n: i128) -> String {
        ordinal(n, Gender::Masculine, Singular).expect("in range")
    }

    #[test]
    fn ordinal_units_and_teens() {
        for (n, w) in [
            (1, "primeiro"),
            (2, "segundo"),
            (3, "terceiro"),
            (4, "quarto"),
            (5, "quinto"),
            (6, "sexto"),
            (7, "sétimo"),
            (8, "oitavo"),
            (9, "nono"),
            (10, "décimo"),
            (11, "décimo primeiro"),
            (12, "décimo segundo"),
            (13, "décimo terceiro"),
            (14, "décimo quarto"),
            (15, "décimo quinto"),
            (16, "décimo sexto"),
            (17, "décimo sétimo"),
            (18, "décimo oitavo"),
            (19, "décimo nono"),
            (20, "vigésimo"),
            (21, "vigésimo primeiro"),
        ] {
            assert_eq!(om(n), w);
        }
    }

    #[test]
    fn ordinal_tens_are_the_irregular_latinate_forms() {
        for (n, w) in [
            (10, "décimo"),
            (20, "vigésimo"),
            (30, "trigésimo"),
            (40, "quadragésimo"),
            (50, "quinquagésimo"),
            (60, "sexagésimo"),
            (70, "septuagésimo"),
            (80, "octogésimo"),
            (90, "nonagésimo"),
        ] {
            assert_eq!(om(n), w);
        }
    }

    #[test]
    fn ordinal_hundreds_are_the_irregular_latinate_forms() {
        for (n, w) in [
            (100, "centésimo"),
            (200, "ducentésimo"),
            (300, "trecentésimo"),
            (400, "quadringentésimo"),
            (500, "quingentésimo"),
            (600, "sexcentésimo"),
            (700, "septingentésimo"),
            (800, "octingentésimo"),
            (900, "nongentésimo"),
        ] {
            assert_eq!(om(n), w);
        }
    }

    /// Ordinal components are juxtaposed with **no** `e`, unlike cardinals.
    #[test]
    fn ordinal_compounds_carry_no_conjunction() {
        assert_eq!(om(101), "centésimo primeiro");
        assert_eq!(om(110), "centésimo décimo");
        assert_eq!(om(999), "nongentésimo nonagésimo nono");
        assert_eq!(om(1_000), "milésimo");
        assert_eq!(om(1_432), "milésimo quadringentésimo trigésimo segundo");
        assert_eq!(om(1_999), "milésimo nongentésimo nonagésimo nono");
        for n in [101, 110, 999, 1_432, 1_999] {
            assert!(!om(n).contains(" e "), "{n}: ordinals take no `e`");
        }
    }

    #[test]
    fn ordinals_agree_in_gender_and_number_on_every_component() {
        assert_eq!(ordinal(1, Gender::Feminine, Singular).unwrap(), "primeira");
        assert_eq!(ordinal(2, Gender::Feminine, Singular).unwrap(), "segunda");
        assert_eq!(ordinal(1, Gender::Masculine, Plural).unwrap(), "primeiros");
        assert_eq!(ordinal(1, Gender::Feminine, Plural).unwrap(), "primeiras");
        assert_eq!(
            ordinal(21, Gender::Feminine, Singular).unwrap(),
            "vigésima primeira"
        );
        assert_eq!(
            ordinal(21, Gender::Feminine, Plural).unwrap(),
            "vigésimas primeiras"
        );
        assert_eq!(
            ordinal(1_432, Gender::Feminine, Singular).unwrap(),
            "milésima quadringentésima trigésima segunda"
        );
    }

    /// The contract example from the template peer: `a segunda ata`.
    #[test]
    fn ordinal_serves_the_template_contract() {
        assert_eq!(
            format!(
                "{} ({}) ata",
                2,
                ordinal(2, Gender::Feminine, Singular).unwrap()
            ),
            "2 (segunda) ata"
        );
    }

    #[test]
    fn every_ordinal_in_range_renders_cleanly() {
        for n in 1..=MAX_ORDINAL {
            for gender in [Gender::Masculine, Gender::Feminine, Gender::Indeterminate] {
                for number in [Singular, Plural] {
                    let w = ordinal(n, gender, number).expect("in range");
                    assert!(!w.is_empty(), "{n} rendered empty");
                    assert_eq!(w, w.trim(), "{n} edge whitespace: {w:?}");
                    assert!(!w.contains("  "), "{n} double space: {w:?}");
                    assert!(!w.contains(" e "), "{n} ordinals take no `e`: {w:?}");
                    let tail = if gender.is_feminine() { 'a' } else { 'o' };
                    let expected_end = if number == Plural {
                        format!("{tail}s")
                    } else {
                        tail.to_string()
                    };
                    assert!(
                        w.ends_with(&expected_end),
                        "{n} must agree: {w:?} should end in {expected_end:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn ordinal_rejections() {
        assert!(matches!(
            ordinal(0, Gender::Masculine, Singular),
            Err(NumeralError::NoSuchNumeral { value: 0, .. })
        ));
        assert!(matches!(
            ordinal(-1, Gender::Masculine, Singular),
            Err(NumeralError::Negative { .. })
        ));
        assert!(ordinal(MAX_ORDINAL, Gender::Masculine, Singular).is_ok());
        let err = ordinal(2_000, Gender::Masculine, Singular).unwrap_err();
        assert!(matches!(err, NumeralError::OutOfRange { .. }));
        // The message must name the competing forms, so the reader knows it is a ruling and not a
        // gap someone forgot to fill.
        let text = err.to_string();
        assert!(text.contains("dois milésimo"), "{text}");
        assert!(text.contains("segundo milésimo"), "{text}");
    }

    // === fractionals ============================================================================

    fn fr(n: i128) -> String {
        fractional(n, Gender::Masculine, Singular).expect("in range")
    }

    /// `meio` and `terço` are suppletive; 4–10 reuse the ordinal.
    #[test]
    fn fractional_suppletive_and_ordinal_forms() {
        assert_eq!(fr(2), "meio");
        assert_eq!(fractional(2, Gender::Feminine, Singular).unwrap(), "meia");
        assert_eq!(fr(3), "terço");
        for (n, w) in [
            (4, "quarto"),
            (5, "quinto"),
            (6, "sexto"),
            (7, "sétimo"),
            (8, "oitavo"),
            (9, "nono"),
            (10, "décimo"),
        ] {
            assert_eq!(fr(n), w, "{n} reuses its single-word ordinal");
        }
    }

    /// From eleven up, a compound ordinal means the `avos` form instead.
    #[test]
    fn fractional_avos_from_eleven() {
        assert_eq!(fr(11), "onze avos");
        assert_eq!(fr(12), "doze avos");
        assert_eq!(fr(13), "treze avos");
        assert_eq!(fr(17), "dezassete avos", "pt-PT `dezassete`");
        assert_eq!(fr(23), "vinte e três avos");
        assert_eq!(fr(115), "cento e quinze avos");
        assert_eq!(fr(1_432), "mil quatrocentos e trinta e dois avos");
    }

    /// The exact tens, hundreds, 1000 and 1 000 000 keep their single-word ordinal.
    #[test]
    fn fractional_round_values_use_the_single_word_ordinal() {
        assert_eq!(fr(20), "vigésimo");
        assert_eq!(fr(50), "quinquagésimo");
        assert_eq!(fr(90), "nonagésimo");
        assert_eq!(fr(100), "centésimo");
        assert_eq!(fr(500), "quingentésimo");
        assert_eq!(fr(900), "nongentésimo");
        assert_eq!(fr(1_000), "milésimo");
        assert_eq!(
            fr(1_000_000),
            "milionésimo",
            "reachable as a fractional even though ordinals stop at 1999"
        );
        // …but a value between them is a compound, so it falls back to `avos`.
        assert_eq!(fr(2_000), "dois mil avos");
        assert_eq!(fr(101), "cento e um avos");
    }

    /// Fractionals agree in number with the numerator: `dois terços`, `três quartos`.
    #[test]
    fn fractionals_pluralise_with_the_numerator() {
        assert_eq!(fractional(3, Gender::Masculine, Plural).unwrap(), "terços");
        assert_eq!(fractional(4, Gender::Masculine, Plural).unwrap(), "quartos");
        assert_eq!(fractional(2, Gender::Masculine, Plural).unwrap(), "meios");
        assert_eq!(fractional(2, Gender::Feminine, Plural).unwrap(), "meias");
        assert_eq!(
            fractional(100, Gender::Masculine, Plural).unwrap(),
            "centésimos"
        );
        // The `avos` form is invariable: `um doze avos`, `sete doze avos`.
        assert_eq!(
            fractional(12, Gender::Masculine, Plural).unwrap(),
            "doze avos"
        );
        // The phrase a template builds.
        assert_eq!(
            format!(
                "{} {}",
                m(2),
                fractional(3, Gender::Masculine, Plural).unwrap()
            ),
            "dois terços"
        );
    }

    /// Only `meio`/`meia` inflects for gender. Everything else is a masculine noun, and asking for
    /// the feminine must fail rather than silently render the masculine or coin "terça".
    #[test]
    fn fractional_gender_is_rejected_where_it_does_not_exist() {
        assert!(fractional(2, Gender::Feminine, Singular).is_ok());
        for n in [3, 4, 10, 11, 100, 1_000] {
            let err = fractional(n, Gender::Feminine, Singular).unwrap_err();
            assert!(
                matches!(err, NumeralError::GenderNotInflected { .. }),
                "{n}: {err}"
            );
            assert!(
                err.to_string().contains("metade"),
                "{n} should point at the alternative"
            );
        }
    }

    #[test]
    fn fractional_rejections() {
        for n in [0, 1] {
            assert!(matches!(
                fractional(n, Gender::Masculine, Singular),
                Err(NumeralError::NoSuchNumeral { .. })
            ));
        }
        assert!(matches!(
            fractional(-3, Gender::Masculine, Singular),
            Err(NumeralError::Negative { .. })
        ));
        assert!(matches!(
            fractional(MAX_CARDINAL + 1, Gender::Masculine, Singular),
            Err(NumeralError::OutOfRange { .. })
        ));
    }

    #[test]
    fn every_fractional_in_range_renders_cleanly() {
        let sweep = (2..=2_000).chain((2_001..=MAX_CARDINAL as u32).step_by(7_919));
        for n in sweep {
            let w = fractional(n as i128, Gender::Masculine, Singular).expect("in range");
            assert!(!w.is_empty(), "{n} rendered empty");
            assert_eq!(w, w.trim(), "{n} edge whitespace: {w:?}");
            assert!(!w.contains("  "), "{n} double space: {w:?}");
            // Either a single -o word, or the cardinal followed by `avos`.
            assert!(
                w.ends_with('o') || w.ends_with(" avos"),
                "{n} is neither an -o form nor an `avos` form: {w:?}"
            );
        }
    }

    // === multiplicatives ========================================================================

    #[test]
    fn multiplicative_series() {
        for (n, w) in [
            (2, "dobro"),
            (3, "triplo"),
            (4, "quádruplo"),
            (5, "quíntuplo"),
            (6, "sêxtuplo"),
            (7, "sétuplo"),
            (8, "óctuplo"),
            (9, "nónuplo"),
            (10, "décuplo"),
            (11, "undécuplo"),
            (12, "duodécuplo"),
            (100, "cêntuplo"),
        ] {
            assert_eq!(
                multiplicative(n, Gender::Masculine, Singular).unwrap(),
                w,
                "×{n}"
            );
        }
    }

    /// `nónuplo` is pt-PT; pt-BR writes `nônuplo`.
    #[test]
    fn multiplicative_nine_is_the_pt_pt_spelling() {
        let w = multiplicative(9, Gender::Masculine, Singular).unwrap();
        assert_eq!(w, "nónuplo");
        assert!(!w.contains('ô'), "pt-BR `nônuplo` must not appear");
    }

    /// The series is closed. 13 and 99 have no Portuguese word and must not be coined.
    #[test]
    fn multiplicative_rejections() {
        for n in [0, 1] {
            let err = multiplicative(n, Gender::Masculine, Singular).unwrap_err();
            assert!(matches!(err, NumeralError::NoSuchNumeral { .. }), "{n}");
            assert!(err.to_string().contains("dobro"), "{n}: {err}");
        }
        for n in [13, 20, 99, 101, 1_000] {
            let err = multiplicative(n, Gender::Masculine, Singular).unwrap_err();
            assert!(matches!(err, NumeralError::NoSuchNumeral { .. }), "{n}");
            assert!(err.to_string().contains("closed"), "{n}: {err}");
        }
        assert!(matches!(
            multiplicative(-2, Gender::Masculine, Singular),
            Err(NumeralError::Negative { .. })
        ));
    }

    /// The substantive series is invariable in both gender and number; the adjectival series
    /// (`dupla`, `tríplice`) is a different word set and is deliberately not served.
    #[test]
    fn multiplicatives_do_not_inflect() {
        assert!(matches!(
            multiplicative(2, Gender::Feminine, Singular),
            Err(NumeralError::GenderNotInflected { .. })
        ));
        assert!(matches!(
            multiplicative(2, Gender::Masculine, Plural),
            Err(NumeralError::NumberNotInflected { .. })
        ));
        assert!(
            multiplicative(2, Gender::Indeterminate, Singular).is_ok(),
            "`i` is masculine, which is what the series is"
        );
    }

    // === cross-form dispatch ====================================================================

    #[test]
    fn in_words_dispatches_to_each_form() {
        assert_eq!(
            in_words(100, Form::Cardinal, Gender::Masculine, Singular).unwrap(),
            "cem"
        );
        assert_eq!(
            in_words(100, Form::Ordinal, Gender::Feminine, Singular).unwrap(),
            "centésima"
        );
        assert_eq!(
            in_words(100, Form::Fractional, Gender::Masculine, Singular).unwrap(),
            "centésimo"
        );
        assert_eq!(
            in_words(100, Form::Multiplicative, Gender::Masculine, Singular).unwrap(),
            "cêntuplo"
        );
    }

    /// Cardinals have no plural of their own — `milhão`/`milhões` follows the value.
    #[test]
    fn cardinal_plural_is_rejected_not_ignored() {
        let err = in_words(2, Form::Cardinal, Gender::Masculine, Plural).unwrap_err();
        assert!(matches!(err, NumeralError::NumberNotInflected { .. }));
        assert!(err.to_string().contains("milhões"), "{err}");
        // The value-driven plural still happens on its own.
        assert_eq!(m(2_000_000), "dois milhões");
    }

    // === the filter seam ========================================================================

    use minijinja::Environment;

    fn env() -> Environment<'static> {
        let mut env = Environment::new();
        env.add_filter("in_words", in_words_filter);
        env.add_filter("plural", plural_filter);
        env
    }

    fn render(src: &str) -> Result<String, String> {
        env()
            .render_str(src, minijinja::context! {})
            .map_err(|e| format!("{e:#}"))
    }

    #[test]
    fn filter_renders_the_documented_contract() {
        assert_eq!(
            render("{{ 100 }} ({{ 100 | in_words }})").unwrap(),
            "100 (cem)"
        );
        assert_eq!(render("{{ 2 | in_words }}").unwrap(), "dois");
        assert_eq!(render(r#"{{ 2 | in_words(gender="f") }}"#).unwrap(), "duas");
        assert_eq!(render(r#"{{ 2 | in_words(gender="m") }}"#).unwrap(), "dois");
        assert_eq!(render(r#"{{ 2 | in_words(gender="i") }}"#).unwrap(), "dois");
        assert_eq!(
            render(r#"{{ 2 | in_words(form="ordinal", gender="f") }}"#).unwrap(),
            "segunda"
        );
        assert_eq!(
            render(r#"{{ 3 | in_words(form="ordinal", gender="f", number="plural") }}"#).unwrap(),
            "terceiras"
        );
        assert_eq!(
            render(r#"{{ 3 | in_words(form="fractional", number="plural") }}"#).unwrap(),
            "terços"
        );
        assert_eq!(
            render(r#"{{ 2 | in_words(form="multiplicative") }}"#).unwrap(),
            "dobro"
        );
        assert_eq!(render("{{ 0 | in_words }}").unwrap(), "zero");
    }

    #[test]
    fn plural_filter_picks_the_singular_only_at_one() {
        assert_eq!(
            render(r#"{{ 1 }} {{ 1 | plural("página", "páginas") }}"#).unwrap(),
            "1 página"
        );
        for n in [0, 2, 100, 1000] {
            let src = format!(r#"{{{{ {n} | plural("página", "páginas") }}}}"#);
            assert_eq!(render(&src).unwrap(), "páginas", "{n} takes the plural");
        }
    }

    /// The whole sentence the template peer needs, at both ends of the page-capacity range.
    #[test]
    fn the_page_capacity_sentence_reads_correctly_at_one_and_at_a_hundred() {
        let src = r#"O livro compõe-se de {{ n }} ({{ n | in_words(gender="f") }}) {{ n | plural("página", "páginas") }}."#;
        let out = |n: u32| {
            env()
                .render_str(src, minijinja::context! { n => n })
                .expect("renders")
        };
        assert_eq!(out(1), "O livro compõe-se de 1 (uma) página.");
        assert_eq!(out(2), "O livro compõe-se de 2 (duas) páginas.");
        assert_eq!(out(100), "O livro compõe-se de 100 (cem) páginas.");
    }

    #[test]
    fn filter_rejects_bad_parameter_values() {
        let err = render(r#"{{ 2 | in_words(gender="fem") }}"#).unwrap_err();
        assert!(err.contains("gender"), "{err}");
        assert!(err.contains("\"fem\""), "{err}");

        let err = render(r#"{{ 2 | in_words(form="collective") }}"#).unwrap_err();
        assert!(err.contains("dezena"), "the error should say why: {err}");

        let err = render(r#"{{ 2 | in_words(number="dual") }}"#).unwrap_err();
        assert!(err.contains("plural"), "{err}");
    }

    /// A misspelled keyword must fail rather than silently fall back to a default. `genero=` is the
    /// old pre-rename spelling and must not quietly work.
    #[test]
    fn filter_rejects_an_unknown_keyword() {
        for src in [
            r#"{{ 2 | in_words(genero="f") }}"#,
            r#"{{ 2 | in_words(género="f") }}"#,
            r#"{{ 2 | in_words(sexo="f") }}"#,
            r#"{{ 2 | in_words(forma="ordinal") }}"#,
        ] {
            assert!(
                render(src).is_err(),
                "{src} must fail rather than quietly render the default"
            );
        }
    }

    #[test]
    fn filter_rejects_non_integers() {
        for src in [
            "{{ 1.5 | in_words }}",
            "{{ 100.0 | in_words }}",
            r#"{{ "100" | in_words }}"#,
            r#"{{ "" | in_words }}"#,
            "{{ none | in_words }}",
            "{{ nao_existe | in_words }}",
            "{{ [1, 2] | in_words }}",
            "{{ true | in_words }}",
            r#"{{ none | plural("página", "páginas") }}"#,
        ] {
            let err = render(src).unwrap_err();
            assert!(
                err.contains("integer"),
                "{src} should be refused as a non-integer, got: {err}"
            );
        }
    }

    #[test]
    fn filter_rejects_out_of_domain_numbers() {
        assert!(
            render("{{ -1 | in_words }}")
                .unwrap_err()
                .contains("negative")
        );
        let err = render("{{ 1000000000 | in_words }}").unwrap_err();
        assert!(err.contains("bilião"), "{err}");
        assert!(err.contains("bilhão"), "{err}");
        assert!(
            render(r#"{{ 2000 | in_words(form="ordinal") }}"#)
                .unwrap_err()
                .contains("unsettled")
        );
    }

    /// The `page_capacity` of a termo de encerramento is `None`, which reaches the template as
    /// `none`. It must stop the render, not print "none" or an empty parenthetical.
    #[test]
    fn filter_refuses_an_unset_page_capacity() {
        let ctx = minijinja::context! { page_capacity => Option::<u32>::None };
        assert!(
            env()
                .render_str("{{ page_capacity | in_words }}", ctx)
                .is_err(),
            "an unset Option must fail the render"
        );
    }

    /// minijinja's `is defined` is `!is_undefined()`, so it is **true for a `none`**. This pins the
    /// behaviour the module doc warns template authors about: `is defined` does not guard an unset
    /// `Option`, and `is not none` does.
    #[test]
    fn is_defined_does_not_guard_a_none_but_is_not_none_does() {
        let ctx = || minijinja::context! { n => Option::<u32>::None };
        assert!(
            env()
                .render_str("{% if n is defined %}{{ n | in_words }}{% endif %}", ctx())
                .is_err(),
            "`is defined` lets a none through to the filter"
        );
        assert_eq!(
            env()
                .render_str("{% if n is not none %}{{ n | in_words }}{% endif %}", ctx())
                .expect("guarded"),
            ""
        );
    }

    /// The filters are reachable under the real author-facing environment, not only a local one.
    #[test]
    fn filters_are_registered_in_the_author_environment() {
        assert!(crate::compile_template_str("{{ n | in_words }}").is_ok());
        assert!(crate::compile_template_str(r#"{{ n | in_words(gender="f") }}"#).is_ok());
        assert!(crate::compile_template_str(r#"{{ n | in_words(form="ordinal") }}"#).is_ok());
        assert!(crate::compile_template_str(r#"{{ n | plural("a", "b") }}"#).is_ok());
    }
}
