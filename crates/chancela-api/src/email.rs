use crate::error::ApiError;

const MAX_EMAIL_LEN: usize = 254;

/// Normalize an optional contact email accepted by management/edit endpoints.
///
/// Empty or whitespace-only values clear the field. The validator is intentionally conservative:
/// it rejects obvious non-addresses without trying to implement full RFC 5322 parsing.
pub(crate) fn normalize_optional_email(
    raw: Option<String>,
    field: &'static str,
) -> Result<Option<String>, ApiError> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let email = value.trim();
    if email.is_empty() {
        return Ok(None);
    }
    if email.len() > MAX_EMAIL_LEN {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be at most {MAX_EMAIL_LEN} characters"
        )));
    }
    if !looks_like_email(email) {
        return Err(ApiError::Unprocessable(format!(
            "{field} must look like an email address"
        )));
    }
    Ok(Some(email.to_ascii_lowercase()))
}

fn looks_like_email(value: &str) -> bool {
    if value.chars().any(char::is_whitespace) || value.matches('@').count() != 1 {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.trim().is_empty() || domain.trim().is_empty() || domain.trim().ends_with('.') {
        return false;
    }
    domain.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_optional_email_trims_lowercases_and_clears_blank_values() {
        assert_eq!(
            normalize_optional_email(Some("  Ana.Example@Example.PT  ".to_owned()), "email")
                .expect("valid email"),
            Some("ana.example@example.pt".to_owned())
        );
        assert_eq!(
            normalize_optional_email(Some("   ".to_owned()), "email").expect("blank clears"),
            None
        );
        assert_eq!(
            normalize_optional_email(None, "email").expect("missing clears"),
            None
        );
    }

    #[test]
    fn normalize_optional_email_rejects_obvious_non_addresses() {
        for value in [
            "ana",
            "ana@example",
            "ana@@example.pt",
            "ana @example.pt",
            "ana@example.pt.",
        ] {
            assert!(
                normalize_optional_email(Some(value.to_owned()), "email").is_err(),
                "{value:?} must be rejected"
            );
        }
    }
}
