//! JSON request construction and response parsing for AMA's SCMD service (`AppSCMDService.svc`).
//!
//! The service speaks ASP.NET-AJAX JSON, not SOAP: each operation is a sibling path segment under
//! the `.svc` endpoint (`/GetCertificate`, `/SCMDSign`, `/ValidateOtp`), the request is a JSON
//! object with PascalCase members, and a successful response may be wrapped in the ASP.NET
//! `{"d": ...}` envelope. This mirrors the working reference `recov-pt`
//! (`src/cli/cmd_challenge.rs`, `src/cli/cmd_verify.rs`), which completes the full CMD flow against
//! the live service — so the field names, encodings, and response shapes here are aligned to it
//! byte for byte, not to the older SOAP `CCMovelDigitalSignature.svc` contract.

use serde::Serialize;
use serde_json::Value;

use crate::error::CmdError;

/// Operation path segment and [`crate::transport::ScmdTransport`] routing key for `GetCertificate`.
pub const OP_GET_CERTIFICATE: &str = "GetCertificate";
/// Operation path segment and routing key for `SCMDSign` — the mobile SCMD service's sign
/// operation (recov-pt `src/cli/cmd_challenge.rs:18`; the SOAP generation named it `CCMovelSign`).
pub const OP_SCMD_SIGN: &str = "SCMDSign";
/// Operation path segment and routing key for `ValidateOtp`.
pub const OP_VALIDATE_OTP: &str = "ValidateOtp";

// --- Requests ----------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct GetCertificateRequest<'a> {
    application_id: &'a str,
    user_id: &'a str,
}

/// Serialize the `GetCertificate` JSON body.
///
/// `application_id` is the **raw** AMA string (never base64-encoded; recov-pt
/// `src/cli/cmd_verify.rs:1097`). `user_id_field` is the citizen mobile already passed through the
/// field encryptor (recov-pt encrypts the mobile for `GetCertificate` too,
/// `src/cli/cmd_verify.rs:544-545,680-683`).
pub(crate) fn get_certificate_body(
    application_id: &str,
    user_id_field: &str,
) -> Result<String, CmdError> {
    to_json(&GetCertificateRequest {
        application_id,
        user_id: user_id_field,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ScmdSignRequest<'a> {
    application_id: &'a str,
    user_id: &'a str,
    pin: &'a str,
    hash: &'a str,
    doc_name: &'a str,
}

/// Serialize the `SCMDSign` JSON body (recov-pt `src/cli/cmd_challenge.rs:85-112`).
///
/// `hash_b64` is the base64 of the 51-byte RFC 8017 §9.2 `DigestInfo` (built by
/// [`crate::flow::ccmovel_sign_hash`]); `pin_field` and `user_id_field` are already field-encrypted.
pub(crate) fn scmd_sign_body(
    application_id: &str,
    doc_name: &str,
    hash_b64: &str,
    pin_field: &str,
    user_id_field: &str,
) -> Result<String, CmdError> {
    to_json(&ScmdSignRequest {
        application_id,
        user_id: user_id_field,
        pin: pin_field,
        hash: hash_b64,
        doc_name,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ValidateOtpRequest<'a> {
    application_id: &'a str,
    code: &'a str,
    process_id: &'a str,
    // recov-pt sends this camelCase member, always `false` (`src/cli/cmd_challenge.rs:145-161`).
    #[serde(rename = "isBiometricValidation")]
    is_biometric_validation: bool,
}

/// Serialize the `ValidateOtp` JSON body (recov-pt `src/cli/cmd_challenge.rs:139-164`).
///
/// `code_field` is the OTP already passed through the field encryptor.
pub(crate) fn validate_otp_body(
    application_id: &str,
    code_field: &str,
    process_id: &str,
) -> Result<String, CmdError> {
    to_json(&ValidateOtpRequest {
        application_id,
        code: code_field,
        process_id,
        is_biometric_validation: false,
    })
}

fn to_json<T: Serialize>(request: &T) -> Result<String, CmdError> {
    serde_json::to_string(request)
        .map_err(|e| CmdError::RequestBuild(format!("failed to serialize SCMD request: {e}")))
}

// --- Responses ---------------------------------------------------------------------------------

/// The parsed `SCMDSign` status (recov-pt `src/cli/cmd_challenge.rs:118-137`).
pub(crate) struct SignOutcome {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) process_id: Option<String>,
}

/// The parsed `ValidateOtp` result (recov-pt `src/cli/cmd_challenge.rs:169-207`).
pub(crate) struct OtpOutcome {
    pub(crate) code: String,
    pub(crate) message: String,
    /// The raw signature bytes, decoded from the JSON **integer array** the service returns — not
    /// base64 (recov-pt `src/cli/cmd_challenge.rs:190-206`). `None` when the field is absent/null.
    pub(crate) signature: Option<Vec<u8>>,
}

/// The most JSON-string framing layers [`get_certificate_pem`] will peel before it refuses.
///
/// AMA has been observed **double-encoding** the certificate: the `{"d": ...}` envelope carries a
/// value that is itself a JSON-string-encoded PEM, so one unwrap leaves a literal leading `"`
/// (U+0022) on the payload — which the chain sanitiser correctly refuses as junk outside the PEM
/// blocks. One extra parse peels that layer. The bound exists only so a pathological, deeply nested
/// input cannot loop: two layers is what the real service produces; eight is generous headroom that
/// still terminates.
const MAX_JSON_STRING_LAYERS: usize = 8;

/// Extract the certificate PEM from a `GetCertificate` JSON response.
///
/// The payload is a PEM string, either bare, `{"d":"<pem>"}`-wrapped, or under a
/// `GetCertificateResult` member (recov-pt `src/cli/cmd_verify.rs:1617-1638`,
/// `decode_certificate_response`). recov-pt unwraps that one envelope and feeds the string straight
/// to its chain decoder; this does the same, then additionally peels any residual JSON-string
/// framing (see [`unwrap_json_string_layers`]) so a double-encoded `d` — a genuine, observed AMA
/// shape recov-pt does *not* itself handle — reaches the sanitiser as bare PEM rather than as a
/// quote-prefixed string it would reject at byte offset 0.
///
/// The framing is peeled by *parsing* the JSON string, never by stripping the `"` bytes: parsing
/// removes exactly one genuine JSON-string transport layer and errors on anything that is not one,
/// so a `"` that legitimately sat inside content could never be corrupted. The certificate bytes
/// that reach the chain sanitiser are exactly what AMA put inside the innermost string.
pub(crate) fn get_certificate_pem(body: &str) -> Result<String, CmdError> {
    let payload = if body.trim_start().starts_with('{') {
        let value: Value = serde_json::from_str(body).map_err(|e| {
            CmdError::ResponseParse(format!("GetCertificate response is not JSON: {e}"))
        })?;
        match value
            .get("d")
            .or_else(|| value.get("GetCertificateResult"))
            .unwrap_or(&value)
        {
            Value::String(pem) => pem.clone(),
            _ => {
                return Err(CmdError::ResponseParse(
                    "GetCertificate response carried no certificate PEM string".to_string(),
                ));
            }
        }
    } else {
        // A bare PEM body (not JSON-wrapped) — but it may still be a JSON-string-framed PEM.
        body.to_string()
    };
    unwrap_json_string_layers(payload)
}

/// Peel any JSON-string framing off an extracted certificate payload, leaving the bare PEM.
///
/// A payload whose first byte is `"` is a JSON-string layer (a bare PEM begins with `-----BEGIN`,
/// never a quote), so it is re-parsed as a JSON string and the check repeats. A payload that does
/// not begin with `"` is handed back untouched — the chain sanitiser, not this function, is the
/// guard on the actual certificate bytes. A leading `"` that does **not** parse as a JSON string is
/// refused loudly rather than guessed at: the transport layer only ever removes a genuine JSON
/// string, never a `"` that belongs to the content.
fn unwrap_json_string_layers(mut payload: String) -> Result<String, CmdError> {
    for _ in 0..MAX_JSON_STRING_LAYERS {
        if !payload.starts_with('"') {
            return Ok(payload);
        }
        payload = serde_json::from_str::<String>(&payload).map_err(|e| {
            CmdError::ResponseParse(format!(
                "GetCertificate certificate payload began with a quote but was not a \
                 JSON-encoded string: {e}"
            ))
        })?;
    }
    if payload.starts_with('"') {
        return Err(CmdError::ResponseParse(format!(
            "GetCertificate certificate payload was still JSON-string-wrapped after \
             {MAX_JSON_STRING_LAYERS} unwrapping passes"
        )));
    }
    Ok(payload)
}

/// Parse an `SCMDSign` response, unwrapping the `{"d": ...}` envelope if present.
pub(crate) fn parse_scmd_sign(body: &str) -> Result<SignOutcome, CmdError> {
    let value = parse_direct_or_wrapped(body)?;
    let object = value.as_object().ok_or_else(|| {
        CmdError::ResponseParse("SCMDSign response is not a JSON object".to_string())
    })?;
    let code = require_string_code(object.get("Code"), "SCMDSign")?;
    let message = object
        .get("Message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let process_id = object
        .get("ProcessId")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(SignOutcome {
        code,
        message,
        process_id,
    })
}

/// Parse a `ValidateOtp` response, unwrapping the `{"d": ...}` envelope if present.
pub(crate) fn parse_validate_otp(body: &str) -> Result<OtpOutcome, CmdError> {
    let value = parse_direct_or_wrapped(body)?;
    let object = value.as_object().ok_or_else(|| {
        CmdError::ResponseParse("ValidateOtp response is not a JSON object".to_string())
    })?;
    let status = object
        .get("Status")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CmdError::ResponseParse("ValidateOtp response missing `Status`".to_string())
        })?;
    let code = require_string_code(status.get("Code"), "ValidateOtp")?;
    let message = status
        .get("Message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let signature = match object.get("Signature") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(signature_bytes(items)?),
        Some(_) => {
            return Err(CmdError::ResponseParse(
                "ValidateOtp `Signature` was not a byte array".to_string(),
            ));
        }
    };
    Ok(OtpOutcome {
        code,
        message,
        signature,
    })
}

/// Decode the `Signature` integer array into bytes, rejecting empty arrays and out-of-range items.
fn signature_bytes(items: &[Value]) -> Result<Vec<u8>, CmdError> {
    if items.is_empty() {
        return Err(CmdError::ResponseParse(
            "ValidateOtp `Signature` array was empty".to_string(),
        ));
    }
    items
        .iter()
        .map(|item| {
            item.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| {
                    CmdError::ResponseParse(
                        "ValidateOtp `Signature` array had a non-byte element".to_string(),
                    )
                })
        })
        .collect()
}

/// Unwrap the ASP.NET-AJAX `{"d": ...}` envelope. A string `d` is re-parsed as JSON; an object `d`
/// is returned directly; no `d` member returns the value as-is (recov-pt
/// `src/cli/cmd_challenge.rs:209-223`).
fn parse_direct_or_wrapped(body: &str) -> Result<Value, CmdError> {
    let mut value: Value = serde_json::from_str(body)
        .map_err(|e| CmdError::ResponseParse(format!("SCMD response is not JSON: {e}")))?;
    let Some(wrapped) = value.as_object_mut().and_then(|object| object.remove("d")) else {
        return Ok(value);
    };
    match wrapped {
        Value::String(json) => serde_json::from_str(&json)
            .map_err(|e| CmdError::ResponseParse(format!("SCMD `d` payload is not JSON: {e}"))),
        other => Ok(other),
    }
}

/// The SCMD status `Code` is always a **string** (recov-pt requires a string, rejecting a numeric
/// `200`; `src/cli/cmd_challenge.rs:225-237`). `operation` names the caller for the error message.
fn require_string_code(code: Option<&Value>, operation: &str) -> Result<String, CmdError> {
    code.and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            CmdError::ResponseParse(format!("{operation} response missing string `Code`"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(body: &str) -> Value {
        serde_json::from_str(body).expect("valid serialized request")
    }

    #[test]
    fn operation_segments_match_the_reference() {
        assert_eq!(OP_GET_CERTIFICATE, "GetCertificate");
        assert_eq!(OP_SCMD_SIGN, "SCMDSign");
        assert_eq!(OP_VALIDATE_OTP, "ValidateOtp");
    }

    #[test]
    fn get_certificate_body_sends_raw_application_id_and_pascalcase_members() {
        let body = get_certificate_body("f0f428c2-app-id", "encrypted-user").unwrap();
        assert_eq!(
            json(&body),
            serde_json::json!({
                "ApplicationId": "f0f428c2-app-id",
                "UserId": "encrypted-user",
            })
        );
    }

    #[test]
    fn scmd_sign_body_is_the_five_member_pascalcase_contract() {
        let body =
            scmd_sign_body("app-id", "livro.pdf", "aGFzaA==", "enc-pin", "enc-user").unwrap();
        let value = json(&body);
        assert_eq!(
            value,
            serde_json::json!({
                "ApplicationId": "app-id",
                "UserId": "enc-user",
                "Pin": "enc-pin",
                "Hash": "aGFzaA==",
                "DocName": "livro.pdf",
            })
        );
        assert_eq!(value.as_object().unwrap().len(), 5);
    }

    #[test]
    fn validate_otp_body_carries_is_biometric_validation_false() {
        let body = validate_otp_body("app-id", "enc-otp", "process-123").unwrap();
        let value = json(&body);
        assert_eq!(
            value,
            serde_json::json!({
                "ApplicationId": "app-id",
                "Code": "enc-otp",
                "ProcessId": "process-123",
                "isBiometricValidation": false,
            })
        );
        assert_eq!(value.as_object().unwrap().len(), 4);
    }

    #[test]
    fn parses_direct_and_d_wrapped_scmd_sign() {
        let direct = parse_scmd_sign(r#"{"Code":"200","Message":"ok","ProcessId":"p-1"}"#).unwrap();
        assert_eq!(direct.code, "200");
        assert_eq!(direct.process_id.as_deref(), Some("p-1"));

        let object_wrapped =
            parse_scmd_sign(r#"{"d":{"Code":"200","Message":"ok","ProcessId":"p-2"}}"#).unwrap();
        assert_eq!(object_wrapped.process_id.as_deref(), Some("p-2"));

        let string_wrapped =
            parse_scmd_sign(r#"{"d":"{\"Code\":\"200\",\"ProcessId\":\"p-3\"}"}"#).unwrap();
        assert_eq!(string_wrapped.process_id.as_deref(), Some("p-3"));
    }

    #[test]
    fn scmd_sign_requires_a_string_code() {
        assert!(parse_scmd_sign(r#"{"Code":200,"ProcessId":"p"}"#).is_err());
        assert!(parse_scmd_sign(r#"{"ProcessId":"p"}"#).is_err());
        assert!(parse_scmd_sign("not-json").is_err());
    }

    #[test]
    fn validate_otp_decodes_the_signature_integer_array() {
        let outcome = parse_validate_otp(
            r#"{"Status":{"Code":"200","Message":"done"},"Signature":[0,1,127,128,254,255]}"#,
        )
        .unwrap();
        assert_eq!(outcome.code, "200");
        assert_eq!(outcome.signature.unwrap(), [0, 1, 127, 128, 254, 255]);
    }

    #[test]
    fn validate_otp_rejects_base64_or_out_of_range_signature() {
        // A base64 string is NOT how this service returns the signature — it is an integer array.
        assert!(parse_validate_otp(r#"{"Status":{"Code":"200"},"Signature":"AQID"}"#).is_err());
        for item in ["256", "-1", "1.5", r#""1""#] {
            let body = format!(r#"{{"Status":{{"Code":"200"}},"Signature":[{item}]}}"#);
            assert!(parse_validate_otp(&body).is_err(), "{item}");
        }
    }

    #[test]
    fn validate_otp_carries_status_code_and_absent_signature() {
        let rejected = parse_validate_otp(
            r#"{"d":{"Status":{"Code":"402","Message":"bad otp"},"Signature":null}}"#,
        )
        .unwrap();
        assert_eq!(rejected.code, "402");
        assert_eq!(rejected.message, "bad otp");
        assert!(rejected.signature.is_none());
    }

    #[test]
    fn get_certificate_pem_reads_bare_wrapped_and_result_forms() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(get_certificate_pem(pem).unwrap(), pem);

        let wrapped = serde_json::json!({ "d": pem }).to_string();
        assert_eq!(get_certificate_pem(&wrapped).unwrap(), pem);

        let result = serde_json::json!({ "GetCertificateResult": pem }).to_string();
        assert_eq!(get_certificate_pem(&result).unwrap(), pem);

        assert!(get_certificate_pem(r#"{"d":null}"#).is_err());
    }

    /// The live-blocking failure: AMA double-encodes the certificate, so `d` holds a value that is
    /// itself a JSON-string-encoded PEM. One unwrap leaves a literal leading `"` (U+0022 at offset
    /// 0), which the chain sanitiser correctly refuses. `get_certificate_pem` must peel the extra
    /// layer and hand back the bare PEM.
    ///
    /// Reproduce-then-fix: before the peel, the extracted value was the quoted inner string and this
    /// asserts the fix yields the bare PEM instead. The PEM here is a fixture, not a real AMA
    /// certificate — this function unwraps framing; the certificate bytes are validated downstream by
    /// the chain sanitiser.
    #[test]
    fn get_certificate_pem_peels_a_double_encoded_payload() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

        // The inner layer AMA wraps around the PEM: the PEM rendered AS a JSON string, so its text
        // begins with a `"`. serde builds it correctly (quotes added, `\n` escaped).
        let inner_json_string = serde_json::to_string(pem).unwrap();
        assert!(
            inner_json_string.starts_with('"'),
            "the inner layer must be a JSON-string-framed PEM"
        );

        // The outer `{"d": ...}` envelope carrying that JSON-string TEXT as its value — the wire
        // shape that reaches the transport double-encoded.
        let double = serde_json::json!({ "d": inner_json_string }).to_string();

        // The value the OLD code would have returned is the still-quoted inner string, which the
        // chain sanitiser rejects at byte offset 0. Pin that this is exactly what was reaching it.
        let singly_unwrapped: Value = serde_json::from_str(&double).unwrap();
        assert_eq!(
            singly_unwrapped.get("d").and_then(Value::as_str),
            Some(inner_json_string.as_str()),
            "a single unwrap leaves the JSON-string-framed PEM, quote and all"
        );
        assert!(inner_json_string.starts_with('"'));

        // After the fix the payload is fully unwrapped to the bare PEM, quote gone.
        let unwrapped = get_certificate_pem(&double).unwrap();
        assert_eq!(unwrapped, pem);
        assert!(!unwrapped.starts_with('"'));

        // The bare-string form of the same double-encoding (no `{"d": ...}` envelope) is peeled too.
        assert_eq!(get_certificate_pem(&inner_json_string).unwrap(), pem);
    }

    /// A leading `"` that is not a valid JSON string is refused, never byte-stripped: the transport
    /// layer only removes a genuine JSON-string frame, and anything else fails loudly.
    #[test]
    fn get_certificate_pem_refuses_a_bare_quote_that_is_not_a_json_string() {
        // A lone quote, and a quote followed by non-JSON text, are both corruption, not framing.
        assert!(get_certificate_pem("\"").is_err());
        assert!(get_certificate_pem("\"-----BEGIN CERTIFICATE-----").is_err());
    }
}
