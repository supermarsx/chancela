//! Hand-built SOAP 1.1 envelopes and response parsing for the AMA SCMD contract.
//!
//! There is no mature Rust WCF/SOAP codegen, so we build the three operation envelopes
//! (`GetCertificate`, `CCMovelSign`, `ValidateOtp`) as strings and parse responses with
//! `quick-xml`, matching element **local names** (namespace-prefix-agnostic). The exact
//! contract is anchored to SCMD v1.6 and must be re-verified against the certified
//! `doc-CMD-assinatura` spec before PROD (spec 04 §1.3, risk #6).

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::CmdError;

/// AMA SCMD WCF operation/message namespace, as advertised by the upstream WSDL.
pub(crate) const NS_AMA_SERVICE: &str = "http://Ama.Authentication.Service/";
/// The data-contract namespace of the SCMD request/response members.
pub(crate) const NS_CMD_DATA: &str =
    "http://schemas.datacontract.org/2004/07/Ama.Authentication.Service.Services.CMDService";

/// SOAPAction for `GetCertificate`.
pub const ACTION_GET_CERTIFICATE: &str =
    "http://Ama.Authentication.Service/CCMovelSignature/GetCertificate";
/// SOAPAction for `CCMovelSign`.
pub const ACTION_CCMOVEL_SIGN: &str =
    "http://Ama.Authentication.Service/CCMovelSignature/CCMovelSign";
/// SOAPAction for `ValidateOtp`.
pub const ACTION_VALIDATE_OTP: &str =
    "http://Ama.Authentication.Service/CCMovelSignature/ValidateOtp";

/// Minimal XML text escaping for element content.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Build the `GetCertificate` envelope. `application_id_b64` is the base64 ApplicationId;
/// `user_id` is the citizen phone number (`+351 XXXXXXXXX`).
pub(crate) fn get_certificate_envelope(application_id_b64: &str, user_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="{ns}">
  <s:Header/>
  <s:Body>
    <tem:GetCertificate>
      <tem:applicationId>{app}</tem:applicationId>
      <tem:userId>{user}</tem:userId>
    </tem:GetCertificate>
  </s:Body>
</s:Envelope>"#,
        ns = NS_AMA_SERVICE,
        app = xml_escape(application_id_b64),
        user = xml_escape(user_id),
    )
}

/// Build the `CCMovelSign` envelope. `pin_field` and `user_id_field` are already passed
/// through the [`crate::field_encryption::FieldEncryptor`] (cleartext or encrypted+base64).
/// Data-contract members are emitted in the WCF-canonical alphabetical order.
pub(crate) fn ccmovel_sign_envelope(
    application_id_b64: &str,
    doc_name: &str,
    hash_b64: &str,
    pin_field: &str,
    user_id_field: &str,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="{tem}">
  <s:Header/>
  <s:Body>
    <tem:CCMovelSign>
      <tem:request xmlns:d="{data}">
        <d:ApplicationId>{app}</d:ApplicationId>
        <d:DocName>{doc}</d:DocName>
        <d:Hash>{hash}</d:Hash>
        <d:Pin>{pin}</d:Pin>
        <d:UserId>{user}</d:UserId>
      </tem:request>
    </tem:CCMovelSign>
  </s:Body>
</s:Envelope>"#,
        tem = NS_AMA_SERVICE,
        data = NS_CMD_DATA,
        app = xml_escape(application_id_b64),
        doc = xml_escape(doc_name),
        hash = xml_escape(hash_b64),
        pin = xml_escape(pin_field),
        user = xml_escape(user_id_field),
    )
}

/// Build the `ValidateOtp` envelope. `otp_field` is already passed through the
/// [`crate::field_encryption::FieldEncryptor`].
pub(crate) fn validate_otp_envelope(
    application_id_b64: &str,
    process_id: &str,
    otp_field: &str,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="{ns}">
  <s:Header/>
  <s:Body>
    <tem:ValidateOtp>
      <tem:code>{otp}</tem:code>
      <tem:processId>{pid}</tem:processId>
      <tem:applicationId>{app}</tem:applicationId>
    </tem:ValidateOtp>
  </s:Body>
</s:Envelope>"#,
        ns = NS_AMA_SERVICE,
        otp = xml_escape(otp_field),
        pid = xml_escape(process_id),
        app = xml_escape(application_id_b64),
    )
}

/// Return the text content of the **shallowest** element whose local name equals `local`
/// (ignoring namespace prefix), or `None` if absent.
///
/// Depth-aware (t41-e4 L8): the original implementation returned the first match in document
/// order at any depth, which let an element injected inside a free-text field (e.g. a
/// `<Code>` placed inside `<Message>`) shadow the real top-level `<Code>` of an SCMD result.
/// We now track element depth and keep the match at the shallowest depth, so a nested
/// injection (always deeper than the real direct child of the result wrapper) is rejected.
/// In the SCMD response shape the result fields (`Code`, `ProcessId`, `Message`, `Signature`)
/// are direct children of the `*Result` wrapper; any `<Code>` nested inside `<Message>` is
/// strictly deeper and is ignored.
pub(crate) fn find_text(xml: &str, local: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let target = local.as_bytes();
    let mut depth: i64 = 0;
    // Best (shallowest-depth) completed match: (depth, value).
    let mut best: Option<(i64, String)> = None;
    // Depth of the candidate currently being captured, if any.
    let mut capture_depth: Option<i64> = None;
    let mut value = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                depth += 1;
                if e.local_name().as_ref() == target
                    && capture_depth.is_none()
                    && best.as_ref().is_none_or(|(d, _)| depth < *d)
                {
                    capture_depth = Some(depth);
                    value.clear();
                }
            }
            Ok(Event::End(e)) => {
                if let Some(cd) = capture_depth
                    && e.local_name().as_ref() == target
                    && cd == depth
                {
                    let is_best = best.as_ref().is_none_or(|(d, _)| cd < *d);
                    if is_best {
                        best = Some((cd, std::mem::take(&mut value)));
                    }
                    capture_depth = None;
                }
                depth -= 1;
            }
            // `<local/>` self-closing: a zero-length match at tree-depth `depth + 1`.
            Ok(Event::Empty(e)) if e.local_name().as_ref() == target => {
                let d = depth + 1;
                if best.as_ref().is_none_or(|(bd, _)| d < *bd) {
                    best = Some((d, String::new()));
                }
            }
            Ok(Event::Text(e)) if capture_depth.is_some() => {
                if let Ok(t) = e.xml_content(quick_xml::XmlVersion::Implicit1_0) {
                    value.push_str(&t);
                }
            }
            Ok(Event::CData(e)) if capture_depth.is_some() => {
                if let Ok(s) = std::str::from_utf8(e.as_ref()) {
                    value.push_str(s);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }
    best.map(|(_, v)| v)
}

/// If the response carries a SOAP `Fault`, return its `faultstring` (or a generic message).
pub(crate) fn fault_message(xml: &str) -> Option<String> {
    // A Fault is present iff a <Fault> element exists.
    if find_text(xml, "faultstring").is_some() || contains_element(xml, "Fault") {
        Some(
            find_text(xml, "faultstring")
                .or_else(|| find_text(xml, "Reason"))
                .or_else(|| find_text(xml, "faultcode"))
                .unwrap_or_else(|| "unspecified SOAP fault".to_string()),
        )
    } else {
        None
    }
}

/// Whether an element with the given local name appears (start or empty).
fn contains_element(xml: &str, local: &str) -> bool {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let target = local.as_bytes();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) if e.local_name().as_ref() == target => {
                return true;
            }
            Ok(Event::Eof) => return false,
            Err(_) => return false,
            _ => {}
        }
    }
}

/// A required text element, or [`CmdError::ResponseParse`] if missing.
pub(crate) fn require_text(xml: &str, local: &str) -> Result<String, CmdError> {
    find_text(xml, local)
        .ok_or_else(|| CmdError::ResponseParse(format!("missing <{local}> in SOAP response")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soap_actions_match_upstream_wsdl() {
        assert_eq!(
            ACTION_GET_CERTIFICATE,
            "http://Ama.Authentication.Service/CCMovelSignature/GetCertificate"
        );
        assert_eq!(
            ACTION_CCMOVEL_SIGN,
            "http://Ama.Authentication.Service/CCMovelSignature/CCMovelSign"
        );
        assert_eq!(
            ACTION_VALIDATE_OTP,
            "http://Ama.Authentication.Service/CCMovelSignature/ValidateOtp"
        );
    }

    #[test]
    fn escapes_xml_special_chars() {
        assert_eq!(xml_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
    }

    #[test]
    fn get_certificate_envelope_has_action_fields() {
        let env = get_certificate_envelope("QVBQSUQ=", "+351 912345678");
        assert!(env.contains(r#"xmlns:tem="http://Ama.Authentication.Service/""#));
        assert!(env.contains("<tem:GetCertificate>"));
        assert!(env.contains("<tem:applicationId>QVBQSUQ=</tem:applicationId>"));
        assert!(env.contains("<tem:userId>+351 912345678</tem:userId>"));
    }

    #[test]
    fn ccmovel_sign_members_in_alphabetical_order() {
        let env = ccmovel_sign_envelope(
            "QVBQSUQ=",
            "livro.pdf",
            "SGFzaA==",
            "1234",
            "+351 900000000",
        );
        let app = env.find("<d:ApplicationId>").unwrap();
        let doc = env.find("<d:DocName>").unwrap();
        let hash = env.find("<d:Hash>").unwrap();
        let pin = env.find("<d:Pin>").unwrap();
        let user = env.find("<d:UserId>").unwrap();
        assert!(app < doc && doc < hash && hash < pin && pin < user);
    }

    #[test]
    fn find_text_ignores_namespace_prefix() {
        let xml = r#"<r xmlns:a="urn:x"><a:ProcessId>abc-123</a:ProcessId></r>"#;
        assert_eq!(find_text(xml, "ProcessId").as_deref(), Some("abc-123"));
        assert_eq!(find_text(xml, "Missing"), None);
    }

    #[test]
    fn find_text_returns_first_match() {
        let xml = r#"<r><Code>200</Code><Status><Code>500</Code></Status></r>"#;
        assert_eq!(find_text(xml, "Code").as_deref(), Some("200"));
    }

    #[test]
    fn find_text_ignores_injected_nested_same_name() {
        // t41-e4 L8: a <Code> injected inside a free-text <Message> field must not shadow
        // the real top-level <Code> of the SCMD result. The injected element is deeper, so
        // the shallowest-depth match (the real one) wins even though it appears later.
        let xml = r#"<r><Message><Code>EVIL</Code></Message><Code>200</Code></r>"#;
        assert_eq!(find_text(xml, "Code").as_deref(), Some("200"));
        assert_ne!(find_text(xml, "Code").as_deref(), Some("EVIL"));
    }

    #[test]
    fn detects_soap_fault() {
        let xml = r#"<s:Envelope xmlns:s="urn:x"><s:Body><s:Fault>
            <faultcode>s:Client</faultcode>
            <faultstring>Invalid ApplicationId</faultstring>
        </s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(fault_message(xml).as_deref(), Some("Invalid ApplicationId"));
    }

    #[test]
    fn no_fault_on_normal_response() {
        let xml = r#"<r><Code>200</Code></r>"#;
        assert_eq!(fault_message(xml), None);
    }
}
