use std::path::Path;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::{CancellationToken, ConnectorError, ErrorClass};

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'\\');

pub(crate) fn encode_path(path: &str) -> Result<String, ConnectorError> {
    validate_relative_path(path)?;
    Ok(path
        .split('/')
        .map(|segment| utf8_percent_encode(segment, PATH_SEGMENT).to_string())
        .collect::<Vec<_>>()
        .join("/"))
}

pub(crate) fn validate_relative_path(path: &str) -> Result<(), ConnectorError> {
    let bytes = path.as_bytes();
    let windows_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    let valid = !path.is_empty()
        && path.len() <= 4_096
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !Path::new(path).is_absolute()
        && !windows_drive
        && !path.chars().any(char::is_control)
        && !path
            .split(['/', '\\'])
            .any(|part| part.is_empty() || part == "." || part == "..");
    if valid {
        Ok(())
    } else {
        Err(ConnectorError::configuration(
            "destination must be a non-empty relative path without traversal",
        ))
    }
}

pub(crate) fn join_remote(root: &str, destination: &str) -> Result<String, ConnectorError> {
    validate_relative_path(destination)?;
    let normalized_root = root.replace('\\', "/");
    let root = normalized_root.trim_end_matches('/');
    if root.is_empty() {
        Ok(destination.replace('\\', "/"))
    } else {
        Ok(format!("{root}/{}", destination.replace('\\', "/")))
    }
}

pub(crate) fn temporary_destination(destination: &str, idempotency_key: &str) -> String {
    let suffix: String = idempotency_key
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .take(24)
        .map(char::from)
        .collect();
    format!("{destination}.chancela-{suffix}.part")
}

pub(crate) async fn sha256_file(path: &Path) -> Result<(String, u64), ConnectorError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| ConnectorError::io("open source", &error))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| ConnectorError::io("read source", &error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok((format!("{:x}", digest.finalize()), bytes))
}

pub(crate) async fn verify_source(
    path: &Path,
    expected_sha256: &str,
    expected_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<(), ConnectorError> {
    cancellation.check()?;
    let (actual_sha256, actual_bytes) = sha256_file(path).await?;
    if actual_sha256 != expected_sha256 || actual_bytes != expected_bytes {
        return Err(ConnectorError::new(
            ErrorClass::Integrity,
            "source size or SHA-256 changed after job creation",
        ));
    }
    Ok(())
}

pub(crate) fn client(timeout_seconds: u64) -> Result<reqwest::Client, ConnectorError> {
    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 3 {
            return attempt.stop();
        }
        let Some(previous) = attempt.previous().last() else {
            return attempt.follow();
        };
        let same_origin = previous.scheme() == attempt.url().scheme()
            && previous.host_str() == attempt.url().host_str()
            && previous.port_or_known_default() == attempt.url().port_or_known_default();
        if same_origin {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_seconds))
        .user_agent(concat!("chancela-connectors/", env!("CARGO_PKG_VERSION")))
        .redirect(redirect_policy)
        .build()
        .map_err(|_| ConnectorError::configuration("unable to build HTTP client"))
}

pub(crate) async fn validate_upload_session_url(
    value: &str,
    provider: &str,
    allow_insecure_http: bool,
) -> Result<(), ConnectorError> {
    let url = reqwest::Url::parse(value).map_err(|_| {
        ConnectorError::new(
            ErrorClass::Permanent,
            format!("invalid {provider} upload session URL"),
        )
    })?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.scheme() != "https" && !(url.scheme() == "http" && allow_insecure_http))
    {
        return Err(ConnectorError::new(
            ErrorClass::Permanent,
            format!("unsafe {provider} upload session URL"),
        ));
    }
    crate::NetworkPolicy::effective()?
        .validate_url(value, &format!("{provider} upload session"))
        .await
}

pub(crate) fn bearer(
    builder: reqwest::RequestBuilder,
    token: &crate::SecretValue,
) -> reqwest::RequestBuilder {
    builder.bearer_auth(token.expose())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_is_relative_bounded_and_traversal_free() {
        for valid in [
            "exports/act-1.pdf",
            "backup.cbackup",
            "folder/name:revision",
        ] {
            validate_relative_path(valid).expect("valid remote destination");
        }
        for invalid in [
            "",
            "/etc/passwd",
            "\\\\server\\share\\file",
            "C:\\secrets\\file",
            "../escape",
            "nested//empty",
            "nested/./dot",
            "line\nbreak",
        ] {
            assert!(
                validate_relative_path(invalid).is_err(),
                "destination {invalid:?} must be rejected"
            );
        }
        assert!(validate_relative_path(&"x".repeat(4_097)).is_err());
    }
}
