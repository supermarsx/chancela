use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::Range;
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};

const FIXTURE_RESPONSE_DER: &[u8] =
    include_bytes!("../../../chancela-tsa/fixtures/openssl_sha256_abc.tsr");
const FIXTURE_DIGEST: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];
const FIXTURE_NONCE: [u8; 8] = [0x31, 0x4c, 0xfc, 0xe4, 0xe0, 0x65, 0x18, 0x27];
const SHA256_IMPRINT_MARKER: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];
const TST_INFO_ANCHOR: &[u8] = &[0x02, 0x01, 0x01, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x01];

pub struct MockTsaServer {
    url: String,
}

impl MockTsaServer {
    pub fn granted() -> Self {
        Self::spawn(MockTsaMode::Granted)
    }

    #[allow(dead_code)]
    pub fn outage() -> Self {
        Self::spawn(MockTsaMode::Outage)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn spawn(mode: MockTsaMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock TSA");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle_connection(stream, mode);
            }
        });
        Self { url }
    }
}

#[derive(Clone, Copy)]
enum MockTsaMode {
    Granted,
    #[allow(dead_code)]
    Outage,
}

fn handle_connection(mut stream: TcpStream, mode: MockTsaMode) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let request = read_http_request(&mut stream).expect("read timestamp request");
    match mode {
        MockTsaMode::Granted => {
            let body = response_for_request(&request);
            write_response(&mut stream, "200 OK", "application/timestamp-reply", &body);
        }
        MockTsaMode::Outage => {
            write_response(
                &mut stream,
                "503 Service Unavailable",
                "text/plain",
                b"tsa outage",
            );
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(header_end) = find_bytes(&buf, b"\r\n\r\n") {
            let body_start = header_end + 4;
            let content_length = content_length(&buf[..header_end]).unwrap_or(0);
            while buf.len() < body_start + content_length {
                let n = stream.read(&mut tmp)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            return Ok(buf[body_start..body_start + content_length].to_vec());
        }
    }
    Ok(Vec::new())
}

fn content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let headers = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).expect("write headers");
    stream.write_all(body).expect("write body");
}

fn response_for_request(der_req: &[u8]) -> Vec<u8> {
    let (digest, nonce) = digest_and_nonce(der_req);
    let mut response = FIXTURE_RESPONSE_DER.to_vec();
    let tst_range = tst_info_range(&response);
    let old_tst = response[tst_range.clone()].to_vec();
    let old_message_digest: [u8; 32] = Sha256::digest(&old_tst).into();

    replace_once(&mut response, &FIXTURE_DIGEST, &digest);
    replace_once(&mut response, &FIXTURE_NONCE, &nonce);

    let new_tst = &response[tst_range];
    let new_message_digest: [u8; 32] = Sha256::digest(new_tst).into();
    replace_once(&mut response, &old_message_digest, &new_message_digest);
    response
}

fn digest_and_nonce(der_req: &[u8]) -> ([u8; 32], [u8; 8]) {
    let digest_start = find_bytes(der_req, SHA256_IMPRINT_MARKER)
        .map(|pos| pos + SHA256_IMPRINT_MARKER.len())
        .expect("timestamp request carries a SHA-256 imprint");
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&der_req[digest_start..digest_start + 32]);

    let nonce_start = find_bytes(&der_req[digest_start + 32..], &[0x02, 0x08])
        .map(|rel| digest_start + 32 + rel + 2)
        .expect("timestamp request carries an 8-byte nonce");
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&der_req[nonce_start..nonce_start + 8]);
    (digest, nonce)
}

fn tst_info_range(response: &[u8]) -> Range<usize> {
    let anchor = find_bytes(response, TST_INFO_ANCHOR).expect("fixture TSTInfo anchor");
    for start in (0..anchor).rev() {
        if response[start] == 0x30 {
            if let Some(end) = der_item_end(response, start) {
                if end > anchor {
                    return start..end;
                }
            }
        }
    }
    panic!("fixture TSTInfo range not found");
}

fn der_item_end(bytes: &[u8], start: usize) -> Option<usize> {
    let len0 = *bytes.get(start + 1)?;
    if len0 & 0x80 == 0 {
        return Some(start + 2 + len0 as usize).filter(|end| *end <= bytes.len());
    }
    let len_len = (len0 & 0x7f) as usize;
    if len_len == 0 || len_len > 4 {
        return None;
    }
    let mut len = 0usize;
    for b in bytes.get(start + 2..start + 2 + len_len)? {
        len = (len << 8) | (*b as usize);
    }
    Some(start + 2 + len_len + len).filter(|end| *end <= bytes.len())
}

fn replace_once(haystack: &mut [u8], old: &[u8], new: &[u8]) {
    assert_eq!(old.len(), new.len(), "replacement length must stay fixed");
    let pos = find_bytes(haystack, old).expect("fixture bytes to replace");
    haystack[pos..pos + old.len()].copy_from_slice(new);
    assert!(
        find_bytes(&haystack[pos + old.len()..], old).is_none(),
        "fixture bytes should be unique"
    );
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
