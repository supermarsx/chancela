// Shared integration-test helper: each `tests/*.rs` binary compiles this module independently, so
// any TSA mock a given binary doesn't exercise reads as dead there. Allow it module-wide rather
// than chasing per-binary drift as new test binaries land.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;
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
    #[cfg(debug_assertions)]
    _local_url_allowance: chancela_api::LocalTrustUrlTestAllowance,
}

impl MockTsaServer {
    pub fn granted() -> Self {
        Self::spawn(MockTsaMode::Granted)
    }

    pub fn outage() -> Self {
        Self::spawn(MockTsaMode::Outage)
    }

    pub fn malformed_token() -> Self {
        Self::spawn(MockTsaMode::MalformedToken)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn spawn(mode: MockTsaMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock TSA");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        #[cfg(debug_assertions)]
        let local_url_allowance = chancela_api::allow_local_trust_url_for_tests(&url)
            .expect("register mock TSA loopback URL");
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle_connection(stream, mode);
            }
        });
        Self {
            url,
            #[cfg(debug_assertions)]
            _local_url_allowance: local_url_allowance,
        }
    }
}

#[derive(Clone, Copy)]
enum MockTsaMode {
    Granted,
    Outage,
    MalformedToken,
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
        MockTsaMode::MalformedToken => {
            write_response(
                &mut stream,
                "200 OK",
                "application/timestamp-reply",
                b"not a DER timestamp token",
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
    match openssl_response_for_request(der_req) {
        Ok(response) => return response,
        Err(err) => eprintln!("mock TSA OpenSSL response generation failed: {err}"),
    }

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

fn openssl_response_for_request(der_req: &[u8]) -> std::io::Result<Vec<u8>> {
    let dir = OpensslTsaDir::new()?;
    std::fs::write(dir.join("request.tsq"), der_req)?;
    std::fs::write(dir.join("serial.txt"), b"01\n")?;
    std::fs::write(dir.join("index.txt"), b"")?;
    std::fs::write(dir.join("tsa.cnf"), tsa_config())?;

    run_openssl(
        &dir.path,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "root.key",
            "-out",
            "root.pem",
            "-sha256",
            "-days",
            "30",
            "-subj",
            "/CN=Chancela API Test TSA Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    )?;
    run_openssl(
        &dir.path,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
            "-subj",
            "/CN=Chancela API Test TSA",
        ],
    )?;
    std::fs::write(
        dir.join("tsa.ext"),
        "basicConstraints=critical,CA:FALSE\n\
         keyUsage=critical,digitalSignature\n\
         extendedKeyUsage=critical,timeStamping\n",
    )?;
    run_openssl(
        &dir.path,
        &[
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-set_serial",
            "2",
            "-sha256",
            "-days",
            "30",
            "-extfile",
            "tsa.ext",
            "-out",
            "tsa.pem",
        ],
    )?;
    run_openssl(
        &dir.path,
        &[
            "ts",
            "-reply",
            "-queryfile",
            "request.tsq",
            "-inkey",
            "tsa.key",
            "-signer",
            "tsa.pem",
            "-out",
            "response.tsr",
            "-config",
            "tsa.cnf",
            "-section",
            "tsa_config1",
        ],
    )?;
    std::fs::read(dir.join("response.tsr"))
}

fn run_openssl(dir: &Path, args: &[&str]) -> std::io::Result<()> {
    let output = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "openssl {:?} failed: {}{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn tsa_config() -> &'static str {
    r#"
[tsa_config1]
serial = serial.txt
crypto_device = builtin
signer_cert = tsa.pem
certs = root.pem
signer_key = tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"#
}

struct OpensslTsaDir {
    path: PathBuf,
}

impl OpensslTsaDir {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "chancela-api-mock-tsa-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for OpensslTsaDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
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
        if response[start] == 0x30
            && let Some(end) = der_item_end(response, start)
            && end > anchor
        {
            return start..end;
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
