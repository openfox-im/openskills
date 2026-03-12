//! openskills-zktls: TLSNotary prover & verifier as Node.js native module.
//!
//! Exposes two async functions to JavaScript:
//!   - `prove(config)` → ProveResult   (generates a zk-TLS attestation)
//!   - `verify(config)` → VerifyResult (verifies a zk-TLS attestation offline)

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

// ---------------------------------------------------------------------------
// JS-facing types
// ---------------------------------------------------------------------------

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveConfig {
    /// Target HTTPS server hostname (e.g. "api.example.com")
    pub server_host: String,
    /// Target HTTPS server port (default 443)
    pub server_port: Option<u16>,
    /// Notary/verifier TCP address (e.g. "127.0.0.1:7047")
    pub notary_host: String,
    pub notary_port: Option<u16>,
    /// HTTP request to send
    pub request: HttpRequest,
    /// Maximum bytes to send (default 4096)
    pub max_sent_data: Option<u32>,
    /// Maximum bytes to receive (default 16384)
    pub max_recv_data: Option<u32>,
    /// Ranges of the response to reveal (byte offsets into recv transcript).
    /// If omitted, the entire transcript is revealed.
    pub reveal_ranges: Option<Vec<RevealRange>>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<HttpHeader>,
    pub body: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealRange {
    pub start: u32,
    pub end: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveResult {
    /// Serialized ProverOutput (commitments + secrets) as JSON
    pub attestation: String,
    /// SHA-256 of the attestation
    pub attestation_sha256: String,
    /// Server hostname that was proven
    pub server_name: String,
    /// Sent transcript length in bytes
    pub sent_len: u32,
    /// Received transcript length in bytes
    pub recv_len: u32,
    pub backend: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyConfig {
    /// Serialized attestation data. Accepts:
    ///   - JSON-serialized Presentation (full crypto verification)
    ///   - Base64-encoded bincode Presentation (full crypto verification)
    ///   - JSON-serialized ProverOutput (structural check only)
    pub attestation: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the attestation is cryptographically valid
    pub valid: bool,
    /// Number of transcript commitments
    pub commitment_count: u32,
    /// SHA-256 of the raw attestation input
    pub attestation_sha256: String,
    /// Verification level: "cryptographic" (Presentation) or "structural" (ProverOutput)
    pub verification_level: String,
    /// Authenticated server hostname (only from Presentation verification)
    pub server_name: Option<String>,
    /// Sent transcript length in bytes (only from Presentation verification)
    pub sent_len: Option<u32>,
    /// Received transcript length in bytes (only from Presentation verification)
    pub recv_len: Option<u32>,
    /// Revealed sent transcript as UTF-8 (only from Presentation verification)
    pub revealed_sent: Option<String>,
    /// Revealed received transcript as UTF-8 (only from Presentation verification)
    pub revealed_recv: Option<String>,
    /// TLS connection time as UNIX timestamp (only from Presentation verification)
    pub connection_time: Option<u32>,
    pub backend: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(data)))
}

// ---------------------------------------------------------------------------
// Prover — generates a zk-TLS attestation via TLSNotary MPC-TLS
// ---------------------------------------------------------------------------

#[napi]
pub async fn prove(config: ProveConfig) -> Result<ProveResult> {
    let server_port = config.server_port.unwrap_or(443);
    let notary_port = config.notary_port.unwrap_or(7047);
    let max_sent = config.max_sent_data.unwrap_or(4096) as usize;
    let max_recv = config.max_recv_data.unwrap_or(16384) as usize;

    // 1. Connect to notary/verifier
    let notary_addr: SocketAddr = format!("{}:{}", config.notary_host, notary_port)
        .parse()
        .map_err(|e| Error::from_reason(format!("invalid notary address: {e}")))?;
    let notary_stream = TcpStream::connect(notary_addr)
        .await
        .map_err(|e| Error::from_reason(format!("failed to connect to notary: {e}")))?;

    // 2. Connect to target HTTPS server
    let server_addr = format!("{}:{}", config.server_host, server_port);
    let server_stream = TcpStream::connect(&server_addr)
        .await
        .map_err(|e| Error::from_reason(format!("failed to connect to server: {e}")))?;

    // 3. Create TLSNotary session (muxed channel to notary)
    let session = tlsn::Session::new(notary_stream.compat());
    let (driver, mut handle) = session.split();

    tokio::spawn(async move {
        if let Err(e) = driver.await {
            eprintln!("tlsn session driver error: {e}");
        }
    });

    // 4. Create prover and run commitment phase (MPC key setup)
    let prover_config = tlsn::config::prover::ProverConfig::builder()
        .build()
        .map_err(|e| Error::from_reason(format!("prover config: {e}")))?;

    let prover = handle
        .new_prover(prover_config)
        .map_err(|e| Error::from_reason(format!("new_prover: {e}")))?;

    let tls_commit_config = tlsn::config::tls_commit::TlsCommitConfig::builder()
        .protocol(
            tlsn::config::tls_commit::mpc::MpcTlsConfig::builder()
                .max_sent_data(max_sent)
                .max_recv_data(max_recv)
                .build()
                .map_err(|e| Error::from_reason(format!("mpc config: {e}")))?,
        )
        .build()
        .map_err(|e| Error::from_reason(format!("tls commit config: {e}")))?;

    let prover = prover
        .commit(tls_commit_config)
        .await
        .map_err(|e| Error::from_reason(format!("commitment: {e}")))?;

    // 5. Connect to target via MPC-TLS
    let server_name = tlsn::connection::ServerName::Dns(
        config.server_host.as_str().try_into().map_err(|e| {
            Error::from_reason(format!("invalid server name: {e}"))
        })?,
    );

    let tls_config = tlsn::config::tls::TlsClientConfig::builder()
        .server_name(server_name)
        .root_store(tlsn::webpki::RootCertStore::mozilla())
        .build()
        .map_err(|e| Error::from_reason(format!("tls config: {e}")))?;

    let (tls_conn, prover_fut) = prover
        .connect(tls_config, server_stream.compat())
        .await
        .map_err(|e| Error::from_reason(format!("tls connect: {e}")))?;

    let prover_task = tokio::spawn(async move { prover_fut.await });

    // 6. HTTP exchange over MPC-TLS connection
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls_conn.compat()))
            .await
            .map_err(|e| Error::from_reason(format!("http handshake: {e}")))?;

    tokio::spawn(connection);

    let mut req_builder = hyper::Request::builder()
        .method(config.request.method.as_str())
        .uri(config.request.path.as_str())
        .header("Host", &config.server_host)
        .header("Connection", "close");

    for h in &config.request.headers {
        req_builder = req_builder.header(h.name.as_str(), h.value.as_str());
    }

    let body = config
        .request
        .body
        .map(|b| http_body_util::Full::new(hyper::body::Bytes::from(b)))
        .unwrap_or_else(|| http_body_util::Full::new(hyper::body::Bytes::new()));

    let req = req_builder
        .body(body)
        .map_err(|e| Error::from_reason(format!("http request build: {e}")))?;

    let response = sender
        .send_request(req)
        .await
        .map_err(|e| Error::from_reason(format!("http request: {e}")))?;

    // Consume response body
    let _ = http_body_util::BodyExt::collect(response.into_body())
        .await
        .map_err(|e| Error::from_reason(format!("http body: {e}")))?;

    // 7. Connection closed → prover transitions to Committed state
    let mut prover = prover_task
        .await
        .map_err(|e| Error::from_reason(format!("prover task: {e}")))?
        .map_err(|e| Error::from_reason(format!("prover: {e}")))?;

    let sent_len = prover.transcript().sent().len() as u32;
    let recv_len = prover.transcript().received().len() as u32;

    // 8. Selective disclosure
    let transcript = prover.transcript();
    let mut prove_builder =
        tlsn::config::prove::ProveConfig::builder(transcript);
    prove_builder.server_identity();

    if let Some(ranges) = &config.reveal_ranges {
        prove_builder.reveal_sent_all()
            .map_err(|e| Error::from_reason(format!("reveal sent: {e}")))?;
        for r in ranges {
            prove_builder.reveal_recv(&(r.start as usize..r.end as usize))
                .map_err(|e| Error::from_reason(format!("reveal recv: {e}")))?;
        }
    } else {
        prove_builder.reveal_sent_all()
            .map_err(|e| Error::from_reason(format!("reveal sent: {e}")))?;
        prove_builder.reveal_recv_all()
            .map_err(|e| Error::from_reason(format!("reveal recv: {e}")))?;
    }

    let prove_config = prove_builder
        .build()
        .map_err(|e| Error::from_reason(format!("prove config: {e}")))?;

    let output: tlsn_core::ProverOutput = prover
        .prove(&prove_config)
        .await
        .map_err(|e| Error::from_reason(format!("prove: {e}")))?;

    // 9. Serialize attestation (ProverOutput = commitments + secrets)
    let attestation_json = serde_json::to_string(&output)
        .map_err(|e| Error::from_reason(format!("serialize: {e}")))?;
    let attestation_sha256 = sha256_hex(attestation_json.as_bytes());

    Ok(ProveResult {
        attestation: attestation_json,
        attestation_sha256,
        server_name: config.server_host,
        sent_len,
        recv_len,
        backend: "skill:zktls.prove".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Verifier — offline attestation validation
// ---------------------------------------------------------------------------

/// Try to deserialize the input as a TLSNotary Presentation and perform full
/// cryptographic verification. Falls back to ProverOutput structural check.
#[napi]
pub async fn verify(config: VerifyConfig) -> Result<VerifyResult> {
    let attestation_sha256 = sha256_hex(config.attestation.as_bytes());
    let backend = "skill:zktls.verify-attestation".to_string();

    // Path 1: Try as Presentation (full cryptographic verification)
    if let Some(result) = try_verify_presentation(&config.attestation, &attestation_sha256, &backend) {
        return Ok(result);
    }

    // Path 2: Fall back to ProverOutput (structural check only)
    verify_prover_output(&config.attestation, &attestation_sha256, &backend)
}

/// Attempt to deserialize as Presentation and perform cryptographic verification.
/// Returns None if the input is not a Presentation.
fn try_verify_presentation(
    attestation: &str,
    attestation_sha256: &str,
    backend: &str,
) -> Option<VerifyResult> {
    use base64::Engine;
    use tlsn::attestation::{presentation::Presentation, CryptoProvider};

    // Try JSON deserialization first
    let presentation: Presentation = serde_json::from_str(attestation)
        .ok()
        // Then try base64-encoded bincode
        .or_else(|| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(attestation.trim())
                .ok()?;
            bincode::deserialize(&bytes).ok()
        })?;

    // Full cryptographic verification: validates notary signature, Merkle proofs,
    // commitment hashes, server identity proof, and transcript proof.
    let provider = CryptoProvider::default();
    match presentation.verify(&provider) {
        Ok(output) => {
            let server_name = output.server_name.map(|sn| sn.to_string());
            let sent_len = Some(output.connection_info.transcript_length.sent);
            let recv_len = Some(output.connection_info.transcript_length.received);
            let connection_time = Some(output.connection_info.time as u32);

            let (revealed_sent, revealed_recv) = if let Some(ref transcript) = output.transcript {
                (
                    Some(String::from_utf8_lossy(transcript.sent_unsafe()).to_string()),
                    Some(String::from_utf8_lossy(transcript.received_unsafe()).to_string()),
                )
            } else {
                (None, None)
            };

            // Count commitment fields in the verified attestation body
            let commitment_count = 0u32; // commitments are internal to the attestation

            Some(VerifyResult {
                valid: true,
                commitment_count,
                attestation_sha256: attestation_sha256.to_string(),
                verification_level: "cryptographic".to_string(),
                server_name,
                sent_len,
                recv_len,
                revealed_sent,
                revealed_recv,
                connection_time,
                backend: backend.to_string(),
            })
        }
        Err(e) => {
            // Presentation deserialized but failed cryptographic verification
            Some(VerifyResult {
                valid: false,
                commitment_count: 0,
                attestation_sha256: attestation_sha256.to_string(),
                verification_level: "cryptographic".to_string(),
                server_name: None,
                sent_len: None,
                recv_len: None,
                revealed_sent: None,
                revealed_recv: None,
                connection_time: None,
                backend: format!("{backend} (error: {e})"),
            })
        }
    }
}

/// Structural-only verification for ProverOutput format.
fn verify_prover_output(
    attestation: &str,
    attestation_sha256: &str,
    backend: &str,
) -> Result<VerifyResult> {
    let output: tlsn_core::ProverOutput = serde_json::from_str(attestation)
        .map_err(|e| Error::from_reason(format!("invalid attestation: {e}")))?;

    let commitment_count = output.transcript_commitments.len() as u32;

    Ok(VerifyResult {
        valid: commitment_count > 0,
        commitment_count,
        attestation_sha256: attestation_sha256.to_string(),
        verification_level: "structural".to_string(),
        server_name: None,
        sent_len: None,
        recv_len: None,
        revealed_sent: None,
        revealed_recv: None,
        connection_time: None,
        backend: backend.to_string(),
    })
}
