use crate::storage::catalog::{Catalog, DuckDbCatalog, TokenScope};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;
use x509_parser::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("X.509 certificate error: {0}")]
    X509(String),

    #[error("Password/Token hashing error: {0}")]
    Hash(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "message": msg
                })),
            )
                .into_response(),
            AuthError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "forbidden",
                    "message": msg
                })),
            )
                .into_response(),
            other => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "internal_error",
                    "message": other.to_string()
                })),
            )
                .into_response(),
        }
    }
}

/// Computes SHA-256 lowercase hexadecimal hash of a plaintext token string.
pub fn hash_token_sha256(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes Argon2id hash of a plaintext token string.
pub fn hash_token_argon2(token: &str) -> Result<String, AuthError> {
    let random_bytes = Uuid::new_v4().into_bytes();
    let salt = SaltString::encode_b64(&random_bytes)
        .map_err(|e| AuthError::Hash(format!("Salt generation failed: {e}")))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| AuthError::Hash(e.to_string()))?;
    Ok(hash.to_string())
}

/// Verifies a plaintext token string against an Argon2id password hash string.
pub fn verify_token_argon2(token: &str, token_hash: &str) -> Result<bool, AuthError> {
    let parsed_hash = PasswordHash::new(token_hash).map_err(|e| AuthError::Hash(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Extracts SAN (Subject Alternative Names) DNS and URI names from a DER-encoded X.509 certificate.
pub fn extract_cert_sans(cert_der: &[u8]) -> Result<Vec<String>, AuthError> {
    let (_, x509) = X509Certificate::from_der(cert_der)
        .map_err(|e| AuthError::X509(format!("Failed to parse DER certificate: {e}")))?;

    let mut sans = Vec::new();
    for ext in x509.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                    GeneralName::URI(uri) => sans.push(uri.to_string()),
                    GeneralName::RFC822Name(rfc) => sans.push(rfc.to_string()),
                    _ => {}
                }
            }
        }
    }

    Ok(sans)
}

/// Extracts the first non-empty SAN entry from a DER-encoded X.509 certificate.
pub fn extract_primary_cert_san(cert_der: &[u8]) -> Result<Option<String>, AuthError> {
    let sans = extract_cert_sans(cert_der)?;
    Ok(sans
        .into_iter()
        .map(|s| s.trim().to_string())
        .find(|s| !s.is_empty()))
}

/// Build rustls::ServerConfig requiring or verifying mTLS client certificates rooted in step-ca CA bundle.
pub fn build_tls_server_config(
    ca_cert_path: impl AsRef<Path>,
    server_cert_path: impl AsRef<Path>,
    server_key_path: impl AsRef<Path>,
) -> Result<rustls::ServerConfig, AuthError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca_file = File::open(ca_cert_path)?;
    let mut ca_reader = BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_reader_iter(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuthError::Tls(format!("Failed to parse CA certificate PEM: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| AuthError::Tls(format!("Failed to add CA cert to root store: {e}")))?;
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| AuthError::Tls(format!("Failed to build client verifier: {e}")))?;

    let srv_file = File::open(server_cert_path)?;
    let mut srv_reader = BufReader::new(srv_file);
    let srv_certs: Vec<CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_reader_iter(&mut srv_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuthError::Tls(format!("Failed to parse server cert PEM: {e}")))?;

    let key_file = File::open(server_key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> =
        rustls_pki_types::PrivateKeyDer::from_pem_reader(&mut key_reader)
            .map_err(|e| AuthError::Tls(format!("Failed to parse server private key: {e}")))?;

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(srv_certs, key)
        .map_err(|e| AuthError::Tls(format!("Failed to configure server cert: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIdentity {
    Anonymous,
    BearerToken(String),
    CertSan(String),
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub identity: ClientIdentity,
    pub scopes: HashSet<TokenScope>,
}

impl AuthContext {
    pub fn anonymous() -> Self {
        Self {
            identity: ClientIdentity::Anonymous,
            scopes: HashSet::new(),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        !matches!(self.identity, ClientIdentity::Anonymous)
    }

    pub fn has_scope(&self, scope: TokenScope) -> bool {
        self.scopes.contains(&scope)
    }

    pub fn require_scope(&self, scope: TokenScope) -> Result<(), AuthError> {
        if !self.is_authenticated() {
            return Err(AuthError::Unauthorized(
                "Authentication credentials required".to_string(),
            ));
        }
        if !self.has_scope(scope) {
            return Err(AuthError::Forbidden(format!(
                "Operation requires '{scope}' scope"
            )));
        }
        Ok(())
    }
}

/// Verified peer certificate SAN attached to request extensions by the mTLS listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClientSan(pub String);

/// Request extension injected by router middleware when `AppConfig::trust_proxy_san_header` is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustProxySanHeader(pub bool);

/// Returns whether the `x-client-cert-san` proxy header fallback is enabled via environment.
#[must_use]
pub fn trust_proxy_san_header_from_env() -> bool {
    crate::config::parse_env_bool_first(&[
        "MU_REGISTRY_TRUST_PROXY_SAN_HEADER",
        "MUREGIST_TRUST_PROXY_SAN_HEADER",
    ])
}

fn cert_san_auth_context(san: &str) -> AuthContext {
    let mut scopes = HashSet::new();
    scopes.insert(TokenScope::Publish);
    scopes.insert(TokenScope::Yank);
    scopes.insert(TokenScope::Read);
    scopes.insert(TokenScope::CanaryManage);

    AuthContext {
        identity: ClientIdentity::CertSan(san.to_string()),
        scopes,
    }
}

fn authenticate_cert_san_from_parts(
    parts: &Parts,
    trust_proxy_san_header: bool,
) -> Option<AuthContext> {
    if let Some(VerifiedClientSan(san)) = parts.extensions.get::<VerifiedClientSan>() {
        let san = san.trim();
        if !san.is_empty() {
            return Some(cert_san_auth_context(san));
        }
    }

    if trust_proxy_san_header {
        if let Some(san_val) = parts.headers.get("x-client-cert-san") {
            if let Ok(san_str) = san_val.to_str() {
                let san = san_str.trim();
                if !san.is_empty() {
                    return Some(cert_san_auth_context(san));
                }
            }
        }
    }

    None
}

/// Authenticate incoming request using:
/// 1. Verified mTLS peer certificate SAN extension (`VerifiedClientSan`) -> grants full administrative scopes.
/// 2. `x-client-cert-san` header fallback ONLY when explicitly enabled (`MU_REGISTRY_TRUST_PROXY_SAN_HEADER=true`).
/// 3. `Authorization: Bearer <token>` verified against SHA-256 or Argon2id hashes in DuckDbCatalog.
pub fn authenticate_request(
    parts: &Parts,
    catalog: &DuckDbCatalog,
) -> Result<AuthContext, AuthError> {
    let trust_proxy_header = parts
        .extensions
        .get::<TrustProxySanHeader>()
        .is_some_and(|flag| flag.0)
        || trust_proxy_san_header_from_env();
    authenticate_request_with_proxy_trust(parts, catalog, trust_proxy_header)
}

/// Authenticate incoming request with an explicit setting for whether the `x-client-cert-san`
/// reverse-proxy header fallback is trusted.
pub fn authenticate_request_with_proxy_trust(
    parts: &Parts,
    catalog: &DuckDbCatalog,
    trust_proxy_san_header: bool,
) -> Result<AuthContext, AuthError> {
    // 1 & 2. Check verified mTLS peer SAN extension first, then optional trusted-proxy header
    if let Some(ctx) = authenticate_cert_san_from_parts(parts, trust_proxy_san_header) {
        return Ok(ctx);
    }

    // 2. Check for Bearer token
    if let Some(auth_val) = parts.headers.get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_val.to_str() {
            let trimmed = auth_str.trim();
            if let Some(raw_token) = trimmed
                .strip_prefix("Bearer ")
                .or_else(|| trimmed.strip_prefix("bearer "))
            {
                let token = raw_token.trim();
                let sha_hash = hash_token_sha256(token);

                // Direct SHA-256 lookup
                if let Ok(Some(tok_rec)) = catalog.find_token_by_hash(&sha_hash) {
                    let scopes = tok_rec
                        .scopes()
                        .map_err(|e| AuthError::Hash(e.to_string()))?;
                    return Ok(AuthContext {
                        identity: ClientIdentity::BearerToken(tok_rec.token_id),
                        scopes,
                    });
                }

                // Check Argon2id hashes if any tokens stored as Argon2id
                if let Ok(all_tokens) = catalog.get_api_tokens() {
                    for tok_rec in all_tokens {
                        if tok_rec.token_hash.starts_with("$argon2") {
                            if let Ok(parsed_hash) = PasswordHash::new(&tok_rec.token_hash) {
                                if Argon2::default()
                                    .verify_password(token.as_bytes(), &parsed_hash)
                                    .is_ok()
                                {
                                    let scopes = tok_rec
                                        .scopes()
                                        .map_err(|e| AuthError::Hash(e.to_string()))?;
                                    return Ok(AuthContext {
                                        identity: ClientIdentity::BearerToken(tok_rec.token_id),
                                        scopes,
                                    });
                                }
                            }
                        }
                    }
                }

                return Err(AuthError::Unauthorized(
                    "Invalid or expired API token".to_string(),
                ));
            }
        }
    }

    Ok(AuthContext::anonymous())
}

// Axum FromRequestParts implementation for AuthContext
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
    Catalog: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let catalog = Catalog::from_ref(state);
        match authenticate_request(parts, &catalog) {
            Ok(ctx) => Ok(ctx),
            Err(e) => Err(e.into_response()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    #[test]
    fn test_pure_rust_sha256_and_auth_context_scopes() {
        let token = "secret-token-123";
        let hash1 = hash_token_sha256(token);
        let hash2 = hash_token_sha256(token);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
        assert_ne!(hash1, hash_token_sha256("different-token"));

        let anon = AuthContext::anonymous();
        assert!(!anon.is_authenticated());
        assert!(!anon.has_scope(TokenScope::Read));
        assert!(matches!(
            anon.require_scope(TokenScope::Read),
            Err(AuthError::Unauthorized(_))
        ));

        let mut scopes = HashSet::new();
        scopes.insert(TokenScope::Read);
        scopes.insert(TokenScope::CanaryManage);
        let ctx = AuthContext {
            identity: ClientIdentity::BearerToken("tok-1".to_string()),
            scopes,
        };
        assert!(ctx.is_authenticated());
        assert!(ctx.has_scope(TokenScope::Read));
        assert!(ctx.has_scope(TokenScope::CanaryManage));
        assert!(!ctx.has_scope(TokenScope::Publish));
        assert!(ctx.require_scope(TokenScope::Read).is_ok());
        assert!(matches!(
            ctx.require_scope(TokenScope::Publish),
            Err(AuthError::Forbidden(_))
        ));
    }

    #[test]
    fn test_pure_rust_argon2_hash_and_verify() {
        // Under Miri, verify pre-computed low-cost Argon2id PHC string and round-trip with minimal params
        let raw_token = "argon-token-xyz";
        #[cfg(miri)]
        let hash_str = {
            let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
            let params = argon2::Params::new(8, 1, 1, Some(32)).unwrap();
            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            argon2
                .hash_password(raw_token.as_bytes(), &salt)
                .unwrap()
                .to_string()
        };
        #[cfg(not(miri))]
        let hash_str = hash_token_argon2(raw_token).unwrap();

        assert!(verify_token_argon2(raw_token, &hash_str).unwrap());
        assert!(!verify_token_argon2("wrong-token", &hash_str).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_token_hashing_and_auth() {
        let catalog = DuckDbCatalog::in_memory().unwrap();
        let raw_token = "secret-token-123";
        let sha_hash = hash_token_sha256(raw_token);

        catalog
            .insert_api_token(
                "tok-1",
                &sha_hash,
                &[TokenScope::Read, TokenScope::CanaryManage],
            )
            .unwrap();

        let req = axum::http::Request::builder()
            .header(AUTHORIZATION, format!("Bearer {raw_token}"))
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();

        let auth = authenticate_request(&parts, &catalog).unwrap();
        assert!(auth.is_authenticated());
        assert!(auth.has_scope(TokenScope::Read));
        assert!(auth.has_scope(TokenScope::CanaryManage));
        assert!(!auth.has_scope(TokenScope::Publish));
        assert!(auth.require_scope(TokenScope::Read).is_ok());
        assert!(auth.require_scope(TokenScope::Publish).is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_argon2_token_auth() {
        let catalog = DuckDbCatalog::in_memory().unwrap();
        let raw_token = "argon-token-xyz";
        let argon_hash = hash_token_argon2(raw_token).unwrap();

        catalog
            .insert_api_token("tok-2", &argon_hash, &[TokenScope::Publish])
            .unwrap();

        let req = axum::http::Request::builder()
            .header(AUTHORIZATION, format!("Bearer {raw_token}"))
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();

        let auth = authenticate_request(&parts, &catalog).unwrap();
        assert!(auth.is_authenticated());
        assert!(auth.has_scope(TokenScope::Publish));
        assert!(!auth.has_scope(TokenScope::Read));
    }

    #[test]
    fn test_pure_rust_verified_client_san_and_spoofed_header_guard() {
        // Spoofed x-client-cert-san header must be ignored when proxy trust is disabled
        let spoof_req = axum::http::Request::builder()
            .header("x-client-cert-san", "spoofed.node-a.example")
            .body(())
            .unwrap();
        let (spoof_parts, _) = spoof_req.into_parts();
        assert!(authenticate_cert_san_from_parts(&spoof_parts, false).is_none());

        // Proxy trust enabled falls back to x-client-cert-san header
        let trusted_proxy_auth =
            authenticate_cert_san_from_parts(&spoof_parts, true).expect("proxy fallback auth");
        assert_eq!(
            trusted_proxy_auth.identity,
            ClientIdentity::CertSan("spoofed.node-a.example".to_string())
        );
        assert!(trusted_proxy_auth.has_scope(TokenScope::Read));
        assert!(trusted_proxy_auth.has_scope(TokenScope::Publish));

        // VerifiedClientSan extension always takes precedence over any header
        let ext_req = axum::http::Request::builder()
            .header("x-client-cert-san", "spoofed.node-a.example")
            .extension(VerifiedClientSan("verified.node-a.example".to_string()))
            .body(())
            .unwrap();
        let (ext_parts, _) = ext_req.into_parts();
        let ext_auth = authenticate_cert_san_from_parts(&ext_parts, true).expect("ext auth");
        assert_eq!(
            ext_auth.identity,
            ClientIdentity::CertSan("verified.node-a.example".to_string())
        );
        assert!(ext_auth.has_scope(TokenScope::Publish));
        assert!(ext_auth.has_scope(TokenScope::Yank));
        assert!(ext_auth.has_scope(TokenScope::Read));
        assert!(ext_auth.has_scope(TokenScope::CanaryManage));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_cert_san_extraction_and_auth() {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test-client");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![
            SanType::DnsName("registry.ci.ci.internal".try_into().unwrap()),
            SanType::URI(
                "spiffe://cluster.internal/ns/ci/sa/deployer"
                    .try_into()
                    .unwrap(),
            ),
        ];
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der();

        let sans = extract_cert_sans(der).unwrap();
        assert_eq!(sans.len(), 2);
        assert!(sans.contains(&"registry.ci.ci.internal".to_string()));
        assert_eq!(
            extract_primary_cert_san(der).unwrap().as_deref(),
            Some("registry.ci.ci.internal")
        );

        let catalog = DuckDbCatalog::in_memory().unwrap();

        // Spoofed header without VerifiedClientSan and with proxy trust disabled -> Anonymous
        let spoof_req = axum::http::Request::builder()
            .header("x-client-cert-san", "registry.ci.ci.internal")
            .body(())
            .unwrap();
        let (spoof_parts, _) = spoof_req.into_parts();
        let spoof_auth = authenticate_request(&spoof_parts, &catalog).unwrap();
        assert!(!spoof_auth.is_authenticated());

        // VerifiedClientSan request extension grants full administrative scopes
        let verified_req = axum::http::Request::builder()
            .extension(VerifiedClientSan("registry.ci.ci.internal".to_string()))
            .body(())
            .unwrap();
        let (verified_parts, _) = verified_req.into_parts();
        let verified_auth = authenticate_request(&verified_parts, &catalog).unwrap();
        assert!(verified_auth.is_authenticated());
        assert_eq!(
            verified_auth.identity,
            ClientIdentity::CertSan("registry.ci.ci.internal".to_string())
        );
        assert!(verified_auth.has_scope(TokenScope::Publish));
        assert!(verified_auth.has_scope(TokenScope::Yank));
        assert!(verified_auth.has_scope(TokenScope::Read));
        assert!(verified_auth.has_scope(TokenScope::CanaryManage));

        // Explicit proxy header trust fallback works when enabled
        let proxy_auth =
            authenticate_request_with_proxy_trust(&spoof_parts, &catalog, true).unwrap();
        assert!(proxy_auth.is_authenticated());
        assert_eq!(
            proxy_auth.identity,
            ClientIdentity::CertSan("registry.ci.ci.internal".to_string())
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_anonymous_and_invalid_token() {
        let catalog = DuckDbCatalog::in_memory().unwrap();

        let req_empty = axum::http::Request::builder().body(()).unwrap();
        let (parts_empty, _) = req_empty.into_parts();
        let auth = authenticate_request(&parts_empty, &catalog).unwrap();
        assert!(!auth.is_authenticated());
        assert!(matches!(
            auth.require_scope(TokenScope::Read),
            Err(AuthError::Unauthorized(_))
        ));

        let req_invalid = axum::http::Request::builder()
            .header(AUTHORIZATION, "Bearer wrong-token")
            .body(())
            .unwrap();
        let (parts_invalid, _) = req_invalid.into_parts();
        let res = authenticate_request(&parts_invalid, &catalog);
        assert!(matches!(res, Err(AuthError::Unauthorized(_))));
    }
}
