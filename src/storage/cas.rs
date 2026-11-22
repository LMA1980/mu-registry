use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid SHA-256 digest: {0}")]
    InvalidDigest(String),

    #[error("Blob not found: {0}")]
    NotFound(String),

    #[error("Corrupt blob data for digest: {0}")]
    CorruptBlob(String),

    #[error("Storage conflict: {0}")]
    Conflict(String),
}

/// Sanitized aggregate Content-Addressed Storage (CAS) health and capacity telemetry.
/// Intentionally omits all host filesystem paths (`root_dir`, `blobs_dir`, `tmp_dir`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CasStorageHealthSummary {
    pub total_blobs: u64,
    pub total_bytes: u64,
    pub dedup_ratio_bps: u32,
    pub dedup_savings_bytes: u64,
    pub last_scrub_epoch_ms: i64,
    pub corrupted_blobs: u64,
    pub healthy: bool,
}

pub type CasStorageSummary = CasStorageHealthSummary;

/// Cached integrity metrics from the most recent full cryptographic CAS scrub
/// or read-path corruption detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CasScrubSnapshot {
    pub corrupted_blobs: u64,
    pub last_scrub_epoch_ms: i64,
}

/// A validated 64-character lowercase hexadecimal SHA-256 digest string.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn new(hex_str: &str) -> Result<Self, StorageError> {
        let trimmed = hex_str.trim();
        if trimmed.len() != 64 {
            return Err(StorageError::InvalidDigest(format!(
                "Expected 64 characters, got {}",
                trimmed.len()
            )));
        }
        if !trimmed.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(StorageError::InvalidDigest(
                "Digest contains non-hexadecimal or uppercase characters".to_string(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        Self(hex::encode(result))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Sha256Digest {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Sha256Digest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({})", self.0)
    }
}

impl FromStr for Sha256Digest {
    type Err = StorageError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Sha256Digest {
    type Error = StorageError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = StorageError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

/// Content-Addressed Store backed by filesystem hierarchy.
/// Layout:
/// `<root>/blobs/sha256/<hex[0..2]>/<hex>`
/// `<root>/tmp/upload-<uuid>.part`
#[derive(Clone, Debug)]
pub struct CasStore {
    root_dir: PathBuf,
    dedup_savings_bytes: Arc<AtomicU64>,
    scrub_snapshot: Arc<RwLock<Option<CasScrubSnapshot>>>,
}

pub type CasStorage = CasStore;

impl CasStore {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
            dedup_savings_bytes: Arc::new(AtomicU64::new(0)),
            scrub_snapshot: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns the most recently cached cryptographic scrub snapshot, if available.
    pub fn cached_scrub_snapshot(&self) -> Option<CasScrubSnapshot> {
        *self
            .scrub_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn record_scrub_snapshot(&self, corrupted_blobs: u64, last_scrub_epoch_ms: i64) {
        let mut guard = self
            .scrub_snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(CasScrubSnapshot {
            corrupted_blobs,
            last_scrub_epoch_ms,
        });
    }

    fn record_detected_corruption(&self) {
        let mut guard = self
            .scrub_snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let corrupted_blobs = guard.map_or(1, |snap| snap.corrupted_blobs.max(1));
        *guard = Some(CasScrubSnapshot {
            corrupted_blobs,
            last_scrub_epoch_ms: Utc::now().timestamp_millis(),
        });
    }

    pub fn default_path() -> PathBuf {
        crate::config::default_root_dir()
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root_dir.join("tmp")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root_dir.join("blobs").join("sha256")
    }

    pub async fn init(&self) -> Result<(), StorageError> {
        tokio::fs::create_dir_all(self.tmp_dir()).await?;
        tokio::fs::create_dir_all(self.blobs_dir()).await?;
        Ok(())
    }

    pub fn blob_path(&self, digest: &str) -> Result<PathBuf, StorageError> {
        let validated = Sha256Digest::new(digest)?;
        let prefix = &validated.as_str()[0..2];
        Ok(self.blobs_dir().join(prefix).join(validated.as_str()))
    }

    pub async fn has_blob(&self, digest: &str) -> bool {
        match self.blob_path(digest) {
            Ok(path) => tokio::fs::try_exists(path).await.unwrap_or(false),
            Err(_) => false,
        }
    }

    pub async fn get_blob(&self, digest: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.blob_path(digest)?;
        if !tokio::fs::try_exists(&path).await? {
            return Err(StorageError::NotFound(digest.to_string()));
        }

        let content = tokio::fs::read(&path).await?;
        let computed = Sha256Digest::from_bytes(&content);
        if computed.as_str() != digest {
            self.record_detected_corruption();
            return Err(StorageError::CorruptBlob(format!(
                "Digest mismatch for {}: expected {}, computed {}",
                path.display(),
                digest,
                computed.as_str()
            )));
        }

        Ok(content)
    }

    pub async fn put_blob(&self, bytes: &[u8]) -> Result<Sha256Digest, StorageError> {
        let digest = Sha256Digest::from_bytes(bytes);
        let target_path = self.blob_path(digest.as_str())?;

        // Deduplication check: if blob already exists and is intact, avoid rewrites
        if tokio::fs::try_exists(&target_path).await.unwrap_or(false) {
            if let Ok(metadata) = tokio::fs::metadata(&target_path).await {
                if metadata.len() == bytes.len() as u64 {
                    // Quick check matches, verify contents
                    if let Ok(existing) = tokio::fs::read(&target_path).await {
                        if Sha256Digest::from_bytes(&existing) == digest {
                            self.dedup_savings_bytes
                                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                            return Ok(digest);
                        }
                    }
                }
            }
        }

        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir).await?;

        let part_filename = format!("upload-{}.part", Uuid::new_v4());
        let part_path = tmp_dir.join(part_filename);

        // Scope file write and sync to ensure handle is flushed and closed before rename
        {
            let mut file = tokio::fs::File::create(&part_path).await?;
            file.write_all(bytes).await?;
            file.sync_all().await?;
        }

        if let Some(parent) = target_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Atomically rename temporary file to target path
        if let Err(e) = tokio::fs::rename(&part_path, &target_path).await {
            // Check if concurrent write succeeded
            if tokio::fs::try_exists(&target_path).await.unwrap_or(false) {
                let _ = tokio::fs::remove_file(&part_path).await;
                self.dedup_savings_bytes
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                return Ok(digest);
            }
            let _ = tokio::fs::remove_file(&part_path).await;
            return Err(StorageError::Io(e));
        }

        Ok(digest)
    }

    /// Computes aggregate CAS storage health metrics by scrubbing the two-level SHA-256 blob
    /// hierarchy (`<blobs_dir>/<hex[0..2]>/<hex>`). Returns zero host filesystem paths.
    pub async fn storage_health_summary(&self) -> Result<CasStorageHealthSummary, StorageError> {
        let blobs_root = self.blobs_dir();
        let mut total_blobs = 0u64;
        let mut total_bytes = 0u64;
        let mut corrupted_blobs = 0u64;

        if tokio::fs::try_exists(&blobs_root).await.unwrap_or(false) {
            let mut prefix_dir = tokio::fs::read_dir(&blobs_root).await?;
            while let Some(prefix_entry) = prefix_dir.next_entry().await? {
                let file_type = prefix_entry.file_type().await?;
                if !file_type.is_dir() {
                    continue;
                }
                let mut shard_dir = tokio::fs::read_dir(prefix_entry.path()).await?;
                while let Some(blob_entry) = shard_dir.next_entry().await? {
                    let blob_type = blob_entry.file_type().await?;
                    if !blob_type.is_file() {
                        continue;
                    }
                    total_blobs += 1;
                    let file_name = blob_entry.file_name().to_string_lossy().to_string();
                    match tokio::fs::read(blob_entry.path()).await {
                        Ok(bytes) => {
                            total_bytes += bytes.len() as u64;
                            let matches_digest = tokio::task::spawn_blocking(move || {
                                Sha256Digest::from_bytes(&bytes).as_str() == file_name
                            })
                            .await
                            .unwrap_or(false);
                            if !matches_digest {
                                corrupted_blobs += 1;
                            }
                        }
                        Err(_) => {
                            corrupted_blobs += 1;
                        }
                    }
                }
            }
        }

        let dedup_savings_bytes = self.dedup_savings_bytes.load(Ordering::Relaxed);
        let logical_bytes = total_bytes.saturating_add(dedup_savings_bytes);
        let dedup_ratio_bps = dedup_savings_bytes
            .saturating_mul(10_000)
            .checked_div(logical_bytes)
            .unwrap_or(0) as u32;
        let last_scrub_epoch_ms = Utc::now().timestamp_millis();
        self.record_scrub_snapshot(corrupted_blobs, last_scrub_epoch_ms);

        Ok(CasStorageHealthSummary {
            total_blobs,
            total_bytes,
            dedup_ratio_bps,
            dedup_savings_bytes,
            last_scrub_epoch_ms,
            corrupted_blobs,
            healthy: corrupted_blobs == 0,
        })
    }

    /// Computes aggregate CAS capacity and health telemetry using directory metadata only
    /// (`entry.metadata().await?.len()`, zero blob reads, and zero SHA-256 hashing),
    /// merged with the most recent cached background scrub snapshot. Returns zero host
    /// filesystem paths.
    pub async fn fast_health_summary(&self) -> Result<CasStorageHealthSummary, StorageError> {
        let blobs_root = self.blobs_dir();
        let mut total_blobs = 0u64;
        let mut total_bytes = 0u64;

        if tokio::fs::try_exists(&blobs_root).await.unwrap_or(false) {
            let mut prefix_dir = tokio::fs::read_dir(&blobs_root).await?;
            while let Some(prefix_entry) = prefix_dir.next_entry().await? {
                let file_type = prefix_entry.file_type().await?;
                if !file_type.is_dir() {
                    continue;
                }
                let mut shard_dir = tokio::fs::read_dir(prefix_entry.path()).await?;
                while let Some(blob_entry) = shard_dir.next_entry().await? {
                    let blob_type = blob_entry.file_type().await?;
                    if !blob_type.is_file() {
                        continue;
                    }
                    match blob_entry.metadata().await {
                        Ok(meta) => {
                            total_blobs += 1;
                            total_bytes = total_bytes.saturating_add(meta.len());
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(StorageError::Io(err)),
                    }
                }
            }
        }

        let dedup_savings_bytes = self.dedup_savings_bytes.load(Ordering::Relaxed);
        let logical_bytes = total_bytes.saturating_add(dedup_savings_bytes);
        let dedup_ratio_bps = dedup_savings_bytes
            .saturating_mul(10_000)
            .checked_div(logical_bytes)
            .unwrap_or(0) as u32;

        let (corrupted_blobs, last_scrub_epoch_ms) = match self.cached_scrub_snapshot() {
            Some(snapshot) => (snapshot.corrupted_blobs, snapshot.last_scrub_epoch_ms),
            None => (0, Utc::now().timestamp_millis()),
        };

        Ok(CasStorageHealthSummary {
            total_blobs,
            total_bytes,
            dedup_ratio_bps,
            dedup_savings_bytes,
            last_scrub_epoch_ms,
            corrupted_blobs,
            healthy: corrupted_blobs == 0,
        })
    }

    /// Alias for [`CasStore::storage_health_summary`].
    pub async fn storage_summary(&self) -> Result<CasStorageSummary, StorageError> {
        self.storage_health_summary().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn test_sha256_digest_validation_and_deterministic_hashing() {
        let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let digest = Sha256Digest::new(valid_hex).unwrap();
        assert_eq!(digest.as_str(), valid_hex);
        assert_eq!(digest.to_string(), valid_hex);

        let empty_digest = Sha256Digest::from_bytes(b"");
        assert_eq!(empty_digest, digest);

        let payload_digest1 = Sha256Digest::from_bytes(b"MuRegist deterministic CAS test");
        let payload_digest2 = Sha256Digest::from_bytes(b"MuRegist deterministic CAS test");
        assert_eq!(payload_digest1, payload_digest2);
        assert_eq!(payload_digest1.as_str().len(), 64);

        assert!(Sha256Digest::new("short").is_err());
        assert!(Sha256Digest::new(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        )
        .is_err());
        assert!(Sha256Digest::new(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_err());

        let store = CasStore::new("/var/lib/mu-registry");
        let blob_path = store.blob_path(valid_hex).unwrap();
        assert!(blob_path.ends_with(format!("blobs/sha256/e3/{valid_hex}")));
        assert!(store.blob_path("invalid").is_err());

        if !Path::new(crate::config::LEGACY_REGISTRY_ROOT_DIR).exists()
            || Path::new(crate::config::DEFAULT_REGISTRY_ROOT_DIR).exists()
        {
            assert_eq!(
                CasStore::default_path(),
                PathBuf::from(crate::config::DEFAULT_REGISTRY_ROOT_DIR)
            );
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_put_get_deduplication() {
        let temp_dir = tempdir().unwrap();
        let store = CasStore::new(temp_dir.path());
        store.init().await.unwrap();

        let data = b"Hello, MuRegist Content Addressed Storage!";
        let digest = store.put_blob(data).await.unwrap();

        assert!(store.has_blob(digest.as_str()).await);
        let retrieved = store.get_blob(digest.as_str()).await.unwrap();
        assert_eq!(retrieved, data);

        // Put again (idempotent deduplication)
        let digest2 = store.put_blob(data).await.unwrap();
        assert_eq!(digest, digest2);

        // Verify no leftover .part files in tmp
        let mut read_dir = tokio::fs::read_dir(store.tmp_dir()).await.unwrap();
        let mut part_count = 0;
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if entry.file_name().to_string_lossy().ends_with(".part") {
                part_count += 1;
            }
        }
        assert_eq!(part_count, 0);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_concurrent_writes_identical_payload() {
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(CasStore::new(temp_dir.path()));
        store.init().await.unwrap();

        let data = b"Concurrent identical payload blob test";
        let mut handles = Vec::new();

        for _ in 0..10 {
            let store_clone = Arc::clone(&store);
            handles.push(tokio::spawn(
                async move { store_clone.put_blob(data).await },
            ));
        }

        for handle in handles {
            let res = handle.await.unwrap();
            assert!(res.is_ok());
        }

        // Verify tmp directory has zero leftover .part files
        let mut read_dir = tokio::fs::read_dir(store.tmp_dir()).await.unwrap();
        let mut part_count = 0;
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if entry.file_name().to_string_lossy().ends_with(".part") {
                part_count += 1;
            }
        }
        assert_eq!(part_count, 0);

        // Verify blob is intact
        let digest = Sha256Digest::from_bytes(data);
        let blob = store.get_blob(digest.as_str()).await.unwrap();
        assert_eq!(blob, data);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_invalid_digest() {
        let temp_dir = tempdir().unwrap();
        let store = CasStore::new(temp_dir.path());
        store.init().await.unwrap();

        assert!(Sha256Digest::new("short").is_err());
        assert!(Sha256Digest::new(
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        )
        .is_err());
        assert!(!store.has_blob("invalid").await);
        assert!(store.get_blob("invalid").await.is_err());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_storage_health_summary_and_corruption_detection() {
        let temp_dir = tempdir().unwrap();
        let store = CasStore::new(temp_dir.path());
        store.init().await.unwrap();

        let empty_summary = store.storage_health_summary().await.unwrap();
        assert_eq!(empty_summary.total_blobs, 0);
        assert_eq!(empty_summary.total_bytes, 0);
        assert_eq!(empty_summary.corrupted_blobs, 0);
        assert!(empty_summary.healthy);

        let blob_a = b"alpha-blob-payload-bytes";
        let blob_b = b"beta-blob-payload-bytes-longer";
        let digest_a = store.put_blob(blob_a).await.unwrap();
        let _digest_b = store.put_blob(blob_b).await.unwrap();
        // Deduplicated write of blob_a
        let _digest_a_dup = store.put_blob(blob_a).await.unwrap();

        let summary = store.storage_summary().await.unwrap();
        assert_eq!(summary.total_blobs, 2);
        assert_eq!(summary.total_bytes, (blob_a.len() + blob_b.len()) as u64);
        assert_eq!(summary.dedup_savings_bytes, blob_a.len() as u64);
        assert!(summary.dedup_ratio_bps > 0);
        assert_eq!(summary.corrupted_blobs, 0);
        assert!(summary.healthy);

        // Ensure serialized JSON never leaks host filesystem path
        let json_str = serde_json::to_string(&summary).unwrap();
        assert!(!json_str.contains(&temp_dir.path().to_string_lossy().to_string()));

        // Tamper with blob_a on disk to verify corruption detection
        let path_a = store.blob_path(digest_a.as_str()).unwrap();
        tokio::fs::write(&path_a, b"tampered-corrupt-content")
            .await
            .unwrap();

        let corrupt_summary = store.storage_health_summary().await.unwrap();
        assert_eq!(corrupt_summary.total_blobs, 2);
        assert_eq!(corrupt_summary.corrupted_blobs, 1);
        assert!(!corrupt_summary.healthy);
    }

    #[test]
    fn test_cached_scrub_snapshot_and_corruption_recording() {
        let store = CasStore::new("/var/lib/mu-registry");
        let cloned = store.clone();
        assert!(store.cached_scrub_snapshot().is_none());

        store.record_scrub_snapshot(0, 1_700_000_000_000);
        assert_eq!(
            cloned.cached_scrub_snapshot(),
            Some(CasScrubSnapshot {
                corrupted_blobs: 0,
                last_scrub_epoch_ms: 1_700_000_000_000,
            })
        );

        // Read-path corruption detection marks unhealthy without inflating above 1 on repeats
        cloned.record_detected_corruption();
        let after_first = store.cached_scrub_snapshot().unwrap();
        assert_eq!(after_first.corrupted_blobs, 1);
        assert!(after_first.last_scrub_epoch_ms > 0);

        store.record_detected_corruption();
        assert_eq!(store.cached_scrub_snapshot().unwrap().corrupted_blobs, 1);

        // A subsequent clean full scrub resets corrupted_blobs back to 0
        store.record_scrub_snapshot(0, 1_700_000_005_000);
        assert_eq!(
            cloned.cached_scrub_snapshot(),
            Some(CasScrubSnapshot {
                corrupted_blobs: 0,
                last_scrub_epoch_ms: 1_700_000_005_000,
            })
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_fast_health_summary_metadata_only_latency_and_scrub_propagation() {
        let temp_dir = tempdir().unwrap();
        let store = CasStore::new(temp_dir.path());
        store.init().await.unwrap();

        let blob_a = b"fast-summary-alpha-payload";
        let blob_large = vec![0x5Au8; 4 * 1024 * 1024];
        let digest_a = store.put_blob(blob_a).await.unwrap();
        let _digest_large = store.put_blob(&blob_large).await.unwrap();
        // Record deduplication savings on duplicate write
        let _dup = store.put_blob(blob_a).await.unwrap();

        // Tamper with blob_a bytes (preserving length) BEFORE any scrub runs
        let path_a = store.blob_path(digest_a.as_str()).unwrap();
        let tampered = vec![b'X'; blob_a.len()];
        tokio::fs::write(&path_a, &tampered).await.unwrap();

        // fast_health_summary() uses metadata only (zero blob reads / zero SHA-256 hashing)
        let started = std::time::Instant::now();
        let fast_before_scrub = store.fast_health_summary().await.unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "fast_health_summary took {:?}, expected < 50ms",
            elapsed
        );
        assert_eq!(fast_before_scrub.total_blobs, 2);
        assert_eq!(
            fast_before_scrub.total_bytes,
            (blob_a.len() + blob_large.len()) as u64
        );
        assert_eq!(fast_before_scrub.dedup_savings_bytes, blob_a.len() as u64);
        assert_eq!(fast_before_scrub.corrupted_blobs, 0);
        assert!(fast_before_scrub.healthy);
        assert!(fast_before_scrub.last_scrub_epoch_ms > 0);

        // Full cryptographic scrub detects corruption and populates the cached snapshot
        let scrubbed = store.storage_health_summary().await.unwrap();
        assert_eq!(scrubbed.corrupted_blobs, 1);
        assert!(!scrubbed.healthy);

        // Subsequent fast_health_summary() propagates cached corruption in < 50ms
        let started_after = std::time::Instant::now();
        let fast_after_scrub = store.fast_health_summary().await.unwrap();
        let elapsed_after = started_after.elapsed();
        assert!(
            elapsed_after < std::time::Duration::from_millis(50),
            "fast_health_summary after scrub took {:?}, expected < 50ms",
            elapsed_after
        );
        assert_eq!(fast_after_scrub.total_blobs, 2);
        assert_eq!(
            fast_after_scrub.total_bytes,
            (blob_a.len() + blob_large.len()) as u64
        );
        assert_eq!(fast_after_scrub.corrupted_blobs, 1);
        assert!(!fast_after_scrub.healthy);
        assert_eq!(
            fast_after_scrub.last_scrub_epoch_ms,
            scrubbed.last_scrub_epoch_ms
        );

        // Read-path corruption detection in get_blob() immediately marks a fresh store unhealthy
        let temp_dir_read = tempdir().unwrap();
        let read_store = CasStore::new(temp_dir_read.path());
        read_store.init().await.unwrap();
        let d_read = read_store.put_blob(b"intact-before-tamper").await.unwrap();
        assert!(read_store.fast_health_summary().await.unwrap().healthy);
        tokio::fs::write(read_store.blob_path(d_read.as_str()).unwrap(), b"corrupted")
            .await
            .unwrap();
        assert!(matches!(
            read_store.get_blob(d_read.as_str()).await,
            Err(StorageError::CorruptBlob(_))
        ));
        let after_read_err = read_store.fast_health_summary().await.unwrap();
        assert_eq!(after_read_err.corrupted_blobs, 1);
        assert!(!after_read_err.healthy);
    }
}
