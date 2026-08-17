//! Unwrapping the store's master key.
//!
//! **This is constraint 2 from the founder's decisions, made concrete.** v1 is
//! CLI-first, so the Secure Enclave is v2 work. The risk that carries is that
//! the Apple hardware path stays unproven until late. The mitigation, recorded
//! with the decision, is that the master key is wrapped by a *pluggable*
//! unwrapper from the first commit: v1 ships [`FileUnwrapper`], v2 drops in an
//! Enclave implementation, and the storage layer never changes.
//!
//! If v1 instead hardcoded how the key is unwrapped, v2 would be a rewrite of
//! the storage layer rather than a new implementation of one trait.
//!
//! ## What the Enclave can and cannot do, recorded here so it is not
//! rediscovered
//!
//! The Secure Enclave supports NIST P-256 elliptic curve keys only. No RSA, no
//! symmetric keys. You therefore **cannot store an API key in the Enclave**.
//! You use an Enclave key to unwrap the store's symmetric key. The Enclave
//! protects the door, not the contents, which is exactly the shape this trait
//! describes.
//!
//! With `biometryCurrentSet`, adding or removing a fingerprint, or changing the
//! machine password, makes every biometry-protected item **permanently
//! inaccessible**. That is Apple's intended behaviour, and it is why constraint
//! 3 exists: the break-glass export is mandatory, and its format is designed in
//! v1 even though the app is v2.

use crate::secret::SecretValue;

/// Turns a wrapped master key into a usable one.
///
/// Implementations are expected to be slow and to involve user presence. The
/// daemon calls this on unlock, not per request: the Touch ID policy in the
/// handoff is explicit that a normal API call through the proxy must not prompt,
/// or the tool becomes unusable.
pub trait MasterKeyUnwrapper: Send + Sync {
    /// A short stable name, recorded in the store header so a store knows which
    /// unwrapper wrote it. Without this a v1 store and a v2 store are
    /// indistinguishable until decryption fails.
    fn id(&self) -> &'static str;

    /// Does this unwrapper require a live human?
    ///
    /// The file unwrapper does not, which is what lets the daemon run headless
    /// on a Linux server. The Enclave unwrapper does, which is the whole point
    /// of it on the founder's Mac.
    fn requires_presence(&self) -> bool;

    fn unwrap_master_key(&self, wrapped: &[u8]) -> Result<SecretValue, UnwrapError>;

    fn wrap_master_key(&self, master: &SecretValue) -> Result<Vec<u8>, UnwrapError>;
}

#[derive(Debug, thiserror::Error)]
pub enum UnwrapError {
    #[error("no key material available at {path}")]
    Missing { path: String },

    #[error("key file {path} has mode {mode:o}, expected 0600")]
    BadPermissions { path: String, mode: u32 },

    #[error("wrapped key is malformed: {0}")]
    Malformed(String),

    #[error("this store was written by the {wrote} unwrapper, but {have} is configured")]
    WrongUnwrapper { wrote: String, have: String },

    #[error("the platform refused to unwrap: {0}")]
    PlatformRefused(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// v1's unwrapper: the master key sits in a file the service account owns.
///
/// Be honest about what this is worth. It is **not** the Enclave, and it does
/// not require presence. What protects it in v1 is the same thing that protects
/// the store itself: file mode 0600 owned by the `_vaultd` service account, so
/// a refusal to read it comes from the macOS kernel rather than from LoopsVault
/// code. That is a real boundary against an agent running as the login user,
/// and it is not a boundary against root.
pub struct FileUnwrapper {
    path: std::path::PathBuf,
}

impl FileUnwrapper {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        FileUnwrapper { path: path.into() }
    }

    /// Refuse to use a key file that anyone else can read.
    ///
    /// Checked on every unwrap rather than once at startup, because the mode
    /// can change under a running daemon and the cost of a `stat` is nothing
    /// next to what it protects.
    #[cfg(unix)]
    fn check_permissions(&self) -> Result<(), UnwrapError> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&self.path)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(UnwrapError::BadPermissions {
                path: self.path.display().to_string(),
                mode,
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_permissions(&self) -> Result<(), UnwrapError> {
        Ok(())
    }
}

impl MasterKeyUnwrapper for FileUnwrapper {
    fn id(&self) -> &'static str {
        "file-v1"
    }

    fn requires_presence(&self) -> bool {
        false
    }

    fn unwrap_master_key(&self, wrapped: &[u8]) -> Result<SecretValue, UnwrapError> {
        if !self.path.exists() {
            return Err(UnwrapError::Missing {
                path: self.path.display().to_string(),
            });
        }
        self.check_permissions()?;

        // v1 keeps the wrapping trivially simple and says so out loud: the file
        // holds the master key, and `wrapped` is expected to be the empty
        // marker written by `wrap_master_key`. The real work here is the
        // permission check and the trait shape, not the arithmetic. When the
        // Enclave implementation lands it does the actual unwrap, and nothing
        // above this line changes.
        if !wrapped.is_empty() {
            return Err(UnwrapError::Malformed(
                "file-v1 stores no wrapped blob; expected an empty marker".into(),
            ));
        }

        let raw = std::fs::read_to_string(&self.path)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(UnwrapError::Malformed("key file is empty".into()));
        }
        Ok(SecretValue::new(trimmed))
    }

    fn wrap_master_key(&self, _master: &SecretValue) -> Result<Vec<u8>, UnwrapError> {
        // Nothing to store beside the store: the key lives in the file.
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// `label` must be unique per test. Tests run in parallel in one process,
    /// so a path derived only from the pid means one test deletes the key file
    /// another is still reading.
    fn temp_key(label: &str, mode: u32, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("lv-unwrap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("key-{label}-{mode:o}"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        path
    }

    #[test]
    fn reads_a_correctly_owned_key() {
        let path = temp_key("reads", 0o600, "FAKE-master-key-v1\n");
        let u = FileUnwrapper::new(&path);
        let key = u.unwrap_master_key(&[]).unwrap();
        assert_eq!(key.expose(), "FAKE-master-key-v1");
        assert_eq!(u.id(), "file-v1");
        assert!(!u.requires_presence());
        let _ = std::fs::remove_file(path);
    }

    /// A world-readable master key is the whole boundary gone. Refuse rather
    /// than warn.
    #[cfg(unix)]
    #[test]
    fn refuses_a_key_file_others_can_read() {
        let path = temp_key("perms", 0o644, "FAKE-master-key-v1");
        let u = FileUnwrapper::new(&path);
        let err = u.unwrap_master_key(&[]).unwrap_err();
        assert!(
            matches!(err, UnwrapError::BadPermissions { mode: 0o644, .. }),
            "got {err:?}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_key_is_reported_not_guessed() {
        let u = FileUnwrapper::new("/nonexistent/loopsvault/master.key");
        assert!(matches!(
            u.unwrap_master_key(&[]).unwrap_err(),
            UnwrapError::Missing { .. }
        ));
    }

    /// The trait is the point of this module, so prove it is object safe. If
    /// this stops compiling, the Enclave implementation cannot be dropped in
    /// behind the same interface and constraint 2 is broken.
    #[test]
    fn the_unwrapper_is_pluggable() {
        let path = temp_key("pluggable", 0o600, "FAKE-master-key-v1");
        let boxed: Box<dyn MasterKeyUnwrapper> = Box::new(FileUnwrapper::new(&path));
        assert_eq!(boxed.id(), "file-v1");
        assert!(boxed.unwrap_master_key(&[]).is_ok());
        let _ = std::fs::remove_file(path);
    }

    /// An unwrapper must not silently accept a blob written by a different one.
    #[test]
    fn rejects_a_blob_it_did_not_write() {
        let path = temp_key("wrongblob", 0o600, "FAKE-master-key-v1");
        let u = FileUnwrapper::new(&path);
        assert!(matches!(
            u.unwrap_master_key(b"enclave-wrapped-blob").unwrap_err(),
            UnwrapError::Malformed(_)
        ));
        let _ = std::fs::remove_file(path);
    }
}
