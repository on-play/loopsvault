//! The encrypted credential store.
//!
//! Only the daemon opens this. The CLI talks to the daemon over HTTP on
//! loopback rather than reading the store itself, which keeps exactly one
//! process in the position to decrypt. That is the same reasoning as the
//! `_vaultd` service account in the handoff: fewer things that can read the
//! plaintext, and the ones that cannot are stopped by the operating system
//! rather than by our own code being careful.
//!
//! ## What protects this file
//!
//! Encryption at rest with age, keyed by the master key the pluggable unwrapper
//! produces. That covers a stolen laptop, a leaked backup, an iCloud sync, and
//! an accidental `git commit`. Plus mode 0600, which is what stops an agent
//! running as the login user, enforced by the kernel.
//!
//! It does not stop root. Nothing at this layer does, and the handoff says so
//! plainly. Do not oversell it.
//!
//! ## Constraint 3, made concrete
//!
//! The break-glass export format is designed here, in v1, even though the
//! SwiftUI app and the Secure Enclave are v2 work. The reason is specific: with
//! `biometryCurrentSet`, adding or removing a fingerprint, or changing the
//! machine password, makes every biometry-protected item permanently
//! inaccessible. That is Apple's intended behaviour. A store written by v1 has
//! to still be recoverable after the Enclave lands, so [`CredentialStore::export_break_glass`]
//! exists now and writes a format that is deliberately independent of whichever
//! unwrapper is in use.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use loopsvault_core::secret::SecretValue;
use loopsvault_core::unwrap::MasterKeyUnwrapper;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// The on-disk plaintext, before encryption. Never written unencrypted.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StorePlaintext {
    /// Which unwrapper wrote this store. Without it, a v1 store and a v2 store
    /// are indistinguishable until decryption fails with a confusing error.
    unwrapper: String,
    /// name -> value.
    values: BTreeMap<String, String>,
}

pub struct CredentialStore {
    path: PathBuf,
    master: SecretValue,
    unwrapper_id: String,
    values: BTreeMap<String, SecretValue>,
}

/// Written by hand rather than derived. A derived `Debug` here would print the
/// whole value map, which is the exact accident `SecretValue` exists to prevent
/// one level down. Names are shown because the daemon's own logs need to be
/// useful; values are not, and cannot be, because `SecretValue` redacts itself.
impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore")
            .field("path", &self.path)
            .field("unwrapper", &self.unwrapper_id)
            .field("entries", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl CredentialStore {
    /// Open an existing store, or create an empty one.
    pub fn open(
        path: impl Into<PathBuf>,
        unwrapper: &dyn MasterKeyUnwrapper,
    ) -> anyhow::Result<Self> {
        let path = path.into();
        let master = unwrapper
            .unwrap_master_key(&[])
            .context("unwrapping the master key")?;

        if !path.exists() {
            return Ok(CredentialStore {
                path,
                master,
                unwrapper_id: unwrapper.id().to_string(),
                values: BTreeMap::new(),
            });
        }

        check_permissions(&path)?;

        let ciphertext = std::fs::read(&path)
            .with_context(|| format!("reading store {}", path.display()))?;
        let plaintext = decrypt(&ciphertext, &master).context("decrypting the store")?;
        let parsed: StorePlaintext =
            serde_json::from_slice(&plaintext).context("parsing the decrypted store")?;

        if parsed.unwrapper != unwrapper.id() {
            bail!(
                "this store was written by the {} unwrapper but {} is configured. \
                 Recover with the break-glass export rather than guessing.",
                parsed.unwrapper,
                unwrapper.id()
            );
        }

        let values = parsed
            .values
            .into_iter()
            .map(|(k, v)| (k, SecretValue::new(v)))
            .collect();

        Ok(CredentialStore {
            path,
            master,
            unwrapper_id: unwrapper.id().to_string(),
            values,
        })
    }

    pub fn get(&self, name: &str) -> Option<&SecretValue> {
        self.values.get(name)
    }

    /// Store a value.
    ///
    /// Write-only by design: there is no API on this type that hands a value
    /// back out to a caller other than [`Self::get`], which the injection path
    /// uses at the moment the byte goes on the wire. The CLI never gets one.
    /// That is a UI policy rather than a cryptographic guarantee, and the
    /// handoff is explicit about the difference: a machine that can decrypt in
    /// order to use can decrypt in order to display. Its value is behavioural,
    /// and it is substantial, because it kills the habit of peeking at a key
    /// and pasting it into a terminal or an agent prompt.
    pub fn put(&mut self, name: impl Into<String>, value: SecretValue) -> anyhow::Result<()> {
        self.values.insert(name.into(), value);
        self.save()
    }

    pub fn remove(&mut self, name: &str) -> anyhow::Result<bool> {
        let existed = self.values.remove(name).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    pub fn names(&self) -> Vec<&str> {
        self.values.keys().map(|s| s.as_str()).collect()
    }

    pub fn shape_of(&self, name: &str) -> Option<loopsvault_core::Shape> {
        self.values.get(name).map(|v| v.shape())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let plaintext = StorePlaintext {
            unwrapper: self.unwrapper_id.clone(),
            values: self
                .values
                .iter()
                .map(|(k, v)| (k.clone(), v.expose().to_string()))
                .collect(),
        };
        let json = serde_json::to_vec(&plaintext).context("serialising the store")?;
        let ciphertext = encrypt(&json, &self.master).context("encrypting the store")?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        // Write to a temporary file and rename, so an interrupted write cannot
        // leave a truncated store. Losing the store means rotating every key
        // across ten projects.
        let tmp = self.path.with_extension("tmp");
        write_private(&tmp, &ciphertext)?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("replacing {}", self.path.display()))?;
        Ok(())
    }

    /// The break-glass export.
    ///
    /// Encrypted with a passphrase the founder supplies, and deliberately
    /// **independent of the configured unwrapper**: that is the entire point.
    /// If the Enclave refuses to unwrap because a fingerprint changed, the
    /// unwrapper is exactly what is unavailable, so an export that depended on
    /// it would be worthless at the only moment it is needed.
    ///
    /// The format is plain age over the same JSON the store holds, with the
    /// unwrapper field set to `break-glass`. Anything that can read an age file
    /// can recover it, including the `age` CLI already installed on this
    /// machine, with no LoopsVault build required. That last property is not an
    /// accident: a recovery path that needs this software to compile is not a
    /// recovery path.
    pub fn export_break_glass(&self, passphrase: &SecretValue) -> anyhow::Result<Vec<u8>> {
        let plaintext = StorePlaintext {
            unwrapper: "break-glass".to_string(),
            values: self
                .values
                .iter()
                .map(|(k, v)| (k.clone(), v.expose().to_string()))
                .collect(),
        };
        let json = serde_json::to_vec_pretty(&plaintext).context("serialising the export")?;
        encrypt(&json, passphrase).context("encrypting the export")
    }

    /// Read a break-glass export back. Used by recovery and by the round-trip
    /// test that proves the format is actually recoverable.
    pub fn import_break_glass(
        ciphertext: &[u8],
        passphrase: &SecretValue,
    ) -> anyhow::Result<BTreeMap<String, SecretValue>> {
        let plaintext = decrypt(ciphertext, passphrase).context("decrypting the export")?;
        let parsed: StorePlaintext =
            serde_json::from_slice(&plaintext).context("parsing the export")?;
        Ok(parsed
            .values
            .into_iter()
            .map(|(k, v)| (k, SecretValue::new(v)))
            .collect())
    }
}

fn encrypt(plaintext: &[u8], key: &SecretValue) -> anyhow::Result<Vec<u8>> {
    let passphrase = SecretString::from(key.expose().to_string());
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .context("starting age encryption")?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

fn decrypt(ciphertext: &[u8], key: &SecretValue) -> anyhow::Result<Vec<u8>> {
    let passphrase = SecretString::from(key.expose().to_string());
    let decryptor = age::Decryptor::new_buffered(ciphertext).context("reading the age header")?;
    let identity = age::scrypt::Identity::new(passphrase);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("wrong key, or the file is not a LoopsVault store")?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("creating {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "store {} has mode {mode:o}, expected 0600. Refusing to open it: \
             a store others can read is the whole boundary gone.",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use loopsvault_core::unwrap::FileUnwrapper;

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Fixture {
            let dir = std::env::temp_dir()
                .join(format!("lv-store-{}-{label}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let key = dir.join("master.key");
            write_private(&key, b"FAKE-master-key-for-tests").unwrap();
            Fixture { dir }
        }

        fn unwrapper(&self) -> FileUnwrapper {
            FileUnwrapper::new(self.dir.join("master.key"))
        }

        fn store_path(&self) -> PathBuf {
            self.dir.join("vault.store")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn round_trips_through_encryption() {
        let f = Fixture::new("roundtrip");
        {
            let mut s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
            s.put(
                "OPENROUTER_API_KEY",
                SecretValue::new("FAKE-sk-or-v1-000111222"),
            )
            .unwrap();
        }
        let s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
        assert_eq!(
            s.get("OPENROUTER_API_KEY").unwrap().expose(),
            "FAKE-sk-or-v1-000111222"
        );
    }

    /// The property the whole at-rest story rests on. If the value is legible
    /// in the file, encryption is not doing anything.
    #[test]
    fn the_file_on_disk_contains_no_value() {
        let f = Fixture::new("opaque");
        let mut s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
        s.put("K", SecretValue::new("FAKE-sk-or-v1-supersecret")).unwrap();

        let raw = std::fs::read(f.store_path()).unwrap();
        let as_text = String::from_utf8_lossy(&raw);
        assert!(!as_text.contains("FAKE-sk-or-v1-supersecret"));
        assert!(!as_text.contains("supersecret"));
        // Name too: the store is not the catalog, and leaking which credentials
        // exist is reconnaissance even without values.
        assert!(!as_text.contains("OPENROUTER"));
        assert!(as_text.starts_with("age-encryption.org/"));
    }

    #[cfg(unix)]
    #[test]
    fn the_store_is_written_private() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("perms");
        let mut s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
        s.put("K", SecretValue::new("v")).unwrap();
        let mode = std::fs::metadata(f.store_path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "store must not be readable by anyone else");
    }

    #[test]
    fn a_wrong_master_key_cannot_open_the_store() {
        let f = Fixture::new("wrongkey");
        {
            let mut s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
            s.put("K", SecretValue::new("v")).unwrap();
        }
        let other = f.dir.join("other.key");
        write_private(&other, b"FAKE-a-different-master-key").unwrap();
        let err = CredentialStore::open(f.store_path(), &FileUnwrapper::new(&other)).unwrap_err();
        assert!(
            format!("{err:#}").contains("wrong key") || format!("{err:#}").contains("decrypting"),
            "got {err:#}"
        );
    }

    /// Constraint 3. If this test fails, a v1 store becomes unrecoverable the
    /// day a fingerprint changes, which is the failure the handoff calls out as
    /// mandatory to prevent.
    #[test]
    fn break_glass_export_recovers_without_the_unwrapper() {
        let f = Fixture::new("breakglass");
        let mut s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
        s.put("A", SecretValue::new("FAKE-value-a")).unwrap();
        s.put("B", SecretValue::new("FAKE-value-b")).unwrap();

        let passphrase = SecretValue::new("correct horse battery staple");
        let exported = s.export_break_glass(&passphrase).unwrap();

        // Recovery does not consult the unwrapper, the master key file, or the
        // store path. That is the whole point: at recovery time the unwrapper
        // is exactly what is unavailable.
        let recovered = CredentialStore::import_break_glass(&exported, &passphrase).unwrap();
        assert_eq!(recovered.get("A").unwrap().expose(), "FAKE-value-a");
        assert_eq!(recovered.get("B").unwrap().expose(), "FAKE-value-b");

        // It is a real age file, so the age CLI already on this machine can
        // read it with no LoopsVault build.
        assert!(String::from_utf8_lossy(&exported).starts_with("age-encryption.org/"));

        let wrong = SecretValue::new("not the passphrase");
        assert!(CredentialStore::import_break_glass(&exported, &wrong).is_err());
    }

    #[test]
    fn removing_a_credential_persists() {
        let f = Fixture::new("remove");
        {
            let mut s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
            s.put("K", SecretValue::new("v")).unwrap();
            assert!(s.remove("K").unwrap());
            assert!(!s.remove("K").unwrap());
        }
        let s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
        assert!(s.get("K").is_none());
    }

    #[test]
    fn shape_is_available_without_exposing_the_value() {
        let f = Fixture::new("shape");
        let mut s = CredentialStore::open(f.store_path(), &f.unwrapper()).unwrap();
        s.put("K", SecretValue::new("abcdef0123456789")).unwrap();
        let shape = s.shape_of("K").unwrap();
        assert_eq!(shape.len, 16);
        assert_eq!(shape.class, loopsvault_core::CharClass::HexLower);
    }
}
