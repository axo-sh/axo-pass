//! Lists GPG keys by parsing gpg's `--with-colons` machine-readable output.
//!
//! The colon format is documented in GnuPG's `doc/DETAILS`. Fields are
//! 1-indexed there and here, so field 12 is `parts[11]`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use secrecy::{ExposeSecret, SecretString};

use crate::core::find_bin_folder::find_bin_folder;
use crate::gpg::GpgError;
use crate::gpg::agent_conf::gnupg_home;
use crate::secrets::keychain::generic_password::PasswordEntry;

/// What a key or subkey may be used for, from the capability field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpgCapability {
    Sign,
    Certify,
    Encrypt,
    Authenticate,
}

impl GpgCapability {
    fn from_char(c: char) -> Option<Self> {
        match c {
            's' => Some(GpgCapability::Sign),
            'c' => Some(GpgCapability::Certify),
            'e' => Some(GpgCapability::Encrypt),
            'a' => Some(GpgCapability::Authenticate),
            _ => None,
        }
    }
}

/// Owner trust, from the validity field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpgTrust {
    Unknown,
    Undefined,
    Never,
    Marginal,
    Full,
    Ultimate,
    Expired,
    Revoked,
    Invalid,
    Disabled,
}

impl GpgTrust {
    fn from_field(field: &str) -> Self {
        match field.chars().next() {
            Some('q') => GpgTrust::Undefined,
            Some('n') => GpgTrust::Never,
            Some('m') => GpgTrust::Marginal,
            Some('f') => GpgTrust::Full,
            Some('u') => GpgTrust::Ultimate,
            Some('e') => GpgTrust::Expired,
            Some('r') => GpgTrust::Revoked,
            Some('i') => GpgTrust::Invalid,
            Some('d') => GpgTrust::Disabled,
            _ => GpgTrust::Unknown,
        }
    }
}

/// Whether the private key material is present, and in what form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpgSecretState {
    /// No private key in the keyring.
    None,
    /// The private key is in `private-keys-v1.d`.
    Present,
    /// A stub pointing at a smartcard or token.
    Card,
    /// A stub for a key kept offline.
    Offline,
}

#[derive(Debug, Clone)]
pub struct GpgUserId {
    /// The full uid string, e.g. `Dana Reyes <dana@example.com>`.
    pub uid: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub trust: GpgTrust,
    pub is_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct GpgSubkey {
    pub key_id: String,
    pub fingerprint: Option<String>,
    pub keygrip: Option<String>,
    pub algorithm: String,
    pub key_length: u32,
    pub curve: Option<String>,
    pub capabilities: Vec<GpgCapability>,
    /// Unix seconds.
    pub created_at: Option<i64>,
    /// Unix seconds. `None` means the key does not expire.
    pub expires_at: Option<i64>,
    pub is_expired: bool,
    pub is_revoked: bool,
    pub secret_state: GpgSecretState,
    /// Whether a passphrase for this subkey's keygrip is saved in the keychain.
    pub has_saved_password: bool,
    /// Whether gpg-agent holds this subkey encrypted, so using it needs a
    /// passphrase.
    pub requires_passphrase: bool,
}

/// A GPG key merged from the public and secret keyring listings.
#[derive(Debug, Clone)]
pub struct GpgKeyOverview {
    /// Long key id of the primary key.
    pub key_id: String,
    pub fingerprint: String,
    pub keygrip: Option<String>,
    pub user_ids: Vec<GpgUserId>,
    /// First uid's name, falling back to the whole uid string.
    pub name: String,
    /// First uid's email, when it has one.
    pub email: Option<String>,
    pub algorithm: String,
    pub key_length: u32,
    pub curve: Option<String>,
    /// Capabilities of the primary key itself, not of the key as a whole.
    pub capabilities: Vec<GpgCapability>,
    pub trust: GpgTrust,
    /// Unix seconds.
    pub created_at: Option<i64>,
    /// Unix seconds. `None` means the key does not expire.
    pub expires_at: Option<i64>,
    pub is_expired: bool,
    pub is_revoked: bool,
    pub is_disabled: bool,
    pub secret_state: GpgSecretState,
    /// Whether a passphrase for this key is saved in the keychain.
    pub has_saved_password: bool,
    /// Whether any of the key's local secret halves is encrypted, so there is
    /// a passphrase to save.
    pub requires_passphrase: bool,
    /// Directory holding the private key files, when a secret key is present.
    pub secret_key_dir: Option<String>,
    pub subkeys: Vec<GpgSubkey>,
}

impl GpgKeyOverview {
    pub fn has_secret(&self) -> bool {
        self.secret_state != GpgSecretState::None
    }

    /// Short form of the key id, as gpg prints it with `--keyid-format short`.
    pub fn short_key_id(&self) -> String {
        let len = self.key_id.len();
        self.key_id[len.saturating_sub(8)..].to_string()
    }
}

/// List every key in the public keyring, with secret key state merged in from
/// the secret keyring.
pub fn list_gpg_keys() -> Result<Vec<GpgKeyOverview>, GpgError> {
    let Some(bin_dir) = find_bin_folder("gpg") else {
        return Err(GpgError::GpgNotFound);
    };
    let gpg = bin_dir.join("gpg");

    let public = run_listing(&gpg, "--list-keys")?;
    let secret = run_listing(&gpg, "--list-secret-keys")?;

    let mut keys = parse_listing(&public);
    let secret_keys = parse_listing(&secret);
    merge_secret_state(&mut keys, &secret_keys);

    // Keychain entries and audit events name a key by its keygrip, which is
    // what gpg-agent passes to pinentry, so saved passphrases are looked up
    // per keygrip rather than per fingerprint.
    let private_dir = gnupg_home().join("private-keys-v1.d");
    let protection = keygrip_protection(&bin_dir);
    for key in &mut keys {
        for sub in &mut key.subkeys {
            sub.has_saved_password = has_saved_password(sub.keygrip.as_deref());
            sub.requires_passphrase = is_protected(&protection, sub.keygrip.as_deref());
        }
        key.has_saved_password = has_saved_password(key.keygrip.as_deref())
            || key.subkeys.iter().any(|sub| sub.has_saved_password);
        key.requires_passphrase = is_protected(&protection, key.keygrip.as_deref())
            || key.subkeys.iter().any(|sub| sub.requires_passphrase);
        if key.secret_state == GpgSecretState::Present {
            key.secret_key_dir = Some(display_path(&private_dir));
        }
    }

    keys.sort_by(|a, b| {
        b.has_secret()
            .cmp(&a.has_secret())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(keys)
}

fn has_saved_password(keygrip: Option<&str>) -> bool {
    let Some(keygrip) = keygrip else { return false };
    PasswordEntry::gpg(keygrip).exists().unwrap_or(false)
}

/// Save a key's passphrase to the keychain, after checking it with gpg.
///
/// gpg-agent names a key by keygrip, so a key with subkeys has one keychain
/// entry per keygrip whose secret half is on disk. They share a passphrase in
/// practice, so the verified passphrase is written under each of them. Returns
/// the keygrips written.
pub fn save_passphrase(
    fingerprint: &str,
    passphrase: SecretString,
) -> Result<Vec<String>, GpgError> {
    let key = list_gpg_keys()?
        .into_iter()
        .find(|k| k.fingerprint == fingerprint)
        .ok_or_else(|| GpgError::KeyNotFound(fingerprint.to_string()))?;

    let keygrips = local_keygrips(&key);
    if keygrips.is_empty() {
        return Err(GpgError::NoSecretKey(fingerprint.to_string()));
    }

    let Some(bin_dir) = find_bin_folder("gpg") else {
        return Err(GpgError::GpgNotFound);
    };
    // A key gpg stores unencrypted has no passphrase to save, and an entry for
    // one would never be read: gpg-agent never asks.
    let protection = keygrip_protection(&bin_dir);
    let keygrips: Vec<String> = keygrips
        .into_iter()
        .filter(|keygrip| is_protected(&protection, Some(keygrip)))
        .collect();
    if keygrips.is_empty() {
        return Err(GpgError::NoPassphrase(fingerprint.to_string()));
    }

    verify_passphrase(&bin_dir, &key.fingerprint, &keygrips, &passphrase)?;

    for keygrip in &keygrips {
        let entry = PasswordEntry::gpg(keygrip);
        // Replace rather than refuse, so a changed passphrase can be saved
        // again without deleting the old entry first.
        let _ = entry.delete();
        entry
            .save_password(passphrase.clone())
            .map_err(|e| GpgError::SaveFailed(e.to_string()))?;
    }
    Ok(keygrips)
}

/// The keygrips whose secret key is on this machine. Smartcard and offline
/// stubs have no local key material to unlock.
fn local_keygrips(key: &GpgKeyOverview) -> Vec<String> {
    let mut keygrips = Vec::new();
    if key.secret_state == GpgSecretState::Present
        && let Some(keygrip) = key.keygrip.clone()
    {
        keygrips.push(keygrip);
    }
    for sub in &key.subkeys {
        if sub.secret_state == GpgSecretState::Present
            && let Some(keygrip) = sub.keygrip.clone()
        {
            keygrips.push(keygrip);
        }
    }
    keygrips
}

/// Check a passphrase by exporting the secret key, which makes gpg-agent
/// decrypt every secret half the key has. The export goes to `/dev/null`: only
/// the exit status matters.
///
/// gpg-agent caches passphrases, and a cached one would let a wrong passphrase
/// pass, so the cache is cleared for each keygrip first.
fn verify_passphrase(
    bin_dir: &Path,
    fingerprint: &str,
    keygrips: &[String],
    passphrase: &SecretString,
) -> Result<(), GpgError> {
    clear_agent_cache(bin_dir, keygrips);

    let mut child = Command::new(bin_dir.join("gpg"))
        .args([
            "--batch",
            "--yes",
            "--no-tty",
            // The passphrase goes over stdin rather than the command line,
            // where `ps` would show it.
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
            "--output",
            "/dev/null",
            "--export-secret-keys",
            fingerprint,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .inspect_err(|e| log::debug!("Failed to run gpg --export-secret-keys: {e}"))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(passphrase.expose_secret().as_bytes())?;
    }
    drop(child.stdin.take());

    let output = child.wait_with_output()?;
    // Clear the cache again: verifying leaves the passphrase cached, and a
    // wrong one that gpg rejected is no reason to change what the agent holds.
    clear_agent_cache(bin_dir, keygrips);

    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    log::debug!("gpg rejected the passphrase: {stderr}");
    if stderr.contains("Bad passphrase") || stderr.contains("bad passphrase") {
        return Err(GpgError::BadPassphrase);
    }
    Err(GpgError::VerifyFailed(stderr))
}

/// Every keygrip gpg-agent knows, and whether it holds that key encrypted.
///
/// `KEYINFO --list` answers with a line per key: `S KEYINFO <grip> <type>
/// <serial> <idstr> <cached> <protection> <fpr> <ttl> <flags>`, where the
/// protection field is `P` for a protected key, `C` for one stored in the
/// clear, and `-` when the agent does not know. `None` means the agent could
/// not be asked, which leaves protection unknown rather than answered.
fn keygrip_protection(bin_dir: &Path) -> Option<BTreeMap<String, String>> {
    let output = Command::new(bin_dir.join("gpg-connect-agent"))
        .args(["KEYINFO --list", "/bye"])
        .stderr(Stdio::null())
        .output()
        .inspect_err(|e| log::debug!("Failed to list keygrips: {e}"))
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(
        stdout
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                (parts.next() == Some("S") && parts.next() == Some("KEYINFO")).then_some(())?;
                let keygrip = parts.next()?;
                let protection = parts.nth(4)?;
                Some((keygrip.to_string(), protection.to_string()))
            })
            .collect(),
    )
}

/// Whether a keygrip's key needs a passphrase to use. A key the agent does not
/// list is not on this machine; an agent that could not be asked leaves every
/// key protected, so nothing is refused on a guess.
fn is_protected(protection: &Option<BTreeMap<String, String>>, keygrip: Option<&str>) -> bool {
    let Some(keygrip) = keygrip else { return false };
    let Some(protection) = protection else {
        return true;
    };
    match protection.get(keygrip) {
        Some(state) => state != "C",
        None => false,
    }
}

/// Drop each keygrip's cached passphrase, so a cached one cannot stand in for
/// the passphrase being checked. A failure here is not fatal: it only means
/// the check may pass on a cached passphrase.
fn clear_agent_cache(bin_dir: &Path, keygrips: &[String]) {
    let connect = bin_dir.join("gpg-connect-agent");
    if !connect.exists() {
        return;
    }
    for keygrip in keygrips {
        let _ = Command::new(&connect)
            .args([&format!("CLEAR_PASSPHRASE --mode=normal {keygrip}"), "/bye"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .inspect_err(|e| log::debug!("Failed to clear the agent cache: {e}"));
    }
}

/// Export one key's public half in ASCII armor.
pub fn export_public_key(fingerprint: &str) -> Result<String, GpgError> {
    let Some(bin_dir) = find_bin_folder("gpg") else {
        return Err(GpgError::GpgNotFound);
    };
    let output = Command::new(bin_dir.join("gpg"))
        .args(["--armor", "--export", "--batch", "--no-tty", fingerprint])
        .output()
        .inspect_err(|e| log::debug!("Failed to run gpg --export: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(GpgError::ListFailed(stderr));
    }
    let armored = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if armored.is_empty() {
        return Err(GpgError::ListFailed("no public key found".to_string()));
    }
    Ok(armored)
}

/// Render a path with the home directory abbreviated to `~`.
fn display_path(path: &PathBuf) -> String {
    let text = path.to_string_lossy().to_string();
    let Some(home) = dirs::home_dir() else {
        return text;
    };
    match path.strip_prefix(&home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => text,
    }
}

fn run_listing(gpg: &PathBuf, mode: &str) -> Result<String, GpgError> {
    let output = Command::new(gpg)
        .args([
            mode,
            "--with-colons",
            "--fixed-list-mode",
            "--with-fingerprint",
            "--with-fingerprint",
            "--with-keygrip",
            "--batch",
            "--no-tty",
        ])
        .output()
        .inspect_err(|e| log::debug!("Failed to run gpg {mode}: {e}"))?;

    // An empty keyring exits non-zero on some gpg versions, so an empty stdout
    // is treated as no keys rather than as a failure.
    if !output.status.success() && output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if stderr.contains("no ") && stderr.contains("keyring") {
            return Ok(String::new());
        }
        log::debug!("gpg {mode} failed: {stderr}");
        return Err(GpgError::ListFailed(stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Which record the fingerprint and keygrip lines that follow belong to.
enum Cursor {
    Primary,
    Subkey(usize),
}

fn parse_listing(text: &str) -> Vec<GpgKeyOverview> {
    let mut keys: Vec<GpgKeyOverview> = Vec::new();
    let mut cursor = Cursor::Primary;

    for line in text.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        let Some(record) = parts.first() else {
            continue;
        };
        match *record {
            "pub" | "sec" => {
                keys.push(primary_from_record(&parts, *record == "sec"));
                cursor = Cursor::Primary;
            },
            "sub" | "ssb" => {
                let Some(key) = keys.last_mut() else { continue };
                key.subkeys
                    .push(subkey_from_record(&parts, *record == "ssb"));
                cursor = Cursor::Subkey(key.subkeys.len() - 1);
            },
            "uid" => {
                let Some(key) = keys.last_mut() else { continue };
                if let Some(uid) = user_id_from_record(&parts) {
                    key.user_ids.push(uid);
                }
            },
            "fpr" => {
                let Some(key) = keys.last_mut() else { continue };
                let Some(value) = field(&parts, 10) else {
                    continue;
                };
                match cursor {
                    Cursor::Primary => key.fingerprint = value,
                    Cursor::Subkey(i) => {
                        if let Some(sub) = key.subkeys.get_mut(i) {
                            sub.fingerprint = Some(value);
                        }
                    },
                }
            },
            "grp" => {
                let Some(key) = keys.last_mut() else { continue };
                let Some(value) = field(&parts, 10) else {
                    continue;
                };
                match cursor {
                    Cursor::Primary => key.keygrip = Some(value),
                    Cursor::Subkey(i) => {
                        if let Some(sub) = key.subkeys.get_mut(i) {
                            sub.keygrip = Some(value);
                        }
                    },
                }
            },
            _ => {},
        }
    }

    for key in &mut keys {
        let (name, email) = match key.user_ids.first() {
            Some(uid) => (
                uid.name.clone().unwrap_or_else(|| uid.uid.clone()),
                uid.email.clone(),
            ),
            None => (key.short_key_id(), None),
        };
        key.name = name;
        key.email = email;
    }
    keys
}

/// Copy secret key state from the secret keyring listing onto the matching
/// public keys, matched by fingerprint.
fn merge_secret_state(keys: &mut [GpgKeyOverview], secret_keys: &[GpgKeyOverview]) {
    let by_fingerprint: BTreeMap<&str, &GpgKeyOverview> = secret_keys
        .iter()
        .map(|k| (k.fingerprint.as_str(), k))
        .collect();

    for key in keys.iter_mut() {
        let Some(secret) = by_fingerprint.get(key.fingerprint.as_str()) else {
            continue;
        };
        key.secret_state = secret.secret_state;
        if key.keygrip.is_none() {
            key.keygrip = secret.keygrip.clone();
        }
        let secret_subs: BTreeMap<&str, &GpgSubkey> = secret
            .subkeys
            .iter()
            .map(|s| (s.key_id.as_str(), s))
            .collect();
        for sub in &mut key.subkeys {
            let Some(secret_sub) = secret_subs.get(sub.key_id.as_str()) else {
                continue;
            };
            sub.secret_state = secret_sub.secret_state;
            if sub.keygrip.is_none() {
                sub.keygrip = secret_sub.keygrip.clone();
            }
        }
    }
}

fn primary_from_record(parts: &[&str], is_secret: bool) -> GpgKeyOverview {
    let validity = field(parts, 2).unwrap_or_default();
    GpgKeyOverview {
        key_id: field(parts, 5).unwrap_or_default(),
        fingerprint: String::new(),
        keygrip: None,
        user_ids: Vec::new(),
        name: String::new(),
        email: None,
        algorithm: algorithm_name(field(parts, 4).as_deref()),
        key_length: field(parts, 3)
            .and_then(|s| s.parse().ok())
            .unwrap_or_default(),
        curve: field(parts, 17),
        capabilities: capabilities(field(parts, 12).as_deref()),
        trust: GpgTrust::from_field(&validity),
        created_at: timestamp(field(parts, 6).as_deref()),
        expires_at: timestamp(field(parts, 7).as_deref()),
        is_expired: validity.starts_with('e'),
        is_revoked: validity.starts_with('r'),
        is_disabled: validity.starts_with('d'),
        secret_state: secret_state(parts, is_secret),
        has_saved_password: false,
        requires_passphrase: false,
        secret_key_dir: None,
        subkeys: Vec::new(),
    }
}

fn subkey_from_record(parts: &[&str], is_secret: bool) -> GpgSubkey {
    let validity = field(parts, 2).unwrap_or_default();
    GpgSubkey {
        key_id: field(parts, 5).unwrap_or_default(),
        fingerprint: None,
        keygrip: None,
        algorithm: algorithm_name(field(parts, 4).as_deref()),
        key_length: field(parts, 3)
            .and_then(|s| s.parse().ok())
            .unwrap_or_default(),
        curve: field(parts, 17),
        capabilities: capabilities(field(parts, 12).as_deref()),
        created_at: timestamp(field(parts, 6).as_deref()),
        expires_at: timestamp(field(parts, 7).as_deref()),
        is_expired: validity.starts_with('e'),
        is_revoked: validity.starts_with('r'),
        secret_state: secret_state(parts, is_secret),
        has_saved_password: false,
        requires_passphrase: false,
    }
}

fn user_id_from_record(parts: &[&str]) -> Option<GpgUserId> {
    let uid = unescape(&field(parts, 10)?);
    let validity = field(parts, 2).unwrap_or_default();
    let (name, email) = split_uid(&uid);
    Some(GpgUserId {
        uid,
        name,
        email,
        trust: GpgTrust::from_field(&validity),
        is_revoked: validity.starts_with('r'),
    })
}

/// Field 15 says where the secret half is: `+` for a key on this machine, `#`
/// for a stub whose key is kept offline, and a token serial number for one on
/// a smartcard. Older gpg versions leave it empty, which counts as present.
fn secret_state(parts: &[&str], is_secret: bool) -> GpgSecretState {
    if !is_secret {
        return GpgSecretState::None;
    }
    match field(parts, 15).as_deref() {
        Some("#") => GpgSecretState::Offline,
        Some("+") | None => GpgSecretState::Present,
        Some(_) => GpgSecretState::Card,
    }
}

/// A 1-indexed colon field, empty strings reported as `None`.
fn field(parts: &[&str], index: usize) -> Option<String> {
    let value = parts.get(index - 1)?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Lowercase letters are the record's own capabilities; uppercase letters
/// describe the key as a whole and are ignored here.
fn capabilities(field: Option<&str>) -> Vec<GpgCapability> {
    let mut caps = Vec::new();
    for c in field.unwrap_or_default().chars() {
        if let Some(cap) = GpgCapability::from_char(c)
            && !caps.contains(&cap)
        {
            caps.push(cap);
        }
    }
    caps
}

/// Dates are unix seconds, or `yyyymmddThhmmss` on older keys.
fn timestamp(field: Option<&str>) -> Option<i64> {
    let value = field?;
    if let Ok(seconds) = value.parse::<i64>() {
        return (seconds > 0).then_some(seconds);
    }
    let (date, _) = value.split_once('T')?;
    let year: i64 = date.get(0..4)?.parse().ok()?;
    let month: i64 = date.get(4..6)?.parse().ok()?;
    let day: i64 = date.get(6..8)?.parse().ok()?;
    Some(days_from_civil(year, month, day) * 86_400)
}

/// Days since the unix epoch, from Howard Hinnant's civil calendar algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Public key algorithm numbers, from RFC 4880 and GnuPG's extensions.
fn algorithm_name(field: Option<&str>) -> String {
    match field.unwrap_or_default() {
        "1" | "2" | "3" => "RSA".to_string(),
        "16" | "20" => "ElGamal".to_string(),
        "17" => "DSA".to_string(),
        "18" => "ECDH".to_string(),
        "19" => "ECDSA".to_string(),
        "22" => "EdDSA".to_string(),
        other if other.is_empty() => "Unknown".to_string(),
        other => format!("Algorithm {other}"),
    }
}

/// Split `Name (comment) <email>` into its name and email parts.
fn split_uid(uid: &str) -> (Option<String>, Option<String>) {
    let email = uid
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(email, _)| email.trim().to_string())
        .filter(|e| !e.is_empty());
    let name = match uid.split_once('<') {
        Some((name, _)) => name.trim().to_string(),
        None => uid.trim().to_string(),
    };
    let name = (!name.is_empty()).then_some(name);
    (name, email)
}

/// gpg escapes colons and non-ASCII bytes in uid strings as `\xNN`.
fn unescape(value: &str) -> String {
    if !value.contains("\\x") {
        return value.to_string();
    }
    let mut bytes = Vec::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' || chars.peek() != Some(&'x') {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        chars.next();
        let hex: String = chars.by_ref().take(2).collect();
        match u8::from_str_radix(&hex, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => bytes.extend_from_slice(format!("\\x{hex}").as_bytes()),
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
tru::1:1700000000:0:3:1:5
pub:u:4096:1:7B6D80539C4A:1710720000:1868486400::u:::scESC::::::23::0:
fpr:::::::::9C4A2F1E7B6D80534E9F1C77A2B5D0E36B1488AF:
grp:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
uid:u::::1710720000::ABCDEF::Dana Reyes <dana@breakfastlabs.com>::::::::::0:
sub:u:4096:1:A2B5D0E3:1710720000:1868486400:::::s::::::23:
fpr:::::::::1111222233334444555566667777888899990000:
sub:u:256:22:0D97C412:1710720000::::::a::::::23:
";

    #[test]
    fn parses_primary_key_and_subkeys() {
        let keys = parse_listing(LISTING);
        assert_eq!(keys.len(), 1);
        let key = &keys[0];
        assert_eq!(key.key_id, "7B6D80539C4A");
        assert_eq!(key.fingerprint, "9C4A2F1E7B6D80534E9F1C77A2B5D0E36B1488AF");
        assert_eq!(
            key.keygrip.as_deref(),
            Some("AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
        );
        assert_eq!(key.algorithm, "RSA");
        assert_eq!(key.key_length, 4096);
        assert_eq!(key.name, "Dana Reyes");
        assert_eq!(key.email.as_deref(), Some("dana@breakfastlabs.com"));
        assert_eq!(key.trust, GpgTrust::Ultimate);
        assert_eq!(
            key.capabilities,
            vec![GpgCapability::Sign, GpgCapability::Certify]
        );
        assert_eq!(key.created_at, Some(1710720000));
        assert_eq!(key.expires_at, Some(1868486400));
        assert_eq!(key.secret_state, GpgSecretState::None);

        assert_eq!(key.subkeys.len(), 2);
        assert_eq!(key.subkeys[0].key_id, "A2B5D0E3");
        assert_eq!(
            key.subkeys[0].fingerprint.as_deref(),
            Some("1111222233334444555566667777888899990000")
        );
        assert_eq!(key.subkeys[0].capabilities, vec![GpgCapability::Sign]);
        assert_eq!(
            key.subkeys[1].capabilities,
            vec![GpgCapability::Authenticate]
        );
        assert_eq!(key.subkeys[1].expires_at, None);
        assert_eq!(key.subkeys[1].algorithm, "EdDSA");
    }

    #[test]
    fn merges_secret_state_by_fingerprint() {
        // Field 15 carries `+` for a key on this machine and `#` for an
        // offline stub, which is what tells the two apart.
        let secret = "\
sec:u:4096:1:7B6D80539C4A:1710720000:1868486400::u:::scESC:::+:::23::0:
fpr:::::::::9C4A2F1E7B6D80534E9F1C77A2B5D0E36B1488AF:
uid:u::::1710720000::ABCDEF::Dana Reyes <dana@breakfastlabs.com>::::::::::0:
ssb:u:4096:1:A2B5D0E3:1710720000:1868486400:::::s:::+:::23:
";
        let mut keys = parse_listing(LISTING);
        merge_secret_state(&mut keys, &parse_listing(secret));
        assert_eq!(keys[0].secret_state, GpgSecretState::Present);
        assert_eq!(keys[0].subkeys[0].secret_state, GpgSecretState::Present);
        assert_eq!(keys[0].subkeys[1].secret_state, GpgSecretState::None);
    }

    #[test]
    fn reads_offline_and_card_secret_state() {
        let offline = "\
sec:u:3072:1:AAAA111122223333:1710720000:::u:::scESC:::#:::23::0:
fpr:::::::::0000111122223333444455556666777788889999:
uid:u::::1710720000::ABCDEF::Air Gapped <airgap@example.test>::::::::::0:
ssb:u:3072:1:BBBB444455556666:1710720000::::::s:::+:::23:
";
        let keys = parse_listing(offline);
        assert_eq!(keys[0].secret_state, GpgSecretState::Offline);
        assert_eq!(keys[0].subkeys[0].secret_state, GpgSecretState::Present);

        let card = "\
sec:u:2048:1:CCCC777788889999:1710720000:::u:::scESC:::D2760001240102000006123456780000:::23::0:
fpr:::::::::AAAA111122223333444455556666777788889999:
uid:u::::1710720000::ABCDEF::On A Token <token@example.test>::::::::::0:
";
        assert_eq!(parse_listing(card)[0].secret_state, GpgSecretState::Card);
    }

    #[test]
    fn unescapes_uid_bytes() {
        assert_eq!(unescape("A\\x3aB"), "A:B");
        assert_eq!(unescape("plain"), "plain");
    }

    #[test]
    fn parses_legacy_date_format() {
        assert_eq!(timestamp(Some("19700102T000000")), Some(86_400));
    }
}
