use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::kek::AgeKek;
use crate::profile::{valid_env_value, valid_name, Kind, ProfileId};

const MAGIC: &[u8; 4] = b"HEV1";
const VERSION: u8 = 1;
const MAX_ENTRIES: usize = 64;
const MAX_FILE_LEN: usize = 256 * 1024;
const BUNDLE_AAD_PREFIX: &[u8] = b"hev-bundle-v1\0";

/// One secret inside a profile bundle. Bytes are wiped when this value drops.
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub bytes: Zeroizing<Vec<u8>>,
}

pub struct Opened {
    pub profile: String,
    pub entries: Vec<Entry>,
    pub dek: Zeroizing<[u8; 32]>,
}

/// Seal `entries` under a fresh DEK wrapped by `kek`. The profile name is in
/// the header so operators can see it, and in the AEAD associated data so a
/// relabeled header does not decrypt.
pub fn seal(profile: ProfileId, entries: Vec<Entry>, kek: &AgeKek) -> Result<Vec<u8>, Error> {
    check_entries(profile, &entries)?;
    seal_bytes(profile.as_str(), entries, kek)
}

/// Seal a profile name and entries into an `HEV1` bundle. Allowlist checks are
/// the caller's job (catalog on sync, `ProfileId` policy on legacy CLI).
pub fn seal_bytes(profile: &str, entries: Vec<Entry>, kek: &AgeKek) -> Result<Vec<u8>, Error> {
    validate_profile_name(profile)?;
    check_entry_shapes(&entries)?;
    let dek_bytes = random_array::<32>()?;
    let dek = Zeroizing::new(dek_bytes);
    let payload = encode_payload(profile, &entries)?;
    let nonce = random_array::<24>()?;
    let ciphertext = aead_encrypt(&dek, &nonce, &payload, &bundle_aad(profile))?;
    let wrapped = kek.wrap_dek(&dek)?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    let name = profile.as_bytes();
    out.push(u8::try_from(name.len()).expect("profile name fits in u8"));
    out.extend_from_slice(name);
    push_u32(
        &mut out,
        u32::try_from(wrapped.len()).expect("age wrap fits in u32"),
    );
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&nonce);
    push_u32(
        &mut out,
        u32::try_from(ciphertext.len()).expect("ciphertext fits"),
    );
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(bundle: &[u8], kek: &AgeKek) -> Result<Opened, Error> {
    let opened = open_bytes(bundle, kek)?;
    let profile = ProfileId::parse(&opened.profile)?;
    check_entries(profile, &opened.entries)?;
    Ok(opened)
}

/// Decrypt an `HEV1` bundle without catalog or legacy policy checks.
pub fn open_bytes(bundle: &[u8], kek: &AgeKek) -> Result<Opened, Error> {
    let header = split_header(bundle)?;
    let dek = kek.unwrap_dek(header.wrapped_dek)?;
    let profile = header.profile.clone();
    let payload = aead_decrypt(
        &dek,
        &header.nonce,
        header.ciphertext,
        &bundle_aad(&profile),
    )?;
    let entries = decode_payload(&profile, &payload)?;
    Ok(Opened {
        profile,
        entries,
        dek,
    })
}

fn check_entries(profile: ProfileId, entries: &[Entry]) -> Result<(), Error> {
    check_entry_shapes(entries)?;
    let policy = profile.policy();
    for entry in entries {
        if !policy.allows(entry.kind, &entry.name) {
            return Err(Error::EntryNotAllowed {
                name: entry.name.clone(),
                kind: entry.kind.as_str(),
                profile: profile.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

fn check_entry_shapes(entries: &[Entry]) -> Result<(), Error> {
    if entries.is_empty() {
        return Err(Error::EmptyBundle);
    }
    if entries.len() > MAX_ENTRIES {
        return Err(Error::RuntimeBody);
    }
    let mut seen = Vec::with_capacity(entries.len());
    for entry in entries {
        if !valid_name(&entry.name) {
            return Err(Error::InvalidName(entry.name.clone()));
        }
        if entry.kind == Kind::Env && !valid_env_value(&entry.bytes) {
            return Err(Error::InvalidEnvValue(entry.name.clone()));
        }
        if entry.kind == Kind::File && (entry.bytes.is_empty() || entry.bytes.len() > MAX_FILE_LEN)
        {
            return Err(Error::InvalidEnvValue(entry.name.clone()));
        }
        if seen.contains(&entry.name.as_str()) {
            return Err(Error::DuplicateEntry(entry.name.clone()));
        }
        seen.push(entry.name.as_str());
    }
    Ok(())
}

fn validate_profile_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() > crate::slot::NAME_MAX_BYTES {
        return Err(Error::InvalidName(name.to_owned()));
    }
    Ok(())
}

fn bundle_aad(profile: &str) -> Vec<u8> {
    let mut aad = Vec::from(BUNDLE_AAD_PREFIX);
    aad.extend_from_slice(profile.as_bytes());
    aad
}

fn encode_payload(profile: &str, entries: &[Entry]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let name = profile.as_bytes();
    out.push(u8::try_from(name.len()).expect("profile name fits"));
    out.extend_from_slice(name);
    push_u16(
        &mut out,
        u16::try_from(entries.len()).expect("entry count fits"),
    );
    for entry in entries {
        out.push(entry.kind.tag());
        let entry_name = entry.name.as_bytes();
        out.push(u8::try_from(entry_name.len()).expect("name checked"));
        out.extend_from_slice(entry_name);
        push_u32(
            &mut out,
            u32::try_from(entry.bytes.len()).expect("len checked"),
        );
        out.extend_from_slice(&entry.bytes);
    }
    Ok(out)
}

fn decode_payload(expected: &str, payload: &[u8]) -> Result<Vec<Entry>, Error> {
    let mut cursor = Cursor::new(payload);
    let name_len = cursor.u8()? as usize;
    let name = std::str::from_utf8(cursor.bytes(name_len)?).map_err(|_| Error::BundleAuth)?;
    validate_profile_name(name).map_err(|_| Error::BundleAuth)?;
    if name != expected {
        return Err(Error::ProfileMismatch {
            found: name.to_owned(),
            expected: expected.to_owned(),
        });
    }
    let count = cursor.u16()? as usize;
    if count == 0 || count > MAX_ENTRIES {
        return Err(Error::BundleAuth);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = Kind::from_tag(cursor.u8()?).ok_or(Error::BundleAuth)?;
        let name_len = cursor.u8()? as usize;
        let name = std::str::from_utf8(cursor.bytes(name_len)?)
            .map_err(|_| Error::BundleAuth)?
            .to_owned();
        let value_len = cursor.u32()? as usize;
        if value_len > MAX_FILE_LEN {
            return Err(Error::BundleAuth);
        }
        let bytes = Zeroizing::new(cursor.bytes(value_len)?.to_vec());
        entries.push(Entry { name, kind, bytes });
    }
    if !cursor.is_empty() {
        return Err(Error::BundleAuth);
    }
    check_entry_shapes(&entries)?;
    Ok(entries)
}

struct Header<'a> {
    profile: String,
    wrapped_dek: &'a [u8],
    nonce: [u8; 24],
    ciphertext: &'a [u8],
}

fn split_header(bundle: &[u8]) -> Result<Header<'_>, Error> {
    let mut cursor = Cursor::new(bundle);
    let magic = cursor.bytes(4)?;
    if magic != MAGIC {
        return Err(Error::BundleAuth);
    }
    if cursor.u8()? != VERSION {
        return Err(Error::BundleAuth);
    }
    let name_len = cursor.u8()? as usize;
    let name = std::str::from_utf8(cursor.bytes(name_len)?).map_err(|_| Error::BundleAuth)?;
    validate_profile_name(name).map_err(|_| Error::BundleAuth)?;
    let profile = name.to_owned();
    let wrapped_len = cursor.u32()? as usize;
    let wrapped = cursor.bytes(wrapped_len)?;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(cursor.bytes(24)?);
    let ct_len = cursor.u32()? as usize;
    let ciphertext = cursor.bytes(ct_len)?;
    if !cursor.is_empty() {
        return Err(Error::BundleAuth);
    }
    Ok(Header {
        profile,
        wrapped_dek: wrapped,
        nonce,
        ciphertext,
    })
}

pub(crate) fn seal_key(dek: &[u8; 32], aad: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce = random_array::<24>()?;
    let ct = aead_encrypt(dek, &nonce, key, aad)?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) fn open_key(dek: &[u8; 32], aad: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
    if wrapped.len() < 24 {
        return Err(Error::RuntimeBody);
    }
    let (nonce, ct) = wrapped.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| Error::RuntimeBody)?;
    let mut plain = aead_decrypt(dek, &nonce, ct, aad)?;
    let out = plain.to_vec();
    plain.zeroize();
    Ok(out)
}

fn aead_encrypt(
    dek: &[u8; 32],
    nonce: &[u8; 24],
    plain: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| Error::BundleAuth)?;
    let nonce = xnonce(nonce)?;
    cipher
        .encrypt(&nonce, Payload { msg: plain, aad })
        .map_err(|_| Error::BundleAuth)
}

fn aead_decrypt(
    dek: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| Error::BundleAuth)?;
    let nonce = xnonce(nonce)?;
    let mut plain = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::BundleAuth)?;
    let secret = Zeroizing::new(plain.clone());
    plain.zeroize();
    Ok(secret)
}

fn xnonce(bytes: &[u8; 24]) -> Result<XNonce, Error> {
    bytes.as_slice().try_into().map_err(|_| Error::BundleAuth)
}

pub(crate) fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| Error::Random)?;
    Ok(buf)
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn is_empty(&self) -> bool {
        self.at >= self.buf.len()
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(len).ok_or(Error::BundleAuth)?;
        if end > self.buf.len() {
            return Err(Error::BundleAuth);
        }
        let slice = &self.buf[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> AgeKek {
        AgeKek::generate()
    }

    fn env(name: &str, value: &str) -> Entry {
        Entry {
            name: name.to_owned(),
            kind: Kind::Env,
            bytes: Zeroizing::new(value.as_bytes().to_vec()),
        }
    }

    #[test]
    fn round_trip_keeps_allowlisted_entries() {
        let kek = kek();
        let bundle = seal(
            ProfileId::DenariusWeb,
            vec![
                env("DB_PASS", "db-secret"),
                env("IDP_CLIENT_SECRET", "idp-secret"),
            ],
            &kek,
        )
        .unwrap();
        let opened = open(&bundle, &kek).unwrap();
        assert_eq!(opened.profile, "denarius-web");
        assert_eq!(opened.entries.len(), 2);
        assert_eq!(opened.entries[0].name, "DB_PASS");
        assert_eq!(&opened.entries[0].bytes[..], b"db-secret");
    }

    #[test]
    fn web_profile_rejects_the_stripe_secret_key() {
        let kek = kek();
        let err = seal(
            ProfileId::DenariusWeb,
            vec![env("STRIPE_SECRET_KEY", "sk_live_nope")],
            &kek,
        )
        .unwrap_err();
        assert!(matches!(err, Error::EntryNotAllowed { .. }));
    }

    #[test]
    fn tampered_ciphertext_does_not_open() {
        let kek = kek();
        let mut bundle = seal(
            ProfileId::DenariusConnect,
            vec![env("STRIPE_SECRET_KEY", "sk_connect")],
            &kek,
        )
        .unwrap();
        let last = bundle.len() - 1;
        bundle[last] ^= 0xff;
        assert!(matches!(open(&bundle, &kek), Err(Error::BundleAuth)));
    }

    #[test]
    fn relabeled_header_does_not_decrypt() {
        let kek = kek();
        let bundle = seal(
            ProfileId::DenariusWeb,
            vec![env("DB_PASS", "db-secret")],
            &kek,
        )
        .unwrap();
        let mut relabeled = bundle.clone();
        let web = b"denarius-web";
        let worker = b"denarius-wor";
        let at = relabeled
            .windows(web.len())
            .position(|window| window == web)
            .unwrap();
        relabeled[at..at + worker.len()].copy_from_slice(worker);
        assert!(open(&relabeled, &kek).is_err());
    }

    #[test]
    fn seal_rejects_empty_duplicate_and_invalid_entries() {
        let kek = kek();
        assert!(matches!(seal(ProfileId::DenariusWeb, vec![], &kek), Err(Error::EmptyBundle)));
        assert!(matches!(
            seal(
                ProfileId::DenariusWeb,
                vec![env("bad name", "x")],
                &kek
            ),
            Err(Error::InvalidName(_))
        ));
        assert!(matches!(
            seal(
                ProfileId::DenariusWeb,
                vec![env("DB_PASS", "x"), env("DB_PASS", "y")],
                &kek
            ),
            Err(Error::DuplicateEntry(_))
        ));
        assert!(matches!(
            seal(
                ProfileId::DenariusWeb,
                vec![env("DB_PASS", "bad\nline")],
                &kek
            ),
            Err(Error::InvalidEnvValue(_))
        ));
    }

    #[test]
    fn open_rejects_truncated_bundle() {
        let kek = kek();
        let bundle = seal(
            ProfileId::DenariusWeb,
            vec![env("DB_PASS", "x")],
            &kek,
        )
        .unwrap();
        assert!(matches!(open(&bundle[..8], &kek), Err(Error::BundleAuth)));
    }

    #[test]
    fn open_key_rejects_short_wrapped_blob() {
        let dek = random_array::<32>().unwrap();
        assert!(matches!(
            open_key(&dek, b"aad", &[0u8; 8]),
            Err(Error::RuntimeBody)
        ));
        assert!(matches!(
            open_key(&dek, b"aad", &[0u8; 23]),
            Err(Error::RuntimeBody)
        ));
    }

    #[test]
    fn seal_bytes_rejects_bad_profile_names() {
        let kek = kek();
        assert!(matches!(
            seal_bytes("", vec![env("DB_PASS", "x")], &kek),
            Err(Error::InvalidName(_))
        ));
        let long = "a".repeat(crate::slot::NAME_MAX_BYTES + 1);
        assert!(matches!(
            seal_bytes(&long, vec![env("DB_PASS", "x")], &kek),
            Err(Error::InvalidName(_))
        ));
    }

    #[test]
    fn seal_bytes_rejects_bad_file_shapes() {
        let kek = kek();
        let empty_file = Entry {
            name: "key.pem".into(),
            kind: Kind::File,
            bytes: Zeroizing::new(vec![]),
        };
        assert!(matches!(
            seal_bytes("denarius-web", vec![empty_file], &kek),
            Err(Error::InvalidEnvValue(_))
        ));
        let huge = Entry {
            name: "key.pem".into(),
            kind: Kind::File,
            bytes: Zeroizing::new(vec![b'x'; MAX_FILE_LEN + 1]),
        };
        assert!(matches!(
            seal_bytes("denarius-web", vec![huge], &kek),
            Err(Error::InvalidEnvValue(_))
        ));
    }

    #[test]
    fn seal_bytes_rejects_too_many_entries() {
        let kek = kek();
        let entries: Vec<Entry> = (0..MAX_ENTRIES + 1)
            .map(|i| env(&format!("E{i:02}"), "v"))
            .collect();
        assert!(matches!(
            seal_bytes("denarius-web", entries, &kek),
            Err(Error::RuntimeBody)
        ));
    }

    #[test]
    fn decode_payload_rejects_bad_counts_and_trailing_bytes() {
        let profile = "denarius-web";
        let mut header = vec![profile.len() as u8];
        header.extend_from_slice(profile.as_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            decode_payload(profile, &header),
            Err(Error::BundleAuth)
        ));

        let mut too_many = vec![profile.len() as u8];
        too_many.extend_from_slice(profile.as_bytes());
        too_many.extend_from_slice(&(MAX_ENTRIES as u16 + 1).to_le_bytes());
        assert!(matches!(
            decode_payload(profile, &too_many),
            Err(Error::BundleAuth)
        ));

        let mut trailing = vec![profile.len() as u8];
        trailing.extend_from_slice(profile.as_bytes());
        trailing.extend_from_slice(&1u16.to_le_bytes());
        trailing.push(Kind::Env.tag());
        trailing.push(7);
        trailing.extend_from_slice(b"DB_PASS");
        trailing.extend_from_slice(&1u32.to_le_bytes());
        trailing.push(b'x');
        trailing.push(0xff);
        assert!(matches!(
            decode_payload(profile, &trailing),
            Err(Error::BundleAuth)
        ));
    }

    #[test]
    fn decode_payload_rejects_wrong_embedded_profile_name() {
        let expected = "denarius-web";
        let mut payload = vec![15u8];
        payload.extend_from_slice(b"denarius-worker");
        payload.extend_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            decode_payload(expected, &payload),
            Err(Error::ProfileMismatch { .. })
        ));
    }
}
