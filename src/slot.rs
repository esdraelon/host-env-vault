//! **Slot table** — fixed-capacity profile memory using an **Object Pool** of
//! four worker slots and a **Generation counter** that invalidates late writes
//! after wipe or lease expiry.

use std::time::{Duration, Instant};

/// Worker threads and pooled slots share this count.
pub const SLOT_COUNT: usize = 4;
pub const SECRETS_PER_PROFILE: usize = 32;
pub const SECRET_MAX_BYTES: usize = 4096;
pub const DOCUMENTS_PER_PROFILE: usize = 20;
pub const DOCUMENT_MAX_BYTES: usize = 100 * 1024;
pub const NAME_MAX_BYTES: usize = 64;
pub const LEASE_MS: u64 = 2000;

const ZERO_NAME: [u8; NAME_MAX_BYTES] = [0; NAME_MAX_BYTES];
const ZERO_SECRET: [u8; SECRET_MAX_BYTES] = [0; SECRET_MAX_BYTES];
const ZERO_DOCUMENT: [u8; DOCUMENT_MAX_BYTES] = [0; DOCUMENT_MAX_BYTES];

/// Lease token returned from a successful acquire. Holds the slot index and the
/// generation observed at acquire time; writes must match the live generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotLease {
    pub slot_index: usize,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    InvalidIndex,
    Busy,
    OversizeName,
    OversizeSecret,
    OversizeDocument,
    StaleGeneration,
    TooManySecrets,
    TooManyDocuments,
}

#[derive(Debug, Clone, Copy)]
struct SecretEntry {
    name: [u8; NAME_MAX_BYTES],
    name_len: u8,
    data: [u8; SECRET_MAX_BYTES],
    data_len: u16,
}

#[derive(Debug, Clone, Copy)]
struct DocumentEntry {
    name: [u8; NAME_MAX_BYTES],
    name_len: u8,
    data: [u8; DOCUMENT_MAX_BYTES],
    data_len: u32,
}

impl Default for SecretEntry {
    fn default() -> Self {
        Self {
            name: ZERO_NAME,
            name_len: 0,
            data: ZERO_SECRET,
            data_len: 0,
        }
    }
}

impl Default for DocumentEntry {
    fn default() -> Self {
        Self {
            name: ZERO_NAME,
            name_len: 0,
            data: ZERO_DOCUMENT,
            data_len: 0,
        }
    }
}

/// One fixed profile buffer. Payloads never allocate on the heap.
#[derive(Debug)]
pub struct Slot {
    profile_name: [u8; NAME_MAX_BYTES],
    profile_name_len: u8,
    secrets: Box<[SecretEntry; SECRETS_PER_PROFILE]>,
    secret_count: u8,
    documents: Box<[DocumentEntry; DOCUMENTS_PER_PROFILE]>,
    document_count: u8,
    generation: u64,
    in_use: bool,
    lease_expires_at: Option<Instant>,
}

fn boxed_secrets() -> Box<[SecretEntry; SECRETS_PER_PROFILE]> {
    let mut entries = Vec::with_capacity(SECRETS_PER_PROFILE);
    for _ in 0..SECRETS_PER_PROFILE {
        entries.push(SecretEntry::default());
    }
    entries
        .into_boxed_slice()
        .try_into()
        .ok()
        .expect("secret count")
}

fn boxed_documents() -> Box<[DocumentEntry; DOCUMENTS_PER_PROFILE]> {
    let mut entries = Vec::with_capacity(DOCUMENTS_PER_PROFILE);
    for _ in 0..DOCUMENTS_PER_PROFILE {
        entries.push(DocumentEntry::default());
    }
    entries
        .into_boxed_slice()
        .try_into()
        .ok()
        .expect("document count")
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            profile_name: ZERO_NAME,
            profile_name_len: 0,
            secrets: boxed_secrets(),
            secret_count: 0,
            documents: boxed_documents(),
            document_count: 0,
            generation: 0,
            in_use: false,
            lease_expires_at: None,
        }
    }
}

impl Slot {
    fn wipe(&mut self) {
        let next = self.generation.wrapping_add(1);
        tracing::info!(
            target: "host_env_vault::slot",
            slot_generation = next,
            "slot wipe"
        );
        self.profile_name = ZERO_NAME;
        self.profile_name_len = 0;
        self.secrets = boxed_secrets();
        self.secret_count = 0;
        self.documents = boxed_documents();
        self.document_count = 0;
        self.in_use = false;
        self.lease_expires_at = None;
        self.generation = next;
    }

    fn lease_expired(&self, now: Instant) -> bool {
        self.lease_expires_at
            .is_some_and(|deadline| now >= deadline)
    }

    fn check_generation(&self, lease: SlotLease) -> Result<(), SlotError> {
        if lease.generation != self.generation {
            tracing::info!(
                target: "host_env_vault::slot",
                expected = lease.generation,
                actual = self.generation,
                "stale generation reject"
            );
            return Err(SlotError::StaleGeneration);
        }
        Ok(())
    }

    fn reject_oversize_name(len: usize) -> Result<(), SlotError> {
        tracing::info!(
            target: "host_env_vault::slot",
            len,
            max = NAME_MAX_BYTES,
            "reject oversize name"
        );
        Err(SlotError::OversizeName)
    }

    fn reject_oversize_secret(len: usize) -> Result<(), SlotError> {
        tracing::info!(
            target: "host_env_vault::slot",
            len,
            max = SECRET_MAX_BYTES,
            "reject oversize secret"
        );
        Err(SlotError::OversizeSecret)
    }

    fn reject_oversize_document(len: usize) -> Result<(), SlotError> {
        tracing::info!(
            target: "host_env_vault::slot",
            len,
            max = DOCUMENT_MAX_BYTES,
            "reject oversize document"
        );
        Err(SlotError::OversizeDocument)
    }

    fn copy_name(dst: &mut [u8; NAME_MAX_BYTES], name: &[u8]) -> Result<u8, SlotError> {
        if name.is_empty() || name.len() > NAME_MAX_BYTES {
            Self::reject_oversize_name(name.len())?;
            unreachable!();
        }
        dst.fill(0);
        dst[..name.len()].copy_from_slice(name);
        Ok(name.len() as u8)
    }

    fn zero_secret_tail(entry: &mut SecretEntry) {
        let start = entry.data_len as usize;
        if start < SECRET_MAX_BYTES {
            entry.data[start..].fill(0);
        }
    }

    fn zero_document_tail(entry: &mut DocumentEntry) {
        let start = entry.data_len as usize;
        if start < DOCUMENT_MAX_BYTES {
            entry.data[start..].fill(0);
        }
    }

    pub fn set_profile_name(&mut self, lease: SlotLease, name: &[u8]) -> Result<(), SlotError> {
        self.check_generation(lease)?;
        self.profile_name_len = Self::copy_name(&mut self.profile_name, name)?;
        Ok(())
    }

    pub fn put_secret(
        &mut self,
        lease: SlotLease,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), SlotError> {
        self.check_generation(lease)?;
        if value.is_empty() || value.len() > SECRET_MAX_BYTES {
            return Self::reject_oversize_secret(value.len());
        }
        let idx = self.secret_count as usize;
        if idx >= SECRETS_PER_PROFILE {
            return Err(SlotError::TooManySecrets);
        }
        let entry = &mut self.secrets[idx];
        entry.name_len = Self::copy_name(&mut entry.name, name)?;
        entry.data.fill(0);
        entry.data[..value.len()].copy_from_slice(value);
        entry.data_len = value.len() as u16;
        Self::zero_secret_tail(entry);
        self.secret_count += 1;
        Ok(())
    }

    pub fn put_document(
        &mut self,
        lease: SlotLease,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), SlotError> {
        self.check_generation(lease)?;
        if value.is_empty() || value.len() > DOCUMENT_MAX_BYTES {
            return Self::reject_oversize_document(value.len());
        }
        let idx = self.document_count as usize;
        if idx >= DOCUMENTS_PER_PROFILE {
            return Err(SlotError::TooManyDocuments);
        }
        let entry = &mut self.documents[idx];
        entry.name_len = Self::copy_name(&mut entry.name, name)?;
        entry.data.fill(0);
        entry.data[..value.len()].copy_from_slice(value);
        entry.data_len = value.len() as u32;
        Self::zero_document_tail(entry);
        self.document_count += 1;
        Ok(())
    }

    pub fn write_if_generation(
        &mut self,
        lease: SlotLease,
        secret_index: usize,
        value: &[u8],
    ) -> Result<(), SlotError> {
        self.check_generation(lease)?;
        if value.len() > SECRET_MAX_BYTES {
            return Self::reject_oversize_secret(value.len());
        }
        if secret_index >= self.secret_count as usize {
            return Err(SlotError::StaleGeneration);
        }
        let entry = &mut self.secrets[secret_index];
        entry.data.fill(0);
        if !value.is_empty() {
            entry.data[..value.len()].copy_from_slice(value);
        }
        entry.data_len = value.len() as u16;
        Self::zero_secret_tail(entry);
        Ok(())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn secret_bytes(&self, index: usize) -> Option<&[u8]> {
        let entry = self.secrets.get(index)?;
        if index >= self.secret_count as usize {
            return None;
        }
        let len = entry.data_len as usize;
        Some(&entry.data[..len])
    }

    pub fn secret_data_array(&self, index: usize) -> Option<&[u8; SECRET_MAX_BYTES]> {
        if index >= self.secret_count as usize {
            return None;
        }
        Some(&self.secrets[index].data)
    }

    pub fn in_use(&self) -> bool {
        self.in_use
    }

    pub fn verify_lease(&self, lease: SlotLease) -> Result<(), SlotError> {
        self.check_generation(lease)
    }

    pub fn profile_name_bytes(&self) -> &[u8] {
        &self.profile_name[..self.profile_name_len as usize]
    }

    pub fn secret_count(&self) -> u8 {
        self.secret_count
    }

    pub fn document_count(&self) -> u8 {
        self.document_count
    }

    pub fn secret_name_bytes(&self, index: usize) -> Option<&[u8]> {
        if index >= self.secret_count as usize {
            return None;
        }
        let entry = &self.secrets[index];
        Some(&entry.name[..entry.name_len as usize])
    }

    pub fn document_name_bytes(&self, index: usize) -> Option<&[u8]> {
        if index >= self.document_count as usize {
            return None;
        }
        let entry = &self.documents[index];
        Some(&entry.name[..entry.name_len as usize])
    }

    pub fn document_bytes(&self, index: usize) -> Option<&[u8]> {
        if index >= self.document_count as usize {
            return None;
        }
        let entry = &self.documents[index];
        let len = entry.data_len as usize;
        Some(&entry.data[..len])
    }

    #[cfg(test)]
    pub fn all_fixed_storage_zero(&self) -> bool {
        self.profile_name.iter().all(|b| *b == 0)
            && self.secrets.iter().all(|e| {
                e.name.iter().all(|b| *b == 0) && e.data.iter().all(|b| *b == 0)
            })
            && self.documents.iter().all(|e| {
                e.name.iter().all(|b| *b == 0) && e.data.iter().all(|b| *b == 0)
            })
    }
}

/// **Object Pool** of four fixed slots shared by worker threads.
#[derive(Debug)]
pub struct SlotTable {
    slots: Box<[Slot; SLOT_COUNT]>,
}

impl SlotTable {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(SLOT_COUNT);
        for _ in 0..SLOT_COUNT {
            slots.push(Slot::default());
        }
        let slots = slots
            .into_boxed_slice()
            .try_into()
            .ok()
            .expect("slot count");
        Self { slots }
    }

    fn slot_mut(&mut self, index: usize) -> Result<&mut Slot, SlotError> {
        self.slots
            .get_mut(index)
            .ok_or(SlotError::InvalidIndex)
    }

    fn slot(&self, index: usize) -> Result<&Slot, SlotError> {
        self.slots.get(index).ok_or(SlotError::InvalidIndex)
    }

    /// Synchronous acquire: returns `Busy` when the slot is already held.
    pub fn try_acquire(
        &mut self,
        index: usize,
        now: Instant,
    ) -> Result<SlotLease, SlotError> {
        let slot = self.slot_mut(index)?;
        if slot.in_use {
            tracing::debug!(
                target: "host_env_vault::slot",
                slot_index = index,
                "acquire busy"
            );
            return Err(SlotError::Busy);
        }
        slot.in_use = true;
        slot.lease_expires_at = Some(now + Duration::from_millis(LEASE_MS));
        Ok(SlotLease {
            slot_index: index,
            generation: slot.generation,
        })
    }

    /// Blocks until the slot is free or the timeout elapses.
    pub fn acquire_sync(
        &mut self,
        index: usize,
        timeout: Duration,
    ) -> Result<SlotLease, SlotError> {
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            match self.try_acquire(index, now) {
                Ok(lease) => return Ok(lease),
                Err(SlotError::Busy) if now < deadline => {
                    std::thread::yield_now();
                }
                Err(SlotError::Busy) => return Err(SlotError::Busy),
                Err(err) => return Err(err),
            }
        }
    }

    pub fn release(&mut self, lease: SlotLease) -> Result<(), SlotError> {
        let slot = self.slot_mut(lease.slot_index)?;
        if slot.generation != lease.generation {
            tracing::info!(
                target: "host_env_vault::slot",
                expected = lease.generation,
                actual = slot.generation,
                "stale generation reject"
            );
            return Err(SlotError::StaleGeneration);
        }
        slot.in_use = false;
        slot.lease_expires_at = None;
        slot.wipe();
        Ok(())
    }

    pub fn sweep_expired(&mut self, now: Instant) {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.lease_expired(now) {
                tracing::info!(
                    target: "host_env_vault::slot",
                    slot_index = index,
                    "sweep expired lease"
                );
                slot.in_use = false;
                slot.lease_expires_at = None;
                slot.wipe();
            }
        }
    }

    pub fn slot_ref(&self, index: usize) -> Result<&Slot, SlotError> {
        self.slot(index)
    }

    pub fn slot_ref_mut(&mut self, index: usize) -> Result<&mut Slot, SlotError> {
        self.slot_mut(index)
    }

    pub fn wipe_slot(&mut self, index: usize) {
        if let Ok(slot) = self.slot_mut(index) {
            slot.wipe();
        }
    }
}

#[cfg(test)]
mod behavior_tests {
    use super::*;

    #[test]
    fn fixed_caps_match_plan() {
        assert_eq!(SECRETS_PER_PROFILE, 32);
        assert_eq!(SECRET_MAX_BYTES, 4096);
        assert_eq!(DOCUMENTS_PER_PROFILE, 20);
        assert_eq!(DOCUMENT_MAX_BYTES, 100 * 1024);
        assert_eq!(NAME_MAX_BYTES, 64);
        assert_eq!(SLOT_COUNT, 4);
        assert_eq!(LEASE_MS, 2000);
    }

    pub(super) fn lease_at(index: usize) -> (SlotTable, SlotLease, Instant) {
        let mut table = SlotTable::new();
        let now = Instant::now();
        let lease = table.try_acquire(index, now).expect("acquire");
        (table, lease, now)
    }

    #[test]
    fn oversize_name_and_values_are_rejected_before_copy() {
        let (mut table, lease, _) = lease_at(0);
        let slot = table.slot_ref_mut(0).unwrap();
        let long_name = vec![b'a'; NAME_MAX_BYTES + 1];
        assert_eq!(
            slot.set_profile_name(lease, &long_name),
            Err(SlotError::OversizeName)
        );

        let ok_name = b"DB_PASS";
        slot.set_profile_name(lease, ok_name).unwrap();
        let big = vec![b'x'; SECRET_MAX_BYTES + 1];
        assert_eq!(
            slot.put_secret(lease, ok_name, &big),
            Err(SlotError::OversizeSecret)
        );
        assert_eq!(
            slot.put_secret(lease, ok_name, &[]),
            Err(SlotError::OversizeSecret)
        );

        let doc_big = vec![b'y'; DOCUMENT_MAX_BYTES + 1];
        assert_eq!(
            slot.put_document(lease, b"site.conf", &doc_big),
            Err(SlotError::OversizeDocument)
        );
    }

    #[test]
    fn wipe_zeros_whole_slot_including_unused_tails() {
        let (mut table, lease, _) = lease_at(0);
        {
            let slot = table.slot_ref_mut(0).unwrap();
            slot.set_profile_name(lease, b"denarius-web").unwrap();
            slot.put_secret(lease, b"DB_PASS", b"secret-value")
                .unwrap();
            let arr = slot.secret_data_array(0).unwrap();
            assert!(arr[512..].iter().all(|b| *b == 0));
        }
        table.release(lease).unwrap();
        let slot = table.slot_ref(0).unwrap();
        assert_eq!(slot.generation(), 1);
        assert!(!slot.in_use());
        assert!(slot.secret_bytes(0).is_none());
        assert!(slot.profile_name_bytes().is_empty());
        assert!(slot.all_fixed_storage_zero());
    }

    #[test]
    fn stale_generation_cannot_write_back() {
        let (mut table, lease, _) = lease_at(1);
        {
            let slot = table.slot_ref_mut(1).unwrap();
            slot.put_secret(lease, b"K", b"v").unwrap();
        }
        table.wipe_slot(1);
        let slot = table.slot_ref_mut(1).unwrap();
        assert_eq!(
            slot.put_secret(lease, b"K2", b"v2"),
            Err(SlotError::StaleGeneration)
        );
        assert_eq!(
            slot.write_if_generation(lease, 0, b"late"),
            Err(SlotError::StaleGeneration)
        );
    }

    #[test]
    fn try_acquire_busy_and_release_wipes() {
        let mut table = SlotTable::new();
        let now = Instant::now();
        let lease = table.try_acquire(2, now).unwrap();
        assert!(table.slot_ref(2).unwrap().in_use());
        assert_eq!(table.try_acquire(2, now), Err(SlotError::Busy));
        table.release(lease).unwrap();
        assert!(!table.slot_ref(2).unwrap().in_use());
    }

    #[test]
    fn sweep_expired_wipes_even_when_in_use() {
        let mut table = SlotTable::new();
        let start = Instant::now();
        let lease = table.try_acquire(3, start).unwrap();
        {
            let slot = table.slot_ref_mut(3).unwrap();
            slot.put_secret(lease, b"X", b"data").unwrap();
        }
        let after_lease = start + Duration::from_millis(LEASE_MS);
        table.sweep_expired(after_lease);
        let slot = table.slot_ref(3).unwrap();
        assert!(!slot.in_use());
        assert!(slot.secret_bytes(0).is_none());
        assert_eq!(slot.generation(), 1);
    }

    #[test]
    fn secret_tail_stays_zero_after_put() {
        let (mut table, lease, _) = lease_at(0);
        let slot = table.slot_ref_mut(0).unwrap();
        slot.put_secret(lease, b"N", &[b'z'; 10]).unwrap();
        let arr = slot.secret_data_array(0).unwrap();
        assert_eq!(&arr[..10], &[b'z'; 10]);
        assert!(arr[10..].iter().all(|b| *b == 0));
    }

    #[test]
    fn invalid_slot_index_errors() {
        let mut table = SlotTable::new();
        assert_eq!(
            table.try_acquire(SLOT_COUNT, Instant::now()),
            Err(SlotError::InvalidIndex)
        );
    }

    #[test]
    fn acquire_sync_succeeds_when_slot_is_free() {
        let mut table = SlotTable::new();
        let lease = table
            .acquire_sync(0, Duration::from_millis(50))
            .expect("sync acquire");
        assert!(table.slot_ref(0).unwrap().in_use());
        table.release(lease).unwrap();
    }

    #[test]
    fn release_rejects_stale_generation() {
        let (mut table, lease, _) = lease_at(0);
        table.wipe_slot(0);
        assert_eq!(table.release(lease), Err(SlotError::StaleGeneration));
    }

    #[test]
    fn write_if_generation_updates_secret_and_rejects_oversize() {
        let (mut table, lease, _) = lease_at(0);
        let slot = table.slot_ref_mut(0).unwrap();
        slot.put_secret(lease, b"K", b"old").unwrap();
        slot.write_if_generation(lease, 0, b"new").unwrap();
        assert_eq!(slot.secret_bytes(0), Some(&b"new"[..]));
        let big = vec![b'z'; SECRET_MAX_BYTES + 1];
        assert_eq!(
            slot.write_if_generation(lease, 0, &big),
            Err(SlotError::OversizeSecret)
        );
    }

    #[test]
    fn acquire_sync_times_out_when_busy() {
        let mut table = SlotTable::new();
        let _busy = table.try_acquire(0, Instant::now()).unwrap();
        assert_eq!(
            table.acquire_sync(0, Duration::from_millis(1)),
            Err(SlotError::Busy)
        );
    }

    #[test]
    fn max_length_names_and_payloads_are_accepted() {
        let (mut table, lease, _) = lease_at(0);
        let slot = table.slot_ref_mut(0).unwrap();
        let name = vec![b'n'; NAME_MAX_BYTES];
        let secret = vec![b's'; SECRET_MAX_BYTES];
        let doc = vec![b'd'; DOCUMENT_MAX_BYTES];
        slot.set_profile_name(lease, &name).unwrap();
        slot.put_secret(lease, &name, &secret).unwrap();
        slot.put_document(lease, b"doc", &doc).unwrap();
        assert_eq!(slot.profile_name_bytes(), &name[..]);
        assert_eq!(slot.secret_bytes(0).unwrap().len(), SECRET_MAX_BYTES);
    }

    #[test]
    fn generation_starts_at_zero_and_profile_name_round_trips() {
        let table = SlotTable::new();
        assert_eq!(table.slot_ref(0).unwrap().generation(), 0);
        let (mut table, lease, _) = lease_at(1);
        let slot = table.slot_ref_mut(1).unwrap();
        slot.set_profile_name(lease, b"denarius-web").unwrap();
        assert_eq!(slot.profile_name_bytes(), b"denarius-web");
    }

    #[test]
    fn sweep_does_not_wipe_before_lease_elapses() {
        let mut table = SlotTable::new();
        let start = Instant::now();
        let lease = table.try_acquire(2, start).unwrap();
        let slot = table.slot_ref_mut(2).unwrap();
        slot.put_secret(lease, b"K", b"v").unwrap();
        table.sweep_expired(start + Duration::from_millis(LEASE_MS - 1));
        let slot = table.slot_ref(2).unwrap();
        assert!(slot.in_use());
        assert_eq!(slot.secret_bytes(0), Some(&b"v"[..]));
    }

    #[test]
    fn acquire_sync_unblocks_after_release_on_another_thread() {
        use std::sync::{Arc, Mutex};
        let table = Arc::new(Mutex::new(SlotTable::new()));
        let bg = Arc::clone(&table);
        let handle = std::thread::spawn(move || {
            let mut t = bg.lock().unwrap();
            let lease = t.try_acquire(0, Instant::now()).unwrap();
            std::thread::sleep(Duration::from_millis(80));
            t.release(lease).unwrap();
        });
        std::thread::sleep(Duration::from_millis(10));
        let started = Instant::now();
        let lease = table
            .lock()
            .unwrap()
            .acquire_sync(0, Duration::from_secs(2))
            .expect("wait for release");
        assert!(started.elapsed() >= Duration::from_millis(40));
        table.lock().unwrap().release(lease).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn write_if_generation_rejects_out_of_range_index() {
        let (mut table, lease, _) = lease_at(0);
        let slot = table.slot_ref_mut(0).unwrap();
        slot.put_secret(lease, b"K", b"v").unwrap();
        assert_eq!(
            slot.write_if_generation(lease, 1, b"x"),
            Err(SlotError::StaleGeneration)
        );
    }

    #[test]
    fn too_many_secrets_and_documents() {
        let (mut table, lease, _) = lease_at(0);
        let slot = table.slot_ref_mut(0).unwrap();
        for i in 0..SECRETS_PER_PROFILE {
            let name = format!("S{i}");
            slot.put_secret(lease, name.as_bytes(), b"x").unwrap();
        }
        assert_eq!(
            slot.put_secret(lease, b"overflow", b"x"),
            Err(SlotError::TooManySecrets)
        );
        for i in 0..DOCUMENTS_PER_PROFILE {
            let name = format!("D{i}");
            slot.put_document(lease, name.as_bytes(), b"x").unwrap();
        }
        assert_eq!(
            slot.put_document(lease, b"overflow", b"x"),
            Err(SlotError::TooManyDocuments)
        );
    }
}

#[cfg(test)]
mod log_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    fn capture_logs<F: FnOnce()>(test: F) -> Vec<String> {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .without_time()
            .with_target(true)
            .with_writer(move || LogWriter(sink.clone()))
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
        let _guard = tracing_subscriber::registry().with(layer).set_default();
        test();
        let captured = lines.lock().unwrap().clone();
        captured
    }

    struct LogWriter(Arc<Mutex<Vec<String>>>);

    impl std::io::Write for LogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let s = String::from_utf8_lossy(buf).to_string();
            self.0.lock().unwrap().push(s);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn joined(lines: &[String]) -> String {
        lines.concat()
    }

    #[test]
    fn log_reject_oversize_secret() {
        let lines = capture_logs(|| {
            let (mut table, lease, _) = super::behavior_tests::lease_at(0);
            let slot = table.slot_ref_mut(0).unwrap();
            let big = vec![b'x'; SECRET_MAX_BYTES + 1];
            let _ = slot.put_secret(lease, b"N", &big);
        });
        let text = joined(&lines);
        assert!(
            text.contains("reject oversize secret"),
            "logs: {text}"
        );
    }

    #[test]
    fn log_reject_oversize_name() {
        let lines = capture_logs(|| {
            let (mut table, lease, _) = super::behavior_tests::lease_at(0);
            let slot = table.slot_ref_mut(0).unwrap();
            let long = vec![b'n'; NAME_MAX_BYTES + 1];
            let _ = slot.set_profile_name(lease, &long);
        });
        assert!(joined(&lines).contains("reject oversize name"));
    }

    #[test]
    fn log_wipe_on_release() {
        let lines = capture_logs(|| {
            let (mut table, lease, _) = super::behavior_tests::lease_at(0);
            table.release(lease).unwrap();
        });
        assert!(joined(&lines).contains("slot wipe"));
    }

    #[test]
    fn log_stale_generation_reject() {
        let lines = capture_logs(|| {
            let (mut table, lease, _) = super::behavior_tests::lease_at(0);
            table.wipe_slot(0);
            let slot = table.slot_ref_mut(0).unwrap();
            let _ = slot.put_secret(lease, b"K", b"v");
        });
        assert!(joined(&lines).contains("stale generation reject"));
    }

    #[test]
    fn log_reject_oversize_document() {
        let lines = capture_logs(|| {
            let (mut table, lease, _) = super::behavior_tests::lease_at(0);
            let slot = table.slot_ref_mut(0).unwrap();
            let big = vec![b'd'; DOCUMENT_MAX_BYTES + 1];
            let _ = slot.put_document(lease, b"doc", &big);
        });
        assert!(joined(&lines).contains("reject oversize document"));
    }

    #[test]
    fn log_sweep_expired_lease() {
        let lines = capture_logs(|| {
            let mut table = SlotTable::new();
            let start = Instant::now();
            let _lease = table.try_acquire(0, start).unwrap();
            table.sweep_expired(start + Duration::from_millis(LEASE_MS));
        });
        let text = joined(&lines);
        assert!(text.contains("sweep expired lease"), "{text}");
        assert!(text.contains("slot wipe"));
    }
}
