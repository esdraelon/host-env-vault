use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::catalog::{write_catalog_snapshot, DEFAULT_CATALOG_PARAMETER};
use crate::error::Error;
use crate::kek::AgeKek;
use crate::port::{MemorySsm, SsmPort};
use crate::profile::Kind;
use crate::render_cmd::{render_from_vault, RenderOptions, RENDER_SLOT_INDEX};
use crate::slot::SlotTable;
use crate::sync::{sync_catalog_from_text, sync_from_ssm, SyncOptions, SYNC_SLOT_INDEX};

const WORKER_CATALOG: &str = r#"{
  "profiles": [{
    "name": "denarius-worker",
    "inject": ["DB_PASS", "STRIPE_WEBHOOK_SECRET"],
    "runtime": ["APP_KEY", "STRIPE_SECRET_KEY"],
    "inject_files": [],
    "runtime_files": ["teller.key"]
  }]
}"#;

fn temp_root(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-render-int-{label}-{}-{id}",
        std::process::id()
    ))
}

fn mode_of(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn seed_worker_ssm(ssm: &MemorySsm) {
    ssm.put(DEFAULT_CATALOG_PARAMETER, WORKER_CATALOG);
    ssm.put("/amtgard/denarius-worker/DB_PASS", "db");
    ssm.put("/amtgard/denarius-worker/STRIPE_WEBHOOK_SECRET", "whsec");
    ssm.put("/amtgard/denarius-worker/APP_KEY", "app-key");
    ssm.put("/amtgard/denarius-worker/STRIPE_SECRET_KEY", "sk");
    ssm.put("/amtgard/denarius-worker/teller.key", "teller-bytes");
}

#[test]
fn render_after_sync_writes_inject_only_with_file_modes_and_no_ssm() {
    let root = temp_root("inject-modes");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let state_dir = root.join("state");
    let dest = root.join("dest");
    let ssm = MemorySsm::new();
    seed_worker_ssm(&ssm);
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let sync_options = SyncOptions {
        identity_path: root.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
    };
    sync_from_ssm(&ssm, &kek, &mut table, &sync_options).unwrap();
    assert!(state_dir.join("catalog.json").is_file());

    struct PanicSsm;
    impl SsmPort for PanicSsm {
        fn get_parameter(&self, name: &str) -> Result<String, crate::port::SsmError> {
            panic!("render must not call SSM, got {name}");
        }
    }
    let _panic_guard = PanicSsm;

    let render_options = RenderOptions::new(
        root.join("kek.age"),
        state_dir.clone(),
        dest.clone(),
        None,
    );
    render_from_vault(&kek, &mut table, "denarius-worker", &render_options).unwrap();

    assert_eq!(mode_of(&dest), 0o700);
    assert_eq!(mode_of(&dest.join("secrets.env")), 0o400);
    assert!(!dest.join("files").exists());
    let env = fs::read_to_string(dest.join("secrets.env")).unwrap();
    assert!(env.contains("DB_PASS=db\n"));
    assert!(env.contains("STRIPE_WEBHOOK_SECRET=whsec\n"));
    assert!(!env.contains("APP_KEY"));
    assert!(!env.contains("STRIPE_SECRET_KEY"));
    assert!(!table.slot_ref(RENDER_SLOT_INDEX).unwrap().in_use());
    assert!(table.slot_ref(SYNC_SLOT_INDEX).unwrap().profile_name_bytes().is_empty());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn render_refuses_dirty_destination() {
    let root = temp_root("dirty-dest");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let state_dir = root.join("state");
    let dest = root.join("dest");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("leftover"), b"x").unwrap();

    let ssm = MemorySsm::new();
    seed_worker_ssm(&ssm);
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    sync_catalog_from_text(WORKER_CATALOG, &ssm, &kek, &mut table, &state_dir).unwrap();

    let options = RenderOptions::new(
        root.join("kek.age"),
        state_dir,
        dest,
        None,
    );
    assert!(matches!(
        render_from_vault(&kek, &mut table, "denarius-worker", &options),
        Err(Error::DestNotEmpty(_))
    ));
    let _ = fs::remove_dir_all(&root);
}

fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn render_gid_override_applies_group_readable_modes() {
    if !running_as_root() {
        return;
    }
    let root = temp_root("gid");
    let _ = fs::remove_dir_all(&root);
    let state_dir = root.join("state");
    let dest = root.join("dest");
    let ssm = MemorySsm::new();
    ssm.put(
        DEFAULT_CATALOG_PARAMETER,
        r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[]}]}"#,
    );
    ssm.put("/amtgard/denarius-web/DB_PASS", "secret");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    sync_from_ssm(
        &ssm,
        &kek,
        &mut table,
        &SyncOptions {
            identity_path: root.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        },
    )
    .unwrap();

    render_from_vault(
        &kek,
        &mut table,
        "denarius-web",
        &RenderOptions::new(root.join("kek.age"), state_dir, dest.clone(), Some(33)),
    )
    .unwrap();
    assert_eq!(mode_of(&dest), 0o550);
    assert_eq!(mode_of(&dest.join("secrets.env")), 0o440);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn render_uses_catalog_gid_when_cli_omits_override() {
    if !running_as_root() {
        return;
    }
    let root = temp_root("catalog-gid");
    let _ = fs::remove_dir_all(&root);
    let state_dir = root.join("state");
    let dest = root.join("dest");
    let catalog = r#"{"profiles":[{"name":"g","inject":["X"],"runtime":[],"gid":42}]}"#;
    write_catalog_snapshot(&state_dir, catalog).unwrap();
    let kek = AgeKek::generate();
    let bundle = crate::bundle::seal_bytes(
        "g",
        vec![crate::bundle::Entry {
            name: "X".into(),
            kind: Kind::Env,
            bytes: zeroize::Zeroizing::new(b"v".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    fs::write(crate::sync::bundle_path(&state_dir, "g"), bundle).unwrap();

    let mut table = SlotTable::new();
    render_from_vault(
        &kek,
        &mut table,
        "g",
        &RenderOptions::new(root.join("unused"), state_dir, dest.clone(), None),
    )
    .unwrap();
    assert_eq!(mode_of(&dest.join("secrets.env")), 0o440);
    let _ = fs::remove_dir_all(&root);
}
