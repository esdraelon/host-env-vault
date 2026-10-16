use std::fs;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;

use crate::application::render::{render_from_vault, RenderOptions};
use crate::application::serve::{fetch_runtime_entry, handle_serve_connection, ServeOptions};
use crate::application::sync::{sync_from_local, SyncOptions, SYNC_SLOT_INDEX};
use crate::core::slot::SlotTable;
use crate::legacy::profile::Kind;
use crate::legacy::serve::{bind_runtime_socket, exchange, OP_FETCH_ENV, ST_OK};
use crate::ports::{SsmPort, LOCAL_CATALOG_FILE};
use crate::vault::kek::AgeKek;

const APP_CATALOG: &str = r#"{
  "profiles": [{
    "name": "app-web",
    "inject": ["DB_PASS", "STRIPE_WEBHOOK_SECRET"],
    "runtime": ["APP_KEY"],
    "inject_files": [],
    "runtime_files": ["teller.key"],
    "socket": true,
    "require_uid": 0
  }]
}"#;

fn temp_root(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/tmp/hev-m11-{label}-{}-{id}",
        std::process::id()
    ))
}

fn seed_local_secrets(root: &PathBuf) {
    fs::create_dir_all(root.join("files")).unwrap();
    fs::write(root.join(LOCAL_CATALOG_FILE), APP_CATALOG).unwrap();
    fs::write(
        root.join("app-web.env"),
        "DB_PASS=db-local\nSTRIPE_WEBHOOK_SECRET=whsec-local\nAPP_KEY=app-key-local\n",
    )
    .unwrap();
    fs::write(root.join("files/teller.key"), "teller-local-bytes").unwrap();
}

#[test]
fn local_sync_render_and_serve_without_aws() {
    let root = temp_root("pipeline");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let secrets_dir = root.join("dev-secrets");
    seed_local_secrets(&secrets_dir);
    let state_dir = root.join("state");
    let dest = root.join("dest");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: root.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: String::new(),
        secrets_prefix: String::new(),
        s3_prefix: None,
    };

    struct PanicSsm;
    impl SsmPort for PanicSsm {
        fn get_parameter(&self, name: &str) -> Result<String, crate::ports::SsmError> {
            panic!("local sync must not call SSM, got {name}");
        }
    }
    let _ssm_guard = PanicSsm;

    sync_from_local(&secrets_dir, None, &kek, &mut table, &options).unwrap();
    assert!(state_dir.join("catalog.json").is_file());
    assert!(state_dir.join("app-web.hev").is_file());
    assert_eq!(
        table.slot_ref(SYNC_SLOT_INDEX).unwrap().secret_count(),
        0,
        "sync must release its slot"
    );

    let render_options =
        RenderOptions::new(root.join("kek.age"), state_dir.clone(), dest.clone(), None);
    render_from_vault(&kek, &mut table, "app-web", &render_options).unwrap();
    let env = fs::read_to_string(dest.join("secrets.env")).unwrap();
    assert!(env.contains("DB_PASS=db-local\n"));
    assert!(env.contains("STRIPE_WEBHOOK_SECRET=whsec-local\n"));
    assert!(!env.contains("APP_KEY"));

    let uid = unsafe { libc::getuid() };
    let catalog_text = APP_CATALOG.replace("\"require_uid\": 0", &format!("\"require_uid\": {uid}"));
    fs::write(state_dir.join("catalog.json"), catalog_text.as_bytes()).unwrap();
    let catalog = crate::catalog::load_catalog_snapshot(&state_dir).unwrap();

    let runtime = fetch_runtime_entry(
        &kek,
        &mut table,
        &catalog,
        "app-web",
        &state_dir,
        Kind::Env,
        "APP_KEY",
    )
    .unwrap();
    assert_eq!(&runtime[..], b"app-key-local");

    let runtime_dir = root.join("run");
    fs::create_dir_all(&runtime_dir).unwrap();
    let listener = bind_runtime_socket(&runtime_dir, "app-web").unwrap();
    let path = runtime_dir.join("sockets").join("app-web.sock");
    let serve_options = ServeOptions::new(
        root.join("kek.age"),
        state_dir.clone(),
        runtime_dir,
        "app-web",
    );
    let mut serve_table = SlotTable::new();
    let serve_kek = kek;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        handle_serve_connection(
            &mut stream,
            &serve_kek,
            &mut serve_table,
            &catalog,
            &serve_options,
        )
        .unwrap();
    });

    let mut client = UnixStream::connect(&path).unwrap();
    let response = exchange(&mut client, OP_FETCH_ENV, b"APP_KEY").unwrap();
    assert_eq!(response.status, ST_OK);
    assert_eq!(&response.body[..], b"app-key-local");
    drop(client);
    server.join().unwrap();

    let _ = fs::remove_dir_all(&root);
}
