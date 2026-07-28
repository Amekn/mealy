//! Process-boundary proof for signed registry trust and monotonic snapshot administration.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use mealy_application::{
    REGISTRY_ROOT_PAYLOAD_TYPE, REGISTRY_SNAPSHOT_CONTRACT_VERSION, REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
    RegistryPublicKey, RegistryPublisher, RegistrySignature, RegistrySignatureAlgorithm,
    RegistrySignedEnvelope, RegistrySnapshot, RegistryTrustRoot, sha256_digest,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    fs::{self, File},
    path::Path,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const REGISTRY_ID: &str = "dev.mealy.registry";
const FIXTURE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROOT_CONTEXT: &str = "MEALY-REGISTRY-ROOT-V1";
const SNAPSHOT_CONTEXT: &str = "MEALY-REGISTRY-SNAPSHOT-V1";

#[test]
#[allow(clippy::too_many_lines)]
fn registry_cli_is_approval_gated_monotonic_stopped_and_restart_durable() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    let metadata = tempfile::tempdir().expect("temporary registry metadata");
    let old_key = SigningKey::from_bytes(&[17; 32]);
    let new_key = SigningKey::from_bytes(&[19; 32]);
    let publisher_key = SigningKey::from_bytes(&[23; 32]);
    let now_ms = epoch_ms();
    let root = RegistryTrustRoot {
        registry_id: REGISTRY_ID.to_owned(),
        root_version: 7,
        keys: vec![public_key(&old_key)],
        threshold: 1,
        expires_at_ms: now_ms + 3_600_000,
    };
    let root_path = metadata.path().join("root.json");
    fs::write(
        &root_path,
        serde_json::to_vec(&root).expect("encode trust root"),
    )
    .expect("write trust root");

    let inspected = registry_command(
        home.path(),
        &["root-inspect", "--root", path_text(&root_path)],
    );
    assert_success(&inspected, "root inspection");
    let response = decode(&inspected);
    assert_eq!(response["operation"], "root_verified");
    assert_eq!(response["root"]["registryId"], REGISTRY_ID);
    assert_eq!(response["root"]["rootVersion"], 7);
    assert_eq!(response["root"]["threshold"], 1);
    assert_eq!(response["networkAccess"], false);
    assert_eq!(response["packageAuthority"], false);
    assert!(!home.path().join("mealy.sqlite3").exists());

    #[cfg(unix)]
    {
        let redirected = metadata.path().join("redirected-root.json");
        std::os::unix::fs::symlink(&root_path, &redirected).expect("root symlink");
        let rejected = registry_command(
            home.path(),
            &["root-inspect", "--root", path_text(&redirected)],
        );
        assert!(!rejected.status.success(), "symlink root must fail closed");
        assert!(!home.path().join("mealy.sqlite3").exists());
    }

    let unapproved = registry_command(home.path(), &["root-add", "--root", path_text(&root_path)]);
    assert!(!unapproved.status.success());
    assert!(
        String::from_utf8_lossy(&unapproved.stderr).contains("requires --approve"),
        "unexpected error: {}",
        String::from_utf8_lossy(&unapproved.stderr)
    );
    assert!(!home.path().join("mealy.sqlite3").exists());

    let uninitialized = registry_command(
        home.path(),
        &["root-add", "--root", path_text(&root_path), "--approve"],
    );
    assert!(!uninitialized.status.success());
    assert!(
        String::from_utf8_lossy(&uninitialized.stderr).contains("no canonical database"),
        "unexpected uninitialized-home error: {}",
        String::from_utf8_lossy(&uninitialized.stderr)
    );
    assert!(!home.path().join("mealy.sqlite3").exists());
    drop(
        mealy_infrastructure::SqliteStore::open(home.path().join("mealy.sqlite3"), now_ms)
            .expect("initialized canonical database"),
    );

    let activated = registry_command(
        home.path(),
        &["root-add", "--root", path_text(&root_path), "--approve"],
    );
    assert_success(&activated, "root activation");
    assert_eq!(decode(&activated)["operation"], "root_active");
    assert_eq!(database_count(home.path(), "registry_trust_root"), 1);

    let status = registry_command(home.path(), &["status", REGISTRY_ID]);
    assert_success(&status, "initial registry status");
    let response = decode(&status);
    assert_eq!(response["root"]["rootVersion"], 7);
    assert!(response["snapshot"].is_null());
    let invalid_identity = registry_command(home.path(), &["status", "bad/registry"]);
    assert!(!invalid_identity.status.success());
    assert!(
        String::from_utf8_lossy(&invalid_identity.stderr)
            .contains("registry identity must be 1 through 255"),
        "unexpected invalid-identity error: {}",
        String::from_utf8_lossy(&invalid_identity.stderr)
    );
    let unapproved_refresh = registry_command(
        home.path(),
        &[
            "snapshot-refresh",
            REGISTRY_ID,
            "--mirror",
            "https://registry.example.test/mealy/v1/",
            "--expected-envelope-digest",
            FIXTURE_DIGEST,
        ],
    );
    assert!(!unapproved_refresh.status.success());
    assert!(
        String::from_utf8_lossy(&unapproved_refresh.stderr).contains("requires --approve"),
        "unexpected unapproved refresh error: {}",
        String::from_utf8_lossy(&unapproved_refresh.stderr)
    );
    let invalid_refresh_digest = registry_command(
        home.path(),
        &[
            "snapshot-refresh",
            REGISTRY_ID,
            "--mirror",
            "https://127.0.0.1/",
            "--expected-envelope-digest",
            "not-a-digest",
            "--approve",
        ],
    );
    assert!(!invalid_refresh_digest.status.success());
    assert!(
        String::from_utf8_lossy(&invalid_refresh_digest.stderr).contains("exact lowercase SHA-256"),
        "unexpected invalid refresh digest error: {}",
        String::from_utf8_lossy(&invalid_refresh_digest.stderr)
    );
    let insecure_mirror = registry_command(
        home.path(),
        &[
            "snapshot-fetch",
            REGISTRY_ID,
            "--mirror",
            "http://registry.example.test/mealy/v1/",
        ],
    );
    assert!(!insecure_mirror.status.success());
    assert!(
        String::from_utf8_lossy(&insecure_mirror.stderr)
            .contains("mirror configuration is invalid"),
        "unexpected insecure-mirror error: {}",
        String::from_utf8_lossy(&insecure_mirror.stderr)
    );
    let private_mirror = registry_command(
        home.path(),
        &[
            "snapshot-fetch",
            REGISTRY_ID,
            "--mirror",
            "https://127.0.0.1/",
        ],
    );
    assert!(!private_mirror.status.success());
    assert!(
        String::from_utf8_lossy(&private_mirror.stderr)
            .contains("mirror transport rejected the response"),
        "unexpected private-mirror error: {}",
        String::from_utf8_lossy(&private_mirror.stderr)
    );
    assert_eq!(database_count(home.path(), "registry_snapshot"), 0);

    let snapshot_one = snapshot(1, now_ms, &publisher_key);
    let snapshot_one_path = metadata.path().join("snapshot-1.json");
    write_envelope(
        &snapshot_one_path,
        REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
        SNAPSHOT_CONTEXT,
        &snapshot_one,
        &[&old_key],
    );
    let inspected = registry_command(
        home.path(),
        &[
            "snapshot-inspect",
            REGISTRY_ID,
            "--envelope",
            path_text(&snapshot_one_path),
        ],
    );
    assert_success(&inspected, "snapshot inspection");
    let response = decode(&inspected);
    assert_eq!(response["operation"], "snapshot_verified");
    assert_eq!(response["state"]["version"], 1);
    assert_eq!(response["publisherCount"], 1);
    assert_eq!(response["targetCount"], 0);
    assert_eq!(database_count(home.path(), "registry_snapshot"), 0);

    let unapproved = registry_command(
        home.path(),
        &[
            "snapshot-accept",
            REGISTRY_ID,
            "--envelope",
            path_text(&snapshot_one_path),
        ],
    );
    assert!(!unapproved.status.success());
    assert_eq!(database_count(home.path(), "registry_snapshot"), 0);

    let accepted = registry_command(
        home.path(),
        &[
            "snapshot-accept",
            REGISTRY_ID,
            "--envelope",
            path_text(&snapshot_one_path),
            "--approve",
        ],
    );
    assert_success(&accepted, "snapshot acceptance");
    assert_eq!(decode(&accepted)["operation"], "snapshot_active");
    assert_eq!(database_count(home.path(), "registry_snapshot"), 1);

    let replay = registry_command(
        home.path(),
        &[
            "snapshot-accept",
            REGISTRY_ID,
            "--envelope",
            path_text(&snapshot_one_path),
            "--approve",
        ],
    );
    assert_success(&replay, "exact snapshot replay");
    assert_eq!(database_count(home.path(), "registry_snapshot"), 1);

    let snapshot_two_path = metadata.path().join("snapshot-2.json");
    write_envelope(
        &snapshot_two_path,
        REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
        SNAPSHOT_CONTEXT,
        &snapshot(2, now_ms, &publisher_key),
        &[&old_key],
    );
    let second = registry_command(
        home.path(),
        &[
            "snapshot-accept",
            REGISTRY_ID,
            "--envelope",
            path_text(&snapshot_two_path),
            "--approve",
        ],
    );
    assert_success(&second, "second snapshot acceptance");
    assert_eq!(decode(&second)["state"]["version"], 2);
    let rollback = registry_command(
        home.path(),
        &[
            "snapshot-inspect",
            REGISTRY_ID,
            "--envelope",
            path_text(&snapshot_one_path),
        ],
    );
    assert!(!rollback.status.success(), "snapshot rollback must fail");
    assert!(
        String::from_utf8_lossy(&rollback.stderr).contains("rollback"),
        "unexpected rollback error: {}",
        String::from_utf8_lossy(&rollback.stderr)
    );

    let next_root = RegistryTrustRoot {
        registry_id: REGISTRY_ID.to_owned(),
        root_version: 8,
        keys: vec![public_key(&new_key)],
        threshold: 1,
        expires_at_ms: now_ms + 7_200_000,
    };
    let rotation_path = metadata.path().join("root-8-envelope.json");
    write_envelope(
        &rotation_path,
        REGISTRY_ROOT_PAYLOAD_TYPE,
        ROOT_CONTEXT,
        &next_root,
        &[&old_key, &new_key],
    );
    let unapproved = registry_command(
        home.path(),
        &[
            "root-rotate",
            REGISTRY_ID,
            "--envelope",
            path_text(&rotation_path),
        ],
    );
    assert!(!unapproved.status.success());
    assert_eq!(
        decode(&registry_command(home.path(), &["status", REGISTRY_ID]))["root"]["rootVersion"],
        7
    );
    let rotated = registry_command(
        home.path(),
        &[
            "root-rotate",
            REGISTRY_ID,
            "--envelope",
            path_text(&rotation_path),
            "--approve",
        ],
    );
    assert_success(&rotated, "trust-root rotation");
    assert_eq!(decode(&rotated)["root"]["rootVersion"], 8);
    let replay = registry_command(
        home.path(),
        &[
            "root-rotate",
            REGISTRY_ID,
            "--envelope",
            path_text(&rotation_path),
            "--approve",
        ],
    );
    assert_success(&replay, "exact trust-root rotation replay");
    assert_eq!(database_count(home.path(), "registry_trust_root"), 2);

    let snapshot_three_path = metadata.path().join("snapshot-3.json");
    write_envelope(
        &snapshot_three_path,
        REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
        SNAPSHOT_CONTEXT,
        &snapshot(3, now_ms, &publisher_key),
        &[&new_key],
    );
    let third = registry_command(
        home.path(),
        &[
            "snapshot-accept",
            REGISTRY_ID,
            "--envelope",
            path_text(&snapshot_three_path),
            "--approve",
        ],
    );
    assert_success(&third, "post-rotation snapshot");
    let status = registry_command(home.path(), &["status", REGISTRY_ID]);
    assert_success(&status, "reopened final registry status");
    let response = decode(&status);
    assert_eq!(response["root"]["rootVersion"], 8);
    assert_eq!(response["snapshot"]["rootVersion"], 8);
    assert_eq!(response["snapshot"]["version"], 3);

    let lock = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(home.path().join("mealyd.lock"))
        .expect("daemon lock");
    lock.try_lock().expect("hold daemon lock");
    let running = registry_command(home.path(), &["status", REGISTRY_ID]);
    assert!(
        !running.status.success(),
        "live-daemon home must be rejected"
    );
    assert!(
        String::from_utf8_lossy(&running.stderr).contains("requires mealyd to be stopped"),
        "unexpected running-daemon error: {}",
        String::from_utf8_lossy(&running.stderr)
    );
}

#[test]
fn registry_cli_refuses_unprotected_existing_schema_migration() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    let root = tempfile::NamedTempFile::new().expect("root file");
    let signing_key = SigningKey::from_bytes(&[29; 32]);
    fs::write(
        root.path(),
        serde_json::to_vec(&RegistryTrustRoot {
            registry_id: REGISTRY_ID.to_owned(),
            root_version: 1,
            keys: vec![public_key(&signing_key)],
            threshold: 1,
            expires_at_ms: epoch_ms() + 3_600_000,
        })
        .expect("valid root"),
    )
    .expect("write valid root");
    let database = home.path().join("mealy.sqlite3");
    let connection = rusqlite::Connection::open(&database).expect("old database");
    connection
        .execute_batch(
            "CREATE TABLE schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at_ms INTEGER NOT NULL
             );
             INSERT INTO schema_version(version, applied_at_ms) VALUES (23, 1);",
        )
        .expect("schema 23 marker");
    drop(connection);

    let output = registry_command(
        home.path(),
        &["root-add", "--root", path_text(root.path()), "--approve"],
    );
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("requires canonical schema 24")
            && error.contains("has schema 23")
            && error.contains("backup-protected migration"),
        "existing schema must be rejected before migration: {error}"
    );
    let connection = rusqlite::Connection::open(&database).expect("reopen old database");
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .expect("schema version"),
        23
    );
    assert!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'registry_trust_root'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .expect("registry table count")
            == 0
    );
}

fn snapshot(version: u64, generated_at_ms: i64, publisher_key: &SigningKey) -> RegistrySnapshot {
    RegistrySnapshot {
        contract_version: REGISTRY_SNAPSHOT_CONTRACT_VERSION.to_owned(),
        registry_id: REGISTRY_ID.to_owned(),
        version,
        generated_at_ms,
        expires_at_ms: generated_at_ms + 600_000,
        publishers: vec![RegistryPublisher {
            publisher_id: "dev.mealy".to_owned(),
            keys: vec![public_key(publisher_key)],
            threshold: 1,
        }],
        targets: Vec::new(),
    }
}

fn public_key(signing_key: &SigningKey) -> RegistryPublicKey {
    let bytes = signing_key.verifying_key().to_bytes();
    RegistryPublicKey {
        key_id: sha256_digest(&bytes),
        algorithm: RegistrySignatureAlgorithm::Ed25519,
        public_key_base64url: URL_SAFE_NO_PAD.encode(bytes),
    }
}

fn write_envelope<T: Serialize>(
    path: &Path,
    payload_type: &str,
    context: &str,
    payload: &T,
    keys: &[&SigningKey],
) {
    let payload = serde_json::to_vec(payload).expect("signed payload");
    let mut material = Vec::from(context.as_bytes());
    material.push(0);
    material.extend_from_slice(&payload);
    let mut signatures = keys
        .iter()
        .map(|key| RegistrySignature {
            key_id: sha256_digest(&key.verifying_key().to_bytes()),
            signature_base64url: URL_SAFE_NO_PAD.encode(key.sign(&material).to_bytes()),
        })
        .collect::<Vec<_>>();
    signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    let envelope = RegistrySignedEnvelope {
        payload_type: payload_type.to_owned(),
        payload_base64url: URL_SAFE_NO_PAD.encode(payload),
        signatures,
    };
    fs::write(
        path,
        serde_json::to_vec(&envelope).expect("signed envelope"),
    )
    .expect("write signed envelope");
}

fn registry_command(home: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .arg("registry")
        .args(arguments)
        .output()
        .expect("run mealyctl registry command")
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn decode(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("registry JSON response")
}

fn database_count(home: &Path, table: &str) -> i64 {
    assert!(
        matches!(table, "registry_trust_root" | "registry_snapshot"),
        "fixed test table"
    );
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("canonical database")
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("canonical row count")
}

fn epoch_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current epoch")
            .as_millis(),
    )
    .expect("millisecond range")
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 temporary path")
}
