//! Public-process proof for stopped-home, exact-digest encrypted backup activation.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_application::OwnershipContext;
use mealy_domain::{ChannelBindingId, PrincipalId};
use mealy_infrastructure::{
    FileArtifactBlobStore, FileProviderSecretStore, LATEST_SCHEMA_VERSION, SqliteStore,
    create_backup, create_pre_migration_backup, inspect_existing_schema_version,
};
use mealy_protocol::{BackupActivationResponse, MigrationBackupActivationResponse};
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
    process::{Command, Stdio},
    time::SystemTime,
};

#[test]
fn encrypted_backup_activation_is_approved_locked_atomic_and_state_preserving() {
    let root = tempfile::tempdir().expect("temporary restore root");
    let home = root.path().join("home");
    fs::create_dir(&home).expect("home");
    fs::write(
        home.join("config.json"),
        br#"{"formatVersion":1,"drainDeadlineMs":10000,"artifactGcMinimumAgeHours":24,"forensicBackupOnOpenFailure":true}"#,
    )
    .expect("configuration");
    let principal_id = PrincipalId::new();
    let channel_binding_id = ChannelBindingId::new();
    let mut store = SqliteStore::open(home.join("mealy.sqlite3"), 1).expect("store");
    store
        .register_local_identity(OwnershipContext::new(principal_id, channel_binding_id), 1)
        .expect("local identity");
    fs::write(
        home.join("identity.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "formatVersion": 1,
            "bearerToken": URL_SAFE_NO_PAD.encode([0x42_u8; 32]),
            "principalId": principal_id,
            "channelBindingId": channel_binding_id,
        }))
        .expect("identity JSON"),
    )
    .expect("identity file");
    FileProviderSecretStore::new(home.join("provider-secrets"))
        .expect("provider broker")
        .put("openai-primary", "restore-process-provider-secret")
        .expect("provider secret");
    let artifacts =
        FileArtifactBlobStore::new(home.join("artifacts"), 1024).expect("artifact store");
    let passphrase = "restore process correct horse battery staple";
    let backup = create_backup(
        &home,
        &store,
        &artifacts,
        "encrypted-process",
        Some(passphrase),
        SystemTime::now(),
    )
    .expect("encrypted backup");
    drop(store);
    fs::write(home.join("newer-only.txt"), b"must move to preserved home").expect("newer sentinel");

    let without_approval = restore_command(&home, &backup.manifest_digest, passphrase, false);
    assert!(!without_approval.status.success());
    assert!(home.join("newer-only.txt").is_file());

    let lock = lock_home(&home);
    let while_running = restore_command(&home, &backup.manifest_digest, passphrase, true);
    assert!(!while_running.status.success());
    assert!(home.join("newer-only.txt").is_file());
    drop(lock);

    let activated = restore_command(&home, &backup.manifest_digest, passphrase, true);
    assert!(
        activated.status.success(),
        "restore activation failed: {}",
        String::from_utf8_lossy(&activated.stderr)
    );
    assert!(
        !activated
            .stdout
            .windows(passphrase.len())
            .any(|value| value == passphrase.as_bytes())
    );
    let response: BackupActivationResponse =
        serde_json::from_slice(&activated.stdout).expect("activation response");
    assert_eq!(response.home, home.display().to_string());
    assert_eq!(response.manifest_digest, backup.manifest_digest);
    let preserved = Path::new(&response.preserved_home);
    assert!(preserved.join("newer-only.txt").is_file());
    assert!(!home.join("newer-only.txt").exists());
    assert!(home.join("mealy.sqlite3").is_file());
    assert!(home.join("restore-activation.json").is_file());
    assert_eq!(
        fs::read(home.join("provider-secrets/openai-primary.key"))
            .expect("restored provider secret"),
        b"restore-process-provider-secret"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn migration_home_activation_accepts_only_an_approved_exact_snapshot_and_inherited_lock() {
    let latest_schema_version =
        u64::try_from(LATEST_SCHEMA_VERSION).expect("latest schema version is nonnegative");
    let root = tempfile::tempdir().expect("temporary migration-activation root");
    let home = root.path().join("home");
    fs::create_dir(&home).expect("home");
    fs::write(
        home.join("config.json"),
        br#"{"formatVersion":1,"drainDeadlineMs":10000,"providerFallbacks":[],"artifactGcMinimumAgeHours":24,"forensicBackupOnOpenFailure":true}"#,
    )
    .expect("configuration");
    let principal_id = PrincipalId::new();
    let channel_binding_id = ChannelBindingId::new();
    let database = home.join("mealy.sqlite3");
    let mut store = SqliteStore::open(&database, 1).expect("store");
    store
        .register_local_identity(OwnershipContext::new(principal_id, channel_binding_id), 1)
        .expect("local identity");
    drop(store);
    fs::write(
        home.join("identity.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "formatVersion": 1,
            "bearerToken": URL_SAFE_NO_PAD.encode([0x52_u8; 32]),
            "principalId": principal_id,
            "channelBindingId": channel_binding_id,
        }))
        .expect("identity JSON"),
    )
    .expect("identity file");
    FileProviderSecretStore::new(home.join("provider-secrets"))
        .expect("provider broker")
        .put("openai-primary", "migration-process-provider-secret")
        .expect("provider secret");

    downgrade_to_schema_13(&database);
    let migration = create_pre_migration_backup(
        &home,
        &database,
        13,
        latest_schema_version,
        SystemTime::now(),
    )
    .expect("migration backup");
    let migration_name = migration
        .path
        .file_name()
        .and_then(|value| value.to_str())
        .expect("migration name");
    drop(SqliteStore::open(&database, 2).expect("migrate active database"));
    fs::write(home.join("newer-only.txt"), b"preserve migrated home").expect("newer sentinel");

    let denied = migration_command(
        &home,
        migration_name,
        &migration.manifest_digest,
        false,
        None,
    );
    assert!(!denied.status.success());
    assert_eq!(
        inspect_existing_schema_version(&database).expect("denied schema"),
        Some(latest_schema_version)
    );

    let inherited_lock = lock_home(&home);
    let activated = migration_command(
        &home,
        migration_name,
        &migration.manifest_digest,
        true,
        Some(&inherited_lock),
    );
    assert!(
        activated.status.success(),
        "migration activation failed: {}",
        String::from_utf8_lossy(&activated.stderr)
    );
    let response: MigrationBackupActivationResponse =
        serde_json::from_slice(&activated.stdout).expect("activation response");
    assert_eq!(response.manifest_digest, migration.manifest_digest);
    assert_eq!(response.from_schema_version, 13);
    assert_eq!(response.to_schema_version, latest_schema_version);
    assert_eq!(
        inspect_existing_schema_version(&database).expect("activated schema"),
        Some(13)
    );
    assert!(
        Path::new(&response.preserved_home)
            .join("newer-only.txt")
            .is_file()
    );
    assert_eq!(
        fs::read(home.join("provider-secrets/openai-primary.key"))
            .expect("restored provider secret"),
        b"migration-process-provider-secret"
    );
    assert!(home.join("migration-rollback-activation.json").is_file());
}

fn downgrade_to_schema_13(database: &Path) {
    let connection = rusqlite::Connection::open(database).expect("downgrade fixture");
    connection
        .execute_batch(
            "DROP TRIGGER session_input_reference_immutable_delete;
             DROP TRIGGER session_input_reference_immutable_update;
             DROP TRIGGER session_input_reference_insert_guard;
             DROP TRIGGER session_input_blob_immutable_update;
             DROP TRIGGER session_input_artifact_immutable_update;
             DROP TRIGGER session_inbox_media_immutable_delete;
             DROP TRIGGER session_inbox_media_immutable_update;
             DROP TRIGGER session_inbox_media_create_reference;
             DROP TRIGGER session_inbox_media_insert_guard;
             DROP INDEX session_inbox_media_owner_idx;
             DROP TABLE session_inbox_media;
             DROP TRIGGER delegation_group_child_insert;
             DROP TRIGGER delegation_group_identity_immutable;
             DROP TRIGGER delegation_group_contract_immutable;
             DROP TRIGGER delegation_group_settlement;
             DROP TRIGGER delegation_group_no_reopen;
             DROP TRIGGER delegation_group_no_delete;
             DROP INDEX delegation_group_ordinal_idx;
             DROP INDEX delegation_group_child_key_idx;
             DROP INDEX delegation_group_parent_state_idx;
             ALTER TABLE delegation DROP COLUMN group_id;
             ALTER TABLE delegation DROP COLUMN group_ordinal;
             ALTER TABLE delegation DROP COLUMN child_key;
             DROP TABLE delegation_group;
             DROP INDEX run_terminal_completion_idx;
             DROP TRIGGER model_attempt_manifest_token_total_insert;
             DROP TABLE context_manifest_bundle_memory_citation;
             DROP TABLE context_manifest_bundle_compaction;
             DROP TABLE context_manifest_bundle_artifact;
             DROP TABLE context_manifest_bundle;
             DROP TABLE slack_envelope_receipt;
             DROP TABLE slack_channel_health;
             DROP TABLE slack_channel_binding;
             DROP TABLE discord_message_receipt;
             DROP TABLE discord_channel_health;
             DROP TABLE discord_channel_cursor;
             DROP TABLE discord_channel_binding;
             DROP TRIGGER turn_provider_selection_immutable;
             DROP TRIGGER turn_provider_selection_insert;
             DROP TRIGGER session_inbox_provider_selection_immutable;
             DROP TRIGGER session_inbox_provider_selection_insert;
             DROP TRIGGER session_provider_selection_update_binding;
             DROP TRIGGER session_provider_selection_insert_binding;
             DROP TABLE session_provider_selection;
             ALTER TABLE session_inbox DROP COLUMN provider_selection_source;
             ALTER TABLE session_inbox DROP COLUMN selected_provider_id;
             ALTER TABLE session_inbox DROP COLUMN selected_model_id;
             ALTER TABLE turn DROP COLUMN selected_provider_id;
             ALTER TABLE turn DROP COLUMN selected_model_id;
             DELETE FROM schema_version WHERE version IN (14, 15, 16, 17, 18, 19, 20, 21);
             PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .expect("simulate v13");
}

fn restore_command(
    home: &Path,
    manifest_digest: &str,
    passphrase: &str,
    approve: bool,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command
        .arg("--home")
        .arg(home)
        .arg("restore-activate")
        .arg("encrypted-process")
        .arg("--expected-manifest-digest")
        .arg(manifest_digest)
        .arg("--passphrase-env")
        .arg("MEALY_TEST_RESTORE_PASSPHRASE")
        .env("MEALY_TEST_RESTORE_PASSPHRASE", passphrase);
    if approve {
        command.arg("--approve");
    }
    command.output().expect("run mealyctl restore activation")
}

fn migration_command(
    home: &Path,
    migration_name: &str,
    manifest_digest: &str,
    approve: bool,
    inherited_lock: Option<&File>,
) -> std::process::Output {
    let latest_schema_version =
        u64::try_from(LATEST_SCHEMA_VERSION).expect("latest schema version is nonnegative");
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command
        .arg("--home")
        .arg(home)
        .arg("migration-home-activate")
        .arg(migration_name)
        .arg("--expected-manifest-digest")
        .arg(manifest_digest)
        .arg("--expected-from-schema-version")
        .arg("13")
        .arg("--expected-to-schema-version")
        .arg(latest_schema_version.to_string());
    if approve {
        command.arg("--approve");
    }
    if let Some(lock) = inherited_lock {
        command
            .arg("--inherited-home-lock-stdin")
            .stdin(Stdio::from(lock.try_clone().expect("clone inherited lock")));
    }
    command.output().expect("run migration-home activation")
}

fn lock_home(home: &Path) -> File {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(home.join("mealyd.lock"))
        .expect("home lock file");
    file.try_lock().expect("hold daemon home lock");
    file
}
