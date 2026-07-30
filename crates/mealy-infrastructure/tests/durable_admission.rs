//! Cross-crate proof that acknowledged session input survives a real `SQLite` reopen.

use mealy_application::{
    AdmitInputCommand, ArtifactBlobStore, ArtifactEvidenceStore, InputAdmissionLimits,
    InputAdmissionOutcome, InputImageArtifactCommit, OwnershipContext, SessionStoreError,
    SessionUseCaseError, admit_input, admit_input_with_images, create_session,
};
use mealy_domain::{ArtifactId, ChannelBindingId, DeliveryMode, PrincipalId, SessionId};
use mealy_infrastructure::{FileArtifactBlobStore, SqliteStore};
use mealy_testkit::{TestClock, TestIdGenerator};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

#[cfg(target_os = "linux")]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
#[cfg(target_os = "linux")]
use mealy_infrastructure::LinuxBubblewrapMediaNormalizer;

const NOW_MS: i64 = 1_782_062_400_000;

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir()
                .join(format!("mealy-admission-{}.sqlite3", SessionId::new())),
        }
    }

    fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut path = self.path.as_os_str().to_owned();
        path.push(suffix);
        PathBuf::from(path)
    }

    fn artifact_root(&self) -> PathBuf {
        self.path.with_extension("artifacts")
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(self.sidecar(suffix));
        }
        let _ = fs::remove_dir_all(self.artifact_root());
    }
}

#[test]
fn acknowledged_input_survives_reopen_and_deduplicates() {
    let database = TemporaryDatabase::new();
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let command_content = "preserve this accepted input".to_owned();

    let (session_id, first_receipt) = {
        let mut store = SqliteStore::open(&database.path, NOW_MS).expect("open file store");
        let session_id =
            create_session(&mut store, &clock, &ids, ownership).expect("create durable session");
        let outcome = admit_input(
            &mut store,
            &clock,
            &ids,
            InputAdmissionLimits::default(),
            AdmitInputCommand {
                session_id,
                ownership,
                dedupe_key: "channel-event-42".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: command_content.clone(),
                provider_selection: mealy_application::ProviderSelectionPreference::InheritSession,
            },
        )
        .expect("acknowledge durably admitted input");
        assert!(matches!(outcome, InputAdmissionOutcome::Accepted(_)));
        (session_id, outcome.receipt().clone())
    };

    let mut reopened = SqliteStore::open(&database.path, NOW_MS + 1).expect("reopen store");
    let duplicate = admit_input(
        &mut reopened,
        &clock,
        &ids,
        InputAdmissionLimits::default(),
        AdmitInputCommand {
            session_id,
            ownership,
            dedupe_key: "channel-event-42".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: command_content,
            provider_selection: mealy_application::ProviderSelectionPreference::InheritSession,
        },
    )
    .expect("recover original admission receipt");

    assert!(duplicate.is_duplicate());
    assert_eq!(duplicate.receipt(), &first_receipt);
    assert_eq!(reopened.journal_count().expect("journal count"), 2);
    assert_eq!(reopened.outbox_count().expect("outbox count"), 1);

    let changed_retry = admit_input(
        &mut reopened,
        &clock,
        &ids,
        InputAdmissionLimits::default(),
        AdmitInputCommand {
            session_id,
            ownership,
            dedupe_key: "channel-event-42".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "changed after acknowledgement".to_owned(),
            provider_selection: mealy_application::ProviderSelectionPreference::InheritSession,
        },
    )
    .expect_err("idempotency key must remain bound to exact input");
    assert_eq!(
        changed_retry,
        SessionUseCaseError::Store(SessionStoreError::IdempotencyConflict)
    );
    assert_eq!(reopened.journal_count().expect("journal count"), 2);
    assert_eq!(reopened.outbox_count().expect("outbox count"), 1);
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn canonical_image_blob_is_committed_before_atomic_link_and_survives_reopen() {
    const ONE_PIXEL_PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

    let database = TemporaryDatabase::new();
    let artifact_store = FileArtifactBlobStore::new(database.artifact_root(), 2 * 1_024 * 1_024)
        .expect("open private artifact store");
    let worker = fs::canonicalize(env!("CARGO_BIN_EXE_mealy-media-worker"))
        .expect("media worker path is canonical");
    let normalizer = LinuxBubblewrapMediaNormalizer::load(Path::new("/usr/bin/bwrap"), &worker)
        .expect("load isolated media normalizer");
    let source = BASE64_STANDARD
        .decode(ONE_PIXEL_PNG)
        .expect("fixture base64 decodes");
    let canonical = normalizer
        .normalize("image/png", &source)
        .expect("normalize hostile source before persistence");
    let blob = artifact_store
        .commit(canonical.bytes())
        .expect("durably publish canonical image bytes first");
    assert_eq!(blob.digest, canonical.sha256_digest());

    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let image = InputImageArtifactCommit {
        artifact_id: ArtifactId::new(),
        blob: blob.clone(),
        committed_at: SystemTime::UNIX_EPOCH + Duration::from_millis(NOW_MS as u64),
        media_type: canonical.media_type().to_owned(),
        width: canonical.width(),
        height: canonical.height(),
    };
    let command = |session_id| AdmitInputCommand {
        session_id,
        ownership,
        dedupe_key: "canonical-image-42".to_owned(),
        delivery_mode: DeliveryMode::Queue,
        content: "describe this canonical image".to_owned(),
        provider_selection: mealy_application::ProviderSelectionPreference::InheritSession,
    };

    let (session_id, first_receipt) = {
        let mut store = SqliteStore::open(&database.path, NOW_MS).expect("open file store");
        let session_id =
            create_session(&mut store, &clock, &ids, ownership).expect("create durable session");
        let outcome = admit_input_with_images(
            &mut store,
            &clock,
            &ids,
            InputAdmissionLimits::default(),
            command(session_id),
            vec![image.clone()],
        )
        .expect("atomically link committed canonical image");
        assert_eq!(
            outcome.receipt().image_artifact_ids,
            vec![image.artifact_id]
        );
        (session_id, outcome.receipt().clone())
    };

    let mut reopened = SqliteStore::open(&database.path, NOW_MS + 1).expect("reopen store");
    let duplicate = admit_input_with_images(
        &mut reopened,
        &clock,
        &ids,
        InputAdmissionLimits::default(),
        command(session_id),
        vec![image.clone()],
    )
    .expect("recover exact image admission receipt");
    assert!(duplicate.is_duplicate());
    assert_eq!(duplicate.receipt(), &first_receipt);
    let descriptor = reopened
        .artifact_content_descriptor(ownership, image.artifact_id)
        .expect("load owner-authorized canonical descriptor");
    assert_eq!(descriptor.committed_blob(), &blob);
    assert_eq!(
        artifact_store
            .read(descriptor.committed_blob())
            .expect("verify durable canonical bytes"),
        canonical.bytes()
    );

    let orphan = artifact_store
        .commit(b"precommitted but unlinked image")
        .expect("publish orphan candidate before rejected metadata transaction");
    let rejected_image = InputImageArtifactCommit {
        artifact_id: ArtifactId::new(),
        blob: orphan.clone(),
        committed_at: SystemTime::UNIX_EPOCH + Duration::from_millis(NOW_MS as u64),
        media_type: "image/png".to_owned(),
        width: 1,
        height: 1,
    };
    assert!(
        admit_input_with_images(
            &mut reopened,
            &clock,
            &ids,
            InputAdmissionLimits::default(),
            command(SessionId::new()),
            vec![rejected_image],
        )
        .is_err()
    );
    let referenced = reopened
        .referenced_artifact_digests()
        .expect("load canonical blob references");
    assert!(referenced.contains(&blob.digest));
    assert!(!referenced.contains(&orphan.digest));
    let report = artifact_store
        .garbage_collect(&referenced, Duration::from_hours(1), SystemTime::now())
        .expect("age-gated collection preserves fresh crash-recovery orphan");
    assert_eq!(report.retained_referenced_blob_count, 1);
    assert_eq!(report.retained_young_file_count, 1);
    assert_eq!(
        artifact_store.read(&orphan).expect("young orphan remains"),
        b"precommitted but unlinked image"
    );
}
