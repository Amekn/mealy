//! Cross-crate proof that provider/model choices are revision-fenced, immutable at admission,
//! duplicate-safe, and durable across a real `SQLite` reopen.

use mealy_application::{
    AdmitInputCommand, InputAdmissionLimits, OwnershipContext, ProviderSelection,
    ProviderSelectionPreference, ProviderSelectionStoreError, ProviderSelectionUseCaseError,
    UpdateSessionProviderSelectionCommand, admit_input, create_session_with_selection,
    query_session_provider_selection, update_session_provider_selection,
};
use mealy_domain::{ChannelBindingId, DeliveryMode, PrincipalId, SessionId};
use mealy_infrastructure::SqliteStore;
use mealy_testkit::{TestClock, TestIdGenerator};
use std::{fs, path::PathBuf};

const NOW_MS: i64 = 1_786_665_600_000;

struct TemporaryDatabase(PathBuf);

impl TemporaryDatabase {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "mealy-provider-selection-{}.sqlite3",
            SessionId::new()
        )))
    }

    fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut path = self.0.as_os_str().to_owned();
        path.push(suffix);
        PathBuf::from(path)
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(self.sidecar(suffix));
        }
    }
}

fn admit(
    store: &mut SqliteStore,
    clock: &TestClock,
    ids: &TestIdGenerator,
    session_id: SessionId,
    ownership: OwnershipContext,
    key: &str,
    preference: ProviderSelectionPreference,
) -> mealy_application::InputAdmissionOutcome {
    admit_input(
        store,
        clock,
        ids,
        InputAdmissionLimits::default(),
        AdmitInputCommand {
            session_id,
            ownership,
            dedupe_key: key.to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!("input for {key}"),
            provider_selection: preference,
        },
    )
    .expect("admit input")
}

#[test]
#[allow(clippy::too_many_lines)]
fn session_and_turn_selections_survive_default_changes_duplicates_and_reopen() {
    let database = TemporaryDatabase::new();
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS.cast_unsigned());
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let foreign = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let primary = ProviderSelection {
        provider_id: "openrouter".to_owned(),
        model_id: "free/model-a".to_owned(),
    };
    let fallback = ProviderSelection {
        provider_id: "local-llama".to_owned(),
        model_id: "local/model-b".to_owned(),
    };

    let (session_id, original_receipt) = {
        let mut store = SqliteStore::open(&database.0, NOW_MS).expect("open file store");
        let session_id = create_session_with_selection(
            &mut store,
            &clock,
            &ids,
            ownership,
            Some(primary.clone()),
        )
        .expect("create selected session");
        let initial =
            query_session_provider_selection(&store, session_id, ownership).expect("initial view");
        assert_eq!(initial.selection.as_ref(), Some(&primary));
        assert_eq!(initial.revision, 0);
        assert!(initial.event_id.is_some());

        let inherited = admit(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            "inherited-before-change",
            ProviderSelectionPreference::InheritSession,
        );
        assert_eq!(
            inherited.receipt().provider_selection.as_ref(),
            Some(&primary)
        );
        assert_eq!(inherited.receipt().provider_selection_source, "inherited");
        let original_receipt = inherited.receipt().clone();

        let automatic = update_session_provider_selection(
            &mut store,
            &clock,
            &ids,
            UpdateSessionProviderSelectionCommand {
                session_id,
                ownership,
                expected_revision: 1,
                selection: None,
            },
        )
        .expect("restore automatic default");
        assert_eq!(automatic.selection, None);
        assert_eq!(automatic.revision, 2);
        assert!(automatic.event_id.is_some());

        let duplicate = admit(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            "inherited-before-change",
            ProviderSelectionPreference::InheritSession,
        );
        assert!(duplicate.is_duplicate());
        assert_eq!(duplicate.receipt(), &original_receipt);

        let inherited_automatic = admit(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            "inherited-after-change",
            ProviderSelectionPreference::InheritSession,
        );
        assert_eq!(inherited_automatic.receipt().provider_selection, None);
        assert_eq!(
            inherited_automatic.receipt().provider_selection_source,
            "inherited"
        );

        let exact_turn = admit(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            "exact-turn",
            ProviderSelectionPreference::Exact(fallback.clone()),
        );
        assert_eq!(
            exact_turn.receipt().provider_selection.as_ref(),
            Some(&fallback)
        );
        assert_eq!(exact_turn.receipt().provider_selection_source, "exact");

        let automatic_turn = admit(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            "automatic-turn",
            ProviderSelectionPreference::Automatic,
        );
        assert_eq!(automatic_turn.receipt().provider_selection, None);
        assert_eq!(
            automatic_turn.receipt().provider_selection_source,
            "automatic"
        );

        let stale = update_session_provider_selection(
            &mut store,
            &clock,
            &ids,
            UpdateSessionProviderSelectionCommand {
                session_id,
                ownership,
                expected_revision: 2,
                selection: Some(primary.clone()),
            },
        )
        .expect_err("stale revision must fail");
        assert_eq!(
            stale,
            ProviderSelectionUseCaseError::Store(ProviderSelectionStoreError::Conflict)
        );

        let unauthorized = query_session_provider_selection(&store, session_id, foreign)
            .expect_err("foreign binding must fail");
        assert_eq!(
            unauthorized,
            ProviderSelectionUseCaseError::Store(ProviderSelectionStoreError::Unauthorized)
        );
        (session_id, original_receipt)
    };

    let mut reopened = SqliteStore::open(&database.0, NOW_MS + 1).expect("reopen store");
    let current =
        query_session_provider_selection(&reopened, session_id, ownership).expect("reopened view");
    assert_eq!(current.selection, None);
    assert_eq!(current.revision, 5);
    assert!(current.event_id.is_some());

    let duplicate = admit(
        &mut reopened,
        &clock,
        &ids,
        session_id,
        ownership,
        "inherited-before-change",
        ProviderSelectionPreference::InheritSession,
    );
    assert!(duplicate.is_duplicate());
    assert_eq!(duplicate.receipt(), &original_receipt);
}
