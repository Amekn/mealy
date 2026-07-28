//! Cross-crate proof for canonical owner titles and immutable session checkpoints.

use mealy_application::{
    AdmitInputCommand, CreateSessionCheckpointCommand, ForkSessionCommand, InputAdmissionLimits,
    OwnershipContext, SessionTranscriptStoreError, SessionWorkbenchStoreError,
    SessionWorkbenchUseCaseError, UpdateSessionTitleCommand, admit_input, create_session,
    create_session_checkpoint, fork_session, query_session_checkpoints, query_session_status,
    query_session_transcript, query_sessions, update_session_title,
};
use mealy_domain::{ChannelBindingId, DeliveryMode, PrincipalId, SessionCheckpointId, SessionId};
use mealy_infrastructure::SqliteStore;
use mealy_testkit::{TestClock, TestIdGenerator};

const NOW_MS: i64 = 1_785_196_800_000;

#[test]
fn owner_title_is_revision_fenced_journaled_and_used_by_discovery() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS.cast_unsigned());
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let foreign = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let session_id = create_session(&mut store, &clock, &ids, ownership).expect("create session");

    let receipt = update_session_title(
        &mut store,
        &clock,
        &ids,
        UpdateSessionTitleCommand {
            session_id,
            ownership,
            expected_revision: 0,
            title: "Production readiness".to_owned(),
        },
    )
    .expect("set owner title");
    assert_eq!(receipt.revision, 1);

    let summary = query_sessions(&store, ownership, 20)
        .expect("list sessions")
        .into_iter()
        .find(|session| session.session_id == session_id)
        .expect("updated session");
    assert_eq!(summary.title, "Production readiness");
    assert_eq!(summary.title_source, "owner");
    assert_eq!(summary.revision, 1);

    let stale = update_session_title(
        &mut store,
        &clock,
        &ids,
        UpdateSessionTitleCommand {
            session_id,
            ownership,
            expected_revision: 0,
            title: "Stale write".to_owned(),
        },
    )
    .expect_err("stale revision must fail");
    assert!(matches!(
        stale,
        SessionWorkbenchUseCaseError::Store(SessionWorkbenchStoreError::Conflict)
    ));

    let unauthorized = update_session_title(
        &mut store,
        &clock,
        &ids,
        UpdateSessionTitleCommand {
            session_id,
            ownership: foreign,
            expected_revision: 1,
            title: "Foreign write".to_owned(),
        },
    )
    .expect_err("foreign binding must fail");
    assert!(matches!(
        unauthorized,
        SessionWorkbenchUseCaseError::Store(SessionWorkbenchStoreError::Unauthorized)
    ));
}

#[test]
fn checkpoint_captures_precommit_cursor_and_rejects_nonquiescent_sessions() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS.cast_unsigned());
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let session_id = create_session(&mut store, &clock, &ids, ownership).expect("create session");

    let checkpoint = create_session_checkpoint(
        &mut store,
        &clock,
        &ids,
        CreateSessionCheckpointCommand {
            session_id,
            ownership,
            expected_revision: 0,
            label: Some("Clean start".to_owned()),
        },
    )
    .expect("create empty-session checkpoint");
    assert_eq!(checkpoint.source_cursor, 1);
    assert_eq!(checkpoint.source_session_revision, 0);
    assert_eq!(checkpoint.revision, 1);
    assert_eq!(checkpoint.label.as_deref(), Some("Clean start"));
    assert!(checkpoint.source_turn_id.is_none());
    assert!(checkpoint.context_epoch_id.is_none());
    assert!(checkpoint.provider_id.is_none());
    assert_eq!(checkpoint.workspace_authority_digest.len(), 64);

    let listed =
        query_session_checkpoints(&store, session_id, ownership, 20).expect("list checkpoints");
    assert_eq!(listed, vec![checkpoint]);

    admit_input(
        &mut store,
        &clock,
        &ids,
        InputAdmissionLimits::default(),
        AdmitInputCommand {
            session_id,
            ownership,
            dedupe_key: "pending-after-checkpoint".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "pending input".to_owned(),
        },
    )
    .expect("admit pending input");

    let revision = query_sessions(&store, ownership, 20)
        .expect("list sessions")
        .into_iter()
        .find(|session| session.session_id == session_id)
        .expect("session")
        .revision;
    let error = create_session_checkpoint(
        &mut store,
        &clock,
        &ids,
        CreateSessionCheckpointCommand {
            session_id,
            ownership,
            expected_revision: revision,
            label: None,
        },
    )
    .expect_err("pending input must prevent checkpoint");
    assert!(matches!(
        error,
        SessionWorkbenchUseCaseError::Store(SessionWorkbenchStoreError::NotQuiescent)
    ));
}

#[test]
fn workbench_metadata_rejects_controls_bidi_padding_and_oversize_values() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS.cast_unsigned());
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let session_id = create_session(&mut store, &clock, &ids, ownership).expect("create session");

    for title in [
        "",
        " padded",
        "line\nbreak",
        "bidi\u{202e}override",
        &"界".repeat(73),
    ] {
        let error = update_session_title(
            &mut store,
            &clock,
            &ids,
            UpdateSessionTitleCommand {
                session_id,
                ownership,
                expected_revision: 0,
                title: title.to_owned(),
            },
        )
        .expect_err("unsafe title must fail");
        assert_eq!(error, SessionWorkbenchUseCaseError::InvalidMetadata);
    }
}

#[test]
fn empty_checkpoint_fork_is_fresh_duplicate_safe_and_exact_owner_bound() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS.cast_unsigned());
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let foreign = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let source_session =
        create_session(&mut store, &clock, &ids, ownership).expect("create source session");
    let first_checkpoint = create_session_checkpoint(
        &mut store,
        &clock,
        &ids,
        CreateSessionCheckpointCommand {
            session_id: source_session,
            ownership,
            expected_revision: 0,
            label: Some("Fork base".to_owned()),
        },
    )
    .expect("checkpoint source");
    let command = ForkSessionCommand {
        source_session_id: source_session,
        checkpoint_id: first_checkpoint.checkpoint_id,
        ownership,
        idempotency_key: "fork:empty:1".to_owned(),
    };
    let created = fork_session(&mut store, &clock, &ids, command.clone()).expect("fork session");
    assert!(!created.duplicate);
    assert_eq!(created.root_session_id, source_session);
    assert_eq!(created.source_session_id, source_session);
    assert_eq!(created.referenced_turns, 0);
    let status = query_session_status(&store, created.fork_session_id, ownership)
        .expect("fresh fork status");
    assert_eq!(status.revision, 0);
    assert_eq!(status.pending_inputs, 0);
    assert!(status.active_turn_id.is_none());
    assert_empty_transcript_lineage(
        &store,
        source_session,
        created.fork_session_id,
        first_checkpoint.checkpoint_id,
        ownership,
        foreign,
    );

    let duplicate = fork_session(&mut store, &clock, &ids, command).expect("replay fork command");
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.fork_session_id, created.fork_session_id);
    assert_eq!(duplicate.event_id, created.event_id);

    let second_checkpoint = create_session_checkpoint(
        &mut store,
        &clock,
        &ids,
        CreateSessionCheckpointCommand {
            session_id: source_session,
            ownership,
            expected_revision: 1,
            label: None,
        },
    )
    .expect("second checkpoint");
    let conflict = fork_session(
        &mut store,
        &clock,
        &ids,
        ForkSessionCommand {
            source_session_id: source_session,
            checkpoint_id: second_checkpoint.checkpoint_id,
            ownership,
            idempotency_key: "fork:empty:1".to_owned(),
        },
    )
    .expect_err("same command key cannot select another checkpoint");
    assert!(matches!(
        conflict,
        SessionWorkbenchUseCaseError::Store(SessionWorkbenchStoreError::IdempotencyConflict)
    ));
    let unauthorized = fork_session(
        &mut store,
        &clock,
        &ids,
        ForkSessionCommand {
            source_session_id: source_session,
            checkpoint_id: first_checkpoint.checkpoint_id,
            ownership: foreign,
            idempotency_key: "fork:foreign:1".to_owned(),
        },
    )
    .expect_err("foreign owner cannot fork");
    assert!(matches!(
        unauthorized,
        SessionWorkbenchUseCaseError::Store(SessionWorkbenchStoreError::Unauthorized)
    ));
}

fn assert_empty_transcript_lineage(
    store: &SqliteStore,
    source_session: SessionId,
    fork_session: SessionId,
    checkpoint_id: SessionCheckpointId,
    ownership: OwnershipContext,
    foreign: OwnershipContext,
) {
    let source_export = query_session_transcript(store, source_session, ownership)
        .expect("empty source transcript");
    assert_eq!(source_export.lineage.root_session_id, source_session);
    assert!(source_export.lineage.parent_checkpoint_id.is_none());
    assert!(source_export.turns.is_empty());
    assert_eq!(source_export.total_eligible_turns, 0);
    let fork_export =
        query_session_transcript(store, fork_session, ownership).expect("empty fork transcript");
    assert_eq!(fork_export.lineage.root_session_id, source_session);
    assert_eq!(fork_export.lineage.parent_session_id, Some(source_session));
    assert_eq!(
        fork_export.lineage.parent_checkpoint_id,
        Some(checkpoint_id)
    );
    assert!(fork_export.turns.is_empty());
    assert_eq!(
        query_session_transcript(store, source_session, foreign),
        Err(SessionTranscriptStoreError::NotFound)
    );
}
