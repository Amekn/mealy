//! Durable evidence and configuration staging for provider-primary switches.

use mealy_application::{ProviderConfig, is_sha256_digest, sha256_digest, validate_provider_chain};
use mealy_protocol::ProviderCatalogResponse;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

const PLAN_SCHEMA: &str = "mealy.provider-switch-plan.v1";
const TRANSACTION_SCHEMA: &str = "mealy.provider-switch-transaction.v1";
const MAXIMUM_CONFIG_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_TRANSACTION_BYTES: u64 = 128 * 1024;
const MAXIMUM_HELPER_BYTES: u64 = 256 * 1024 * 1024;

/// A non-mutating decision for promoting one already-configured provider route.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProviderSwitchPlan {
    pub(crate) schema_version: &'static str,
    pub(crate) provider_id: String,
    pub(crate) model_id: String,
    pub(crate) previous_provider_id: String,
    pub(crate) previous_model_id: String,
    pub(crate) active_config_digest: String,
    pub(crate) previous_config_sha256: String,
    pub(crate) candidate_config_sha256: String,
    pub(crate) configured_route_count: usize,
    pub(crate) action_required: bool,
    pub(crate) apply_supported: bool,
    pub(crate) probe_required: bool,
    pub(crate) drain_required: bool,
    pub(crate) restart_required: bool,
    pub(crate) exact_rollback_available: bool,
    pub(crate) selection_scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unsupported_reason: Option<String>,
}

/// Parsed and fenced bytes retained between plan display and transaction creation.
pub(crate) struct PreparedProviderSwitch {
    pub(crate) plan: ProviderSwitchPlan,
    pub(crate) previous_config: Vec<u8>,
    pub(crate) candidate_config: Vec<u8>,
    pub(crate) candidate_provider: ProviderConfig,
}

/// Durable phase for a disconnect-resistant primary-route promotion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProviderSwitchPhase {
    Scheduled,
    Prepared,
    Draining,
    Stopped,
    Activated,
    Starting,
    Verifying,
    Committed,
    Aborted,
    RollingBack,
    RolledBack,
    RecoveryFailed,
}

impl ProviderSwitchPhase {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Aborted | Self::RolledBack | Self::RecoveryFailed
        )
    }
}

/// Durable, non-secret evidence and recovery cursor for one provider switch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProviderSwitchTransaction {
    pub(crate) schema_version: String,
    pub(crate) transaction_id: String,
    pub(crate) phase: ProviderSwitchPhase,
    pub(crate) home: PathBuf,
    pub(crate) service_fragment: PathBuf,
    pub(crate) daemon_executable: PathBuf,
    pub(crate) daemon_sha256: String,
    pub(crate) helper_executable: PathBuf,
    pub(crate) helper_sha256: String,
    pub(crate) previous_config: PathBuf,
    pub(crate) previous_config_sha256: String,
    pub(crate) candidate_config: PathBuf,
    pub(crate) candidate_config_sha256: String,
    pub(crate) previous_active_config_digest: String,
    pub(crate) previous_provider_id: String,
    pub(crate) previous_model_id: String,
    pub(crate) candidate_provider_id: String,
    pub(crate) candidate_model_id: String,
    pub(crate) configured_route_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) archived_config: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) committed_config_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) failure: Option<String>,
    pub(crate) rollback_attempted: bool,
}

#[derive(Debug, Error)]
pub(crate) enum ProviderSwitchError {
    #[error("provider switch plan is invalid or disagrees with the active daemon")]
    InvalidPlan,
    #[error("provider switch transaction evidence is invalid or inconsistent")]
    InvalidTransaction,
    #[error("provider switch transaction storage failed: {0}")]
    Io(#[from] io::Error),
    #[error("provider switch configuration JSON is invalid")]
    Json(#[from] serde_json::Error),
}

/// Construct an exact reordered candidate and verify that active runtime/catalog/config agree.
#[allow(clippy::too_many_lines)]
pub(crate) fn plan(
    home: &Path,
    provider_id: &str,
    model_id: &str,
    catalog: &ProviderCatalogResponse,
    apply_supported: bool,
    unsupported_reason: Option<String>,
) -> Result<PreparedProviderSwitch, ProviderSwitchError> {
    if catalog.api_version != mealy_protocol::API_VERSION
        || catalog.catalog_scope != "configured_route"
        || !is_sha256_digest(&catalog.config_digest)
        || provider_id.is_empty()
        || provider_id.len() > 128
        || model_id.is_empty()
        || model_id.len() > 128
        || provider_id.chars().any(char::is_control)
        || model_id.chars().any(char::is_control)
    {
        return Err(ProviderSwitchError::InvalidPlan);
    }
    let config_path = home.join("config.json");
    let previous_config = read_bounded_regular_file(&config_path, MAXIMUM_CONFIG_BYTES)?;
    let mut document = serde_json::from_slice::<Value>(&previous_config)?;
    let object = document
        .as_object_mut()
        .ok_or(ProviderSwitchError::InvalidPlan)?;
    if object.get("formatVersion").and_then(Value::as_u64) != Some(1) {
        return Err(ProviderSwitchError::InvalidPlan);
    }
    let primary = serde_json::from_value::<ProviderConfig>(
        object
            .get("provider")
            .cloned()
            .ok_or(ProviderSwitchError::InvalidPlan)?,
    )?;
    let fallbacks = object
        .get("providerFallbacks")
        .cloned()
        .map(serde_json::from_value::<Vec<ProviderConfig>>)
        .transpose()?
        .unwrap_or_default();
    validate_provider_chain(&primary, &fallbacks).map_err(|_| ProviderSwitchError::InvalidPlan)?;
    let mut routes = Vec::with_capacity(fallbacks.len().saturating_add(1));
    routes.push(primary);
    routes.extend(fallbacks);
    if routes.len() < 2 || routes.len() != catalog.routes.len() {
        return Err(ProviderSwitchError::InvalidPlan);
    }
    for (ordinal, (configured, active)) in routes.iter().zip(&catalog.routes).enumerate() {
        if configured.provider_id() != Some(active.provider_id.as_str())
            || configured.model_id() != Some(active.model_id.as_str())
            || active.route_ordinal != u64::try_from(ordinal).unwrap_or(u64::MAX)
            || active.route_role != if ordinal == 0 { "primary" } else { "fallback" }
            || !active.selectable
        {
            return Err(ProviderSwitchError::InvalidPlan);
        }
    }
    let selected = routes
        .iter()
        .position(|route| {
            route.provider_id() == Some(provider_id) && route.model_id() == Some(model_id)
        })
        .ok_or(ProviderSwitchError::InvalidPlan)?;
    let previous_provider_id = routes[0]
        .provider_id()
        .ok_or(ProviderSwitchError::InvalidPlan)?
        .to_owned();
    let previous_model_id = routes[0]
        .model_id()
        .ok_or(ProviderSwitchError::InvalidPlan)?
        .to_owned();
    let action_required = selected != 0;
    let candidate_provider = routes[selected].clone();
    if action_required {
        let promoted = routes.remove(selected);
        routes.insert(0, promoted);
    }
    validate_provider_chain(&routes[0], &routes[1..])
        .map_err(|_| ProviderSwitchError::InvalidPlan)?;
    object.insert("provider".to_owned(), serde_json::to_value(&routes[0])?);
    object.insert(
        "providerFallbacks".to_owned(),
        serde_json::to_value(&routes[1..])?,
    );
    let candidate_config = if action_required {
        serde_json::to_vec_pretty(&document)?
    } else {
        previous_config.clone()
    };
    let previous_config_sha256 = sha256_digest(&previous_config);
    let candidate_config_sha256 = sha256_digest(&candidate_config);
    if action_required && previous_config_sha256 == candidate_config_sha256 {
        return Err(ProviderSwitchError::InvalidPlan);
    }
    Ok(PreparedProviderSwitch {
        plan: ProviderSwitchPlan {
            schema_version: PLAN_SCHEMA,
            provider_id: provider_id.to_owned(),
            model_id: model_id.to_owned(),
            previous_provider_id,
            previous_model_id,
            active_config_digest: catalog.config_digest.clone(),
            previous_config_sha256,
            candidate_config_sha256,
            configured_route_count: routes.len(),
            action_required,
            apply_supported,
            probe_required: action_required,
            drain_required: action_required,
            restart_required: action_required,
            exact_rollback_available: action_required,
            selection_scope: "configured-route-primary",
            unsupported_reason,
        },
        previous_config,
        candidate_config,
        candidate_provider,
    })
}

/// Durably record an exact switch request before its independent helper is scheduled.
pub(crate) fn prepare_transaction(
    home: &Path,
    prepared: &PreparedProviderSwitch,
    service_fragment: &Path,
    daemon_executable: &Path,
    helper_source: &Path,
) -> Result<ProviderSwitchTransaction, ProviderSwitchError> {
    if !prepared.plan.action_required || !prepared.plan.apply_supported {
        return Err(ProviderSwitchError::InvalidPlan);
    }
    let home = canonical_real_directory(home)?;
    let service_fragment = canonical_regular_file(service_fragment)?;
    let daemon_executable = canonical_regular_file(daemon_executable)?;
    let helper_source = canonical_regular_file(helper_source)?;
    let transaction_id = Uuid::now_v7().to_string();
    let directory = transaction_directory(&home)?;
    let helper_executable = directory.join(format!("{transaction_id}.helper"));
    let previous_config = directory.join(format!("{transaction_id}.previous.json"));
    let candidate_config = directory.join(format!("{transaction_id}.candidate.json"));
    let helper_sha256 = copy_executable(&helper_source, &helper_executable)?;
    if let Err(error) = write_new_private(&previous_config, &prepared.previous_config, 0o600)
        .and_then(|()| write_new_private(&candidate_config, &prepared.candidate_config, 0o600))
    {
        let _ = fs::remove_file(&helper_executable);
        let _ = fs::remove_file(&previous_config);
        let _ = fs::remove_file(&candidate_config);
        return Err(error.into());
    }
    let record = ProviderSwitchTransaction {
        schema_version: TRANSACTION_SCHEMA.to_owned(),
        transaction_id,
        phase: ProviderSwitchPhase::Scheduled,
        home,
        service_fragment,
        daemon_sha256: digest_regular_file(&daemon_executable, MAXIMUM_HELPER_BYTES)?,
        daemon_executable,
        helper_executable,
        helper_sha256,
        previous_config,
        previous_config_sha256: prepared.plan.previous_config_sha256.clone(),
        candidate_config,
        candidate_config_sha256: prepared.plan.candidate_config_sha256.clone(),
        previous_active_config_digest: prepared.plan.active_config_digest.clone(),
        previous_provider_id: prepared.plan.previous_provider_id.clone(),
        previous_model_id: prepared.plan.previous_model_id.clone(),
        candidate_provider_id: prepared.plan.provider_id.clone(),
        candidate_model_id: prepared.plan.model_id.clone(),
        configured_route_count: prepared.plan.configured_route_count,
        archived_config: None,
        committed_config_digest: None,
        failure: None,
        rollback_attempted: false,
    };
    if let Err(error) = validate_transaction(&record, true) {
        remove_transaction_payloads(&record);
        return Err(error);
    }
    let destination = transaction_path(&record.home, &record.transaction_id);
    if let Err(error) = write_new_private(&destination, &serde_json::to_vec_pretty(&record)?, 0o600)
    {
        remove_transaction_payloads(&record);
        return Err(error.into());
    }
    sync_directory(&directory)?;
    Ok(record)
}

pub(crate) fn load_transaction(
    home: &Path,
    transaction_id: &str,
) -> Result<ProviderSwitchTransaction, ProviderSwitchError> {
    validate_transaction_id(transaction_id)?;
    let home = canonical_real_directory(home)?;
    validate_existing_transaction_directory(&home)?;
    let bytes = read_bounded_private_file(
        &transaction_path(&home, transaction_id),
        MAXIMUM_TRANSACTION_BYTES,
    )?;
    let record = serde_json::from_slice::<ProviderSwitchTransaction>(&bytes)?;
    validate_transaction(&record, false)?;
    if record.home != home || record.transaction_id != transaction_id {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(record)
}

pub(crate) fn persist_transaction(
    record: &ProviderSwitchTransaction,
) -> Result<(), ProviderSwitchError> {
    validate_transaction(record, false)?;
    let current = load_transaction(&record.home, &record.transaction_id)?;
    if !same_identity(&current, record) || !valid_transition(current.phase, record.phase) {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    let directory = transaction_directory(&record.home)?;
    atomic_write_private(
        &transaction_path(&record.home, &record.transaction_id),
        &serde_json::to_vec_pretty(record)?,
    )?;
    sync_directory(&directory)?;
    Ok(())
}

pub(crate) fn verify_helper_identity(
    record: &ProviderSwitchTransaction,
    executable: &Path,
) -> Result<(), ProviderSwitchError> {
    validate_transaction(record, false)?;
    let executable = canonical_regular_file(executable)?;
    let mode = fs::metadata(&executable)?.permissions().mode() & 0o777;
    if executable != record.helper_executable
        || mode != 0o500
        || digest_regular_file(&executable, MAXIMUM_HELPER_BYTES)? != record.helper_sha256
    {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(())
}

pub(crate) fn verify_daemon_identity(
    record: &ProviderSwitchTransaction,
) -> Result<(), ProviderSwitchError> {
    if canonical_regular_file(&record.daemon_executable)? != record.daemon_executable
        || digest_regular_file(&record.daemon_executable, MAXIMUM_HELPER_BYTES)?
            != record.daemon_sha256
    {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(())
}

pub(crate) fn read_previous_config(
    record: &ProviderSwitchTransaction,
) -> Result<Vec<u8>, ProviderSwitchError> {
    read_snapshot(&record.previous_config, &record.previous_config_sha256)
}

pub(crate) fn read_candidate_config(
    record: &ProviderSwitchTransaction,
) -> Result<Vec<u8>, ProviderSwitchError> {
    read_snapshot(&record.candidate_config, &record.candidate_config_sha256)
}

pub(crate) fn active_config_slot(
    record: &ProviderSwitchTransaction,
) -> Result<Option<ProviderSwitchConfigSlot>, ProviderSwitchError> {
    let bytes = read_bounded_regular_file(&record.home.join("config.json"), MAXIMUM_CONFIG_BYTES)?;
    let digest = sha256_digest(&bytes);
    Ok(if digest == record.previous_config_sha256 {
        Some(ProviderSwitchConfigSlot::Previous)
    } else if digest == record.candidate_config_sha256 {
        Some(ProviderSwitchConfigSlot::Candidate)
    } else {
        None
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderSwitchConfigSlot {
    Previous,
    Candidate,
}

pub(crate) fn retire_helper(record: &ProviderSwitchTransaction) -> Result<(), ProviderSwitchError> {
    if !matches!(
        record.phase,
        ProviderSwitchPhase::Committed
            | ProviderSwitchPhase::Aborted
            | ProviderSwitchPhase::RolledBack
    ) {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    verify_helper_identity(record, &record.helper_executable)?;
    fs::remove_file(&record.helper_executable)?;
    sync_directory(&transaction_directory(&record.home)?)?;
    Ok(())
}

fn validate_transaction(
    record: &ProviderSwitchTransaction,
    allow_missing_record: bool,
) -> Result<(), ProviderSwitchError> {
    validate_transaction_id(&record.transaction_id)?;
    let directory = record.home.join("provider-switch-transactions");
    if record.schema_version != TRANSACTION_SCHEMA
        || !valid_absolute_path(&record.home)
        || !valid_absolute_path(&record.service_fragment)
        || !valid_absolute_path(&record.daemon_executable)
        || record.helper_executable != directory.join(format!("{}.helper", record.transaction_id))
        || record.previous_config
            != directory.join(format!("{}.previous.json", record.transaction_id))
        || record.candidate_config
            != directory.join(format!("{}.candidate.json", record.transaction_id))
        || !is_sha256_digest(&record.daemon_sha256)
        || !is_sha256_digest(&record.helper_sha256)
        || !is_sha256_digest(&record.previous_config_sha256)
        || !is_sha256_digest(&record.candidate_config_sha256)
        || record.previous_config_sha256 == record.candidate_config_sha256
        || !is_sha256_digest(&record.previous_active_config_digest)
        || !valid_identity(&record.previous_provider_id, 128)
        || !valid_identity(&record.previous_model_id, 128)
        || !valid_identity(&record.candidate_provider_id, 128)
        || !valid_identity(&record.candidate_model_id, 128)
        || record.configured_route_count < 2
        || record.configured_route_count > 32
        || record.failure.as_ref().is_some_and(|failure| {
            failure.is_empty() || failure.len() > 256 || failure.chars().any(char::is_control)
        })
        || record
            .committed_config_digest
            .as_ref()
            .is_some_and(|digest| !is_sha256_digest(digest))
        || record.archived_config.as_ref().is_some_and(|path| {
            !valid_absolute_path(path)
                || path.parent() != Some(record.home.join("config-history").as_path())
        })
        || (matches!(
            record.phase,
            ProviderSwitchPhase::RollingBack | ProviderSwitchPhase::RolledBack
        ) && !record.rollback_attempted)
        || (record.rollback_attempted
            && !matches!(
                record.phase,
                ProviderSwitchPhase::RollingBack
                    | ProviderSwitchPhase::RolledBack
                    | ProviderSwitchPhase::RecoveryFailed
            ))
        || (record.phase == ProviderSwitchPhase::Committed
            && record.committed_config_digest.is_none())
    {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    if !allow_missing_record {
        read_snapshot(&record.previous_config, &record.previous_config_sha256)?;
        read_snapshot(&record.candidate_config, &record.candidate_config_sha256)?;
    }
    Ok(())
}

fn same_identity(left: &ProviderSwitchTransaction, right: &ProviderSwitchTransaction) -> bool {
    left.schema_version == right.schema_version
        && left.transaction_id == right.transaction_id
        && left.home == right.home
        && left.service_fragment == right.service_fragment
        && left.daemon_executable == right.daemon_executable
        && left.daemon_sha256 == right.daemon_sha256
        && left.helper_executable == right.helper_executable
        && left.helper_sha256 == right.helper_sha256
        && left.previous_config == right.previous_config
        && left.previous_config_sha256 == right.previous_config_sha256
        && left.candidate_config == right.candidate_config
        && left.candidate_config_sha256 == right.candidate_config_sha256
        && left.previous_active_config_digest == right.previous_active_config_digest
        && left.previous_provider_id == right.previous_provider_id
        && left.previous_model_id == right.previous_model_id
        && left.candidate_provider_id == right.candidate_provider_id
        && left.candidate_model_id == right.candidate_model_id
        && left.configured_route_count == right.configured_route_count
}

fn valid_transition(from: ProviderSwitchPhase, to: ProviderSwitchPhase) -> bool {
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (
            ProviderSwitchPhase::Scheduled,
            ProviderSwitchPhase::Prepared
                | ProviderSwitchPhase::Aborted
                | ProviderSwitchPhase::RecoveryFailed
        ) | (
            ProviderSwitchPhase::Prepared,
            ProviderSwitchPhase::Draining
                | ProviderSwitchPhase::Aborted
                | ProviderSwitchPhase::RollingBack
                | ProviderSwitchPhase::RecoveryFailed
        ) | (
            ProviderSwitchPhase::Draining,
            ProviderSwitchPhase::Stopped
                | ProviderSwitchPhase::Aborted
                | ProviderSwitchPhase::RollingBack
                | ProviderSwitchPhase::RecoveryFailed
        ) | (
            ProviderSwitchPhase::Stopped,
            ProviderSwitchPhase::Activated
                | ProviderSwitchPhase::Aborted
                | ProviderSwitchPhase::RollingBack
                | ProviderSwitchPhase::RecoveryFailed
        ) | (
            ProviderSwitchPhase::Activated,
            ProviderSwitchPhase::Starting
                | ProviderSwitchPhase::RollingBack
                | ProviderSwitchPhase::RecoveryFailed
        ) | (
            ProviderSwitchPhase::Starting,
            ProviderSwitchPhase::Verifying
                | ProviderSwitchPhase::RollingBack
                | ProviderSwitchPhase::RecoveryFailed
        ) | (
            ProviderSwitchPhase::Verifying,
            ProviderSwitchPhase::Committed
                | ProviderSwitchPhase::RollingBack
                | ProviderSwitchPhase::RecoveryFailed
        ) | (
            ProviderSwitchPhase::RollingBack,
            ProviderSwitchPhase::RolledBack | ProviderSwitchPhase::RecoveryFailed
        )
    )
}

fn read_snapshot(path: &Path, expected: &str) -> Result<Vec<u8>, ProviderSwitchError> {
    let bytes = read_bounded_private_file(path, MAXIMUM_CONFIG_BYTES)?;
    if sha256_digest(&bytes) != expected {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(bytes)
}

fn transaction_directory(home: &Path) -> Result<PathBuf, ProviderSwitchError> {
    let directory = home.join("provider-switch-transactions");
    match fs::create_dir(&directory) {
        Ok(()) => {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            sync_directory(home)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    validate_transaction_directory(&directory)?;
    Ok(directory)
}

fn validate_existing_transaction_directory(home: &Path) -> Result<(), ProviderSwitchError> {
    validate_transaction_directory(&home.join("provider-switch-transactions"))
}

fn validate_transaction_directory(directory: &Path) -> Result<(), ProviderSwitchError> {
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(())
}

fn transaction_path(home: &Path, transaction_id: &str) -> PathBuf {
    home.join("provider-switch-transactions")
        .join(format!("{transaction_id}.json"))
}

fn copy_executable(source: &Path, destination: &Path) -> Result<String, ProviderSwitchError> {
    let mut input = open_no_follow(source)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAXIMUM_HELPER_BYTES {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o500);
    let mut output = options.open(destination)?;
    let mut bytes = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    let result = (|| -> Result<String, ProviderSwitchError> {
        loop {
            let count = input.read(&mut bytes)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
                .ok_or(ProviderSwitchError::InvalidTransaction)?;
            if total > MAXIMUM_HELPER_BYTES {
                return Err(ProviderSwitchError::InvalidTransaction);
            }
            output.write_all(&bytes[..count])?;
            hasher.update(&bytes[..count]);
        }
        if total != metadata.len() {
            return Err(ProviderSwitchError::InvalidTransaction);
        }
        output.set_permissions(fs::Permissions::from_mode(0o500))?;
        output.sync_all()?;
        Ok(lowercase_hex(&hasher.finalize()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn digest_regular_file(path: &Path, maximum: u64) -> Result<String, ProviderSwitchError> {
    let bytes = read_bounded_regular_file(path, maximum)?;
    if bytes.is_empty() {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(sha256_digest(&bytes))
}

fn write_new_private(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no transaction parent"))?;
    let temporary = parent.join(format!(
        ".{}.{}.new",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("record"),
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    write_new_private(&temporary, bytes, 0o600)?;
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = open_no_follow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe bounded file",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(bytes)
}

fn read_bounded_private_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is not owner-private",
        ));
    }
    read_bounded_regular_file(path, maximum)
}

fn canonical_real_directory(path: &Path) -> Result<PathBuf, ProviderSwitchError> {
    let metadata = fs::symlink_metadata(path)?;
    let canonical = fs::canonicalize(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || !valid_absolute_path(&canonical) {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(canonical)
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, ProviderSwitchError> {
    let metadata = fs::symlink_metadata(path)?;
    let canonical = fs::canonicalize(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || !valid_absolute_path(&canonical)
    {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(canonical)
}

fn valid_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn valid_identity(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn validate_transaction_id(value: &str) -> Result<(), ProviderSwitchError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ProviderSwitchError::InvalidTransaction)?;
    if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != value {
        return Err(ProviderSwitchError::InvalidTransaction);
    }
    Ok(())
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, open};
    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(Into::into)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn remove_transaction_payloads(record: &ProviderSwitchTransaction) {
    let _ = fs::remove_file(&record.helper_executable);
    let _ = fs::remove_file(&record.previous_config);
    let _ = fs::remove_file(&record.candidate_config);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mealy_protocol::{API_VERSION, ProviderCatalogRouteResponse};

    fn route(provider_id: &str, model_id: &str, ordinal: u64) -> ProviderCatalogRouteResponse {
        ProviderCatalogRouteResponse {
            route_ordinal: ordinal,
            route_role: if ordinal == 0 {
                "primary".to_owned()
            } else {
                "fallback".to_owned()
            },
            protocol: "openai_responses".to_owned(),
            provider_id: provider_id.to_owned(),
            model_id: model_id.to_owned(),
            input_modalities: vec!["text".to_owned()],
            tool_calling: true,
            structured_output: true,
            reasoning_controls: Vec::new(),
            streaming: false,
            residency: "owner-local".to_owned(),
            local: true,
            context_tokens: 32_768,
            maximum_output_tokens: 4_096,
            input_token_overhead: 0,
            limits_source: "active_configuration".to_owned(),
            limits_operator_verified: false,
            input_microunits_per_million_tokens: 0,
            output_microunits_per_million_tokens: 0,
            pricing_source: "active_configuration".to_owned(),
            pricing_verified: false,
            health: "unknown".to_owned(),
            estimated_latency_ms: 1_000,
            in_flight_requests: 0,
            maximum_concurrent_requests: 1,
            requests_in_current_minute: 0,
            requests_per_minute: 60,
            selectable: true,
        }
    }

    fn provider(provider_id: &str, model: &str, port: u16) -> ProviderConfig {
        ProviderConfig::OpenAiResponses {
            provider_id: provider_id.to_owned(),
            base_url: format!("http://127.0.0.1:{port}/v1"),
            model: model.to_owned(),
            credential: None,
            residency: "owner-local".to_owned(),
            context_tokens: 32_768,
            maximum_output_tokens: 4_096,
            streaming: false,
            input_microunits_per_million_tokens: 0,
            output_microunits_per_million_tokens: 0,
            estimated_latency_ms: 1_000,
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        ProviderCatalogResponse,
        PreparedProviderSwitch,
    ) {
        let temporary = tempfile::tempdir().expect("temporary home");
        let primary = provider("local.primary", "primary-model", 18_080);
        let fallback = provider("local.fallback", "fallback-model", 18_081);
        let document = serde_json::json!({
            "formatVersion": 1,
            "provider": primary,
            "providerFallbacks": [fallback]
        });
        fs::write(
            temporary.path().join("config.json"),
            serde_json::to_vec_pretty(&document).expect("configuration"),
        )
        .expect("write configuration");
        let catalog = ProviderCatalogResponse {
            api_version: API_VERSION.to_owned(),
            catalog_scope: "configured_route".to_owned(),
            config_digest: "a".repeat(64),
            automatic_fallback_enabled: true,
            routes: vec![
                route("local.primary", "primary-model", 0),
                route("local.fallback", "fallback-model", 1),
            ],
        };
        let prepared = plan(
            temporary.path(),
            "local.fallback",
            "fallback-model",
            &catalog,
            true,
            None,
        )
        .expect("switch plan");
        (temporary, catalog, prepared)
    }

    #[test]
    fn plan_promotes_only_one_exact_active_route_and_preserves_the_chain() {
        let (temporary, catalog, prepared) = fixture();
        assert!(prepared.plan.action_required);
        assert_eq!(prepared.plan.previous_provider_id, "local.primary");
        assert_eq!(prepared.plan.provider_id, "local.fallback");
        assert_ne!(
            prepared.plan.previous_config_sha256,
            prepared.plan.candidate_config_sha256
        );
        let candidate: Value =
            serde_json::from_slice(&prepared.candidate_config).expect("candidate JSON");
        assert_eq!(
            candidate["provider"]["providerId"],
            Value::String("local.fallback".to_owned())
        );
        assert_eq!(
            candidate["providerFallbacks"][0]["providerId"],
            Value::String("local.primary".to_owned())
        );

        let no_op = plan(
            temporary.path(),
            "local.primary",
            "primary-model",
            &catalog,
            true,
            None,
        )
        .expect("no-op plan");
        assert!(!no_op.plan.action_required);
        assert_eq!(
            no_op.plan.previous_config_sha256,
            no_op.plan.candidate_config_sha256
        );

        let mut mismatched = catalog;
        mismatched.routes[1].model_id = "different".to_owned();
        assert!(
            plan(
                temporary.path(),
                "local.fallback",
                "fallback-model",
                &mismatched,
                true,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn transaction_snapshots_are_private_digest_bound_and_phase_fenced() {
        let (temporary, _catalog, prepared) = fixture();
        let service = temporary.path().join("mealy.service");
        let daemon = temporary.path().join("mealyd");
        let helper = temporary.path().join("mealyctl");
        fs::write(&service, b"[Service]\n").expect("service");
        fs::write(&daemon, b"daemon").expect("daemon");
        fs::write(&helper, b"client").expect("helper");
        let mut transaction =
            prepare_transaction(temporary.path(), &prepared, &service, &daemon, &helper)
                .expect("transaction");
        assert_eq!(transaction.phase, ProviderSwitchPhase::Scheduled);
        assert_eq!(
            fs::metadata(&transaction.helper_executable)
                .expect("helper metadata")
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
        assert_eq!(
            read_previous_config(&transaction).expect("previous snapshot"),
            prepared.previous_config
        );
        assert_eq!(
            read_candidate_config(&transaction).expect("candidate snapshot"),
            prepared.candidate_config
        );

        transaction.phase = ProviderSwitchPhase::Prepared;
        persist_transaction(&transaction).expect("valid phase advance");
        let mut invalid = transaction.clone();
        invalid.phase = ProviderSwitchPhase::Committed;
        invalid.committed_config_digest = Some("b".repeat(64));
        assert!(persist_transaction(&invalid).is_err());

        fs::write(&transaction.candidate_config, b"tampered").expect("tamper candidate");
        assert!(
            load_transaction(temporary.path(), &transaction.transaction_id).is_err(),
            "a changed snapshot must invalidate the whole recovery record"
        );
    }
}
