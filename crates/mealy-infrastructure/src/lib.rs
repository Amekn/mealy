//! Concrete infrastructure adapters for Mealy.

mod artifact;
mod browser;
mod browser_bundle;
mod channel_secret;
mod codex_app_server;
mod extension_host;
mod fixture;
mod image_generation;
mod maintenance;
mod mcp;
mod mcp_oauth;
mod mcp_oauth_token;
mod media;
mod provider_secret;
mod registry_mirror;
mod registry_package;
mod sandbox;
mod skill_package;
mod sqlite;
mod subscription_cli;
mod system;
mod trusted_executable;
mod web;
mod workspace;

pub use artifact::{ArtifactGarbageCollectionReport, ArtifactStorageUsage, FileArtifactBlobStore};
pub use browser::{
    BrowserHostError, BrowserReadTool, BrowserRuntimeProbe, BrowserTransactionDownload,
    BrowserTransactionExecution, BrowserTransactionTool, BrowserTransactionUploadFile,
    browser_worker_main, probe_browser_bundle_product, verify_browser_runtime_installation,
};
pub use browser_bundle::{
    BrowserBundleEntry, BrowserBundleError, BrowserBundleInspection, inspect_browser_bundle,
    publish_browser_bundle,
};
pub use channel_secret::{ChannelSecretStoreError, FileChannelSecretStore};
pub use codex_app_server::{
    CodexAccountKind, CodexAccountState, CodexAppServerClient, CodexAppServerError,
    CodexChatgptLoginChallenge, CodexChatgptLoginFlow, CodexSubscriptionModel,
};
pub use extension_host::{
    InstalledExtensionPackage, LinuxBubblewrapExtensionHost, inspect_extension_package,
};
pub use fixture::{FixtureReadTool, FixtureResource, FixtureToolConfigurationError};
pub use image_generation::{
    ImageGenerationAdapter, ImageGenerationAdapterError, RemoteGeneratedImage,
};
pub use maintenance::{
    BackupActivationReport, BackupManifest, BackupReport, BackupVerificationReport, ExportReport,
    ForensicBackupReport, MaintenanceError, MigrationBackupActivationReport, MigrationBackupReport,
    activate_backup, activate_migration_backup, create_backup, create_complete_export,
    create_pre_migration_backup, inspect_existing_schema_version, preserve_forensic_database,
    publish_export, verify_backup,
};
pub use mcp::{
    LoadedMcpHttpTools, LoadedMcpTools, McpEffectTool, McpEffectToolOutput, McpHostError,
    McpHttpReadTool, McpReadTool, discover_mcp_http_server, discover_mcp_stdio_server,
    inspect_mcp_http_endpoint, load_mcp_http_read_tools, load_mcp_http_tools, load_mcp_read_tools,
    load_mcp_tools, mcp_stdio_launcher_main,
};
pub use mcp_oauth::discover_mcp_oauth_metadata;
pub use mcp_oauth_token::{
    FileMcpOAuthTokenStore, McpOAuthAccessToken, McpOAuthAuthorizationTransaction,
    McpOAuthTokenError, McpOAuthTokenSet, exchange_mcp_oauth_authorization_code,
    force_refresh_mcp_oauth_access_token, prepare_mcp_oauth_authorization,
    resolve_mcp_oauth_access_token,
};
pub use media::{
    CanonicalImage, LinuxBubblewrapMediaNormalizer, MediaNormalizerError, media_worker_main,
};
pub use provider_secret::{FileProviderSecretStore, ProviderSecretStoreError};
pub use registry_mirror::HttpsRegistryMirrorTransport;
pub use registry_package::{
    InspectedRegistryPackageArchive, InspectedRegistryPackageFile, RegistryPackageArchiveError,
    inspect_registry_package_archive,
};
pub use sandbox::{LinuxBubblewrapConfig, LinuxBubblewrapExecutor, SandboxRuntimeBinding};
pub use skill_package::{
    InspectedSkillAsset, InspectedSkillPackage, MAXIMUM_ACTIVE_SKILL_INSTRUCTION_BYTES,
    MAXIMUM_ACTIVE_SKILL_RESOURCE_BYTES, SkillPackageError, SkillResourceReadTool,
    inspect_skill_package, inspected_registry_skill_package, publish_skill_package,
};
pub use sqlite::{
    ArtifactBlobRecord, JournalRecord, LATEST_SCHEMA_VERSION, OutboxRecord, SqliteStore,
    StoreError, TaskMutation, TaskSnapshot,
};
pub use subscription_cli::{
    SubscriptionCliBuildError, SubscriptionCliProvider, SubscriptionCliSettings,
    inspect_subscription_cli_executable,
};
pub use system::{SystemClock, SystemIdGenerator};
pub use trusted_executable::is_trusted_system_executable;
pub use web::{WebReadTool, WebToolConfigurationError};
pub use workspace::{WorkspaceGrant, WorkspaceReadTool, WorkspaceToolConfigurationError};
