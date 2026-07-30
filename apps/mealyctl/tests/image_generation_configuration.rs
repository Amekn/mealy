//! Public-process proof for governed image-generation configuration and credential brokering.

use mealy_application::{AgentLoopLimits, ProviderConfig};
use mealy_infrastructure::FileProviderSecretStore;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

fn initialize_home(home: &Path) {
    fs::create_dir_all(home.join("config-history")).expect("configuration history");
    let config = json!({
        "formatVersion": 1,
        "drainDeadlineMs": 10_000,
        "maximumPendingInputsPerSession": 1_024,
        "agentLoopLimits": AgentLoopLimits::default(),
        "concurrencyLimits": {
            "daemonAgentRuns": 1,
            "principalAgentRuns": 1,
            "sessionAgentRuns": 1,
            "providerRequests": 1,
            "providerRequestsPerMinute": 600,
            "extensionInvocations": 1,
            "agentRoleRuns": 1,
            "resourceClassInvocations": 1
        },
        "provider": ProviderConfig::default(),
        "artifactGcMinimumAgeHours": 24,
        "forensicBackupOnOpenFailure": true,
        "retentionPolicy": {
            "dataClassMinimumAgeHours": {
                "canonical_audit": 87_600,
                "temporary_artifact": 24,
                "unreferenced_artifact": 24
            },
            "sensitivityMinimumAgeHours": {
                "internal": 720,
                "private": 8_760,
                "public": 24,
                "restricted": 87_600
            },
            "protectedPrincipalIds": [],
            "protectedTaskIds": [],
            "protectedChannelBindingIds": [],
            "legalHoldLabels": []
        }
    });
    fs::write(
        home.join("config.json"),
        serde_json::to_vec_pretty(&config).expect("config JSON"),
    )
    .expect("config file");
}

fn run(home: &Path, arguments: &[&str], credential: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command.arg("--home").arg(home).args(arguments);
    if let Some(credential) = credential {
        command.env("MEALY_TEST_IMAGE_API_KEY", credential);
    }
    command.output().expect("run mealyctl")
}

fn run_success(home: &Path, arguments: &[&str], credential: Option<&str>) -> Value {
    let output = run(home, arguments, credential);
    assert!(
        output.status.success(),
        "mealyctl {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("mealyctl JSON response")
}

#[test]
#[allow(clippy::too_many_lines)]
fn enable_replace_disable_and_secret_revocation_are_approved_private_and_reversible() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    initialize_home(home.path());
    let local = [
        "media",
        "image-generation",
        "--enable",
        "--protocol",
        "open-ai-images",
        "--provider-id",
        "local.images",
        "--base-url",
        "http://127.0.0.1:11434/v1",
        "--model",
        "local-image-model",
        "--residency",
        "local",
        "--size",
        "1024x1024",
        "--quality",
        "low",
        "--maximum-cost-microunits",
        "50000",
        "--maximum-output-bytes",
        "2097152",
        "--timeout-ms",
        "120000",
    ];
    assert!(!run(home.path(), &local, None).status.success());
    let before_denial = fs::read(home.path().join("config.json")).expect("configuration");
    assert!(!String::from_utf8_lossy(&before_denial).contains("imageGeneration"));

    let mut approved_local = local.to_vec();
    approved_local.push("--approve");
    let local_result = run_success(home.path(), &approved_local, None);
    assert_eq!(local_result["enabled"], true);
    assert_eq!(local_result["protocol"], "open_ai_images");
    assert_eq!(local_result["connectivityTested"], false);

    let remote = [
        "media",
        "image-generation",
        "--enable",
        "--protocol",
        "open-router-images",
        "--provider-id",
        "openrouter.images",
        "--base-url",
        "https://openrouter.ai/api/v1",
        "--model",
        "owner/image-model:free",
        "--residency",
        "openrouter",
        "--secret-id",
        "openrouter-images",
        "--credential-env",
        "MEALY_TEST_IMAGE_API_KEY",
        "--size",
        "1024x1024",
        "--quality",
        "low",
        "--maximum-cost-microunits",
        "50000",
        "--maximum-output-bytes",
        "2097152",
        "--timeout-ms",
        "120000",
        "--approve",
    ];
    let remote_result = run_success(
        home.path(),
        &remote,
        Some("process-image-generation-secret"),
    );
    assert_eq!(remote_result["protocol"], "open_router_images");
    assert_eq!(remote_result["secretId"], "openrouter-images");
    assert_eq!(remote_result["connectivityTested"], false);
    let config = fs::read(home.path().join("config.json")).expect("remote configuration");
    let config_text = String::from_utf8(config).expect("configuration UTF-8");
    assert!(config_text.contains("\"secretId\": \"openrouter-images\""));
    assert!(!config_text.contains("process-image-generation-secret"));
    assert!(!config_text.contains("MEALY_TEST_IMAGE_API_KEY"));
    assert_eq!(
        FileProviderSecretStore::new(home.path().join("provider-secrets"))
            .expect("provider secret store")
            .read("openrouter-images")
            .expect("brokered image credential")
            .as_str(),
        "process-image-generation-secret"
    );

    assert!(
        !run(
            home.path(),
            &[
                "config",
                "provider-secret-revoke",
                "openrouter-images",
                "--approve"
            ],
            None
        )
        .status
        .success()
    );
    let disabled = run_success(
        home.path(),
        &["media", "image-generation", "--disable", "--approve"],
        None,
    );
    assert_eq!(disabled["enabled"], false);
    let revoked = run_success(
        home.path(),
        &[
            "config",
            "provider-secret-revoke",
            "openrouter-images",
            "--approve",
        ],
        None,
    );
    assert_eq!(revoked["removed"], true);
    assert!(
        fs::read_dir(home.path().join("config-history"))
            .expect("configuration history")
            .count()
            >= 3
    );
}
