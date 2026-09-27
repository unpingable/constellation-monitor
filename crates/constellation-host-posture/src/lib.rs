#![forbid(unsafe_code)]
//! Installed, single-profile host-posture runner.
//!
//! This crate composes the existing filesystem-capacity correspondence,
//! Pulse reactor, owner consequence adapter, and status projector. It owns no
//! diagnostic threshold or consequence rule.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use constellation_status_nq_filesystem_capacity::{
    CONSEQUENCE_SCHEMA_V1, FACT_OWNER, admit_live, fact_for, live_support_selector,
    operator_component_label, operator_detail, recommended_safe_reasons,
};
use constellation_status_projection::{
    AudienceClassV1, ComponentOutputFieldV1, ComponentPolicyV1, DisclosurePolicyV1,
    FactRequirementV1, LiveSupportSelectorV1, OutputComponentV1, PROJECTION_POLICY_SCHEMA_V1,
    ProjectedStateV1, ProjectionMomentV1, ProjectionPolicyV1, SourceFactClassV1,
    project_with_details, read_current_artifact, stage_publication,
};
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceError, CorrespondenceProfileV1, NQ_ARTIFACT_SCHEMA, NqEnrollmentV1,
    NqProducerV1, OccurrenceOutcomeV1, PinnedNqExecutable, PulseEnrollmentV1, QuestionV1,
    SemanticIdentityV1, SubjectIncarnationWitness, VerifiedCorrespondenceV1, read_regular_bounded,
    sha256_hex_of_file, write_create_new,
};
use pulse_runtime::{
    HistoricalJournal, JournalBoundsV1, JournalConfigV1, LocalCrashReactor,
    LocalQualificationInputsV1, MonotonicEpochV1, QualificationCorpusArtifactV1,
    QualificationResultsArtifactV1, ReactorConditionV1, ReactorConfigV1, ReceiverSchedulerRuntime,
    RuntimeBoundsV1, RuntimeConfigV1, build_local_qualification_package,
};
use pulse_types::{
    BuildIdentityV1, ClockId, DigestV1, IncarnationId, LocalActivationAcceptanceV1,
    QualificationCertificateV1, QualificationEvidenceReportV1, QualifiedArtifactManifestV1,
    ReceiverId, RuntimeBindingStateV1, RuntimeDependencyIdentityV1, SCHEMA_VERSION_V1,
    SourceIdentityV1, artifact_content_digest, canonical_artifact_bytes,
};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_CONFIG_BYTES: usize = 256 * 1_024;
const MAX_PROFILE_BYTES: usize = 64 * 1_024;
const MAX_PACKAGE_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_NQ_ARTIFACT_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_NQ_EXECUTABLE_BYTES: usize = 128 * 1_024 * 1_024;
const MAX_NQ_CONFIG_BYTES: usize = 256 * 1_024;
const CONDITION_KEY: &str = "nq.host_filesystem_capacity.pressure";
const CONDITION_OUTPUT: &str = "filesystem-capacity";
const FACT_ID: &str = "fact.nq.host_filesystem_capacity.pressure";
const BUILD_INFO_SCHEMA: &str = "constellation.host_posture.build_info.v1";
const UNAVAILABLE: &str = "unavailable";

const SOURCE_REPOSITORY: &str = match option_env!("CONSTELLATION_HOST_POSTURE_SOURCE_REPOSITORY") {
    Some(value) => value,
    None => UNAVAILABLE,
};
const SOURCE_COMMIT: &str = match option_env!("CONSTELLATION_HOST_POSTURE_SOURCE_COMMIT") {
    Some(value) => value,
    None => UNAVAILABLE,
};
const SOURCE_TREE_DIGEST: &str = match option_env!("CONSTELLATION_HOST_POSTURE_SOURCE_TREE_DIGEST")
{
    Some(value) => value,
    None => UNAVAILABLE,
};
const TOOLCHAIN_IDENTITY: &str = match option_env!("CONSTELLATION_HOST_POSTURE_TOOLCHAIN_IDENTITY")
{
    Some(value) => value,
    None => UNAVAILABLE,
};
const TARGET_TRIPLE: &str = match option_env!("CONSTELLATION_HOST_POSTURE_TARGET_TRIPLE") {
    Some(value) => value,
    None => UNAVAILABLE,
};
const BUILD_PROFILE: &str = match option_env!("CONSTELLATION_HOST_POSTURE_BUILD_PROFILE") {
    Some(value) => value,
    None => UNAVAILABLE,
};
const ENABLED_FEATURES: &str = match option_env!("CONSTELLATION_HOST_POSTURE_ENABLED_FEATURES_JSON")
{
    Some(value) => value,
    None => UNAVAILABLE,
};
const CARGO_LOCK_DIGEST: &str = match option_env!("CONSTELLATION_HOST_POSTURE_CARGO_LOCK_DIGEST") {
    Some(value) => value,
    None => UNAVAILABLE,
};

#[derive(Debug, Serialize)]
pub struct BuildInformation {
    schema: &'static str,
    component: &'static str,
    version: &'static str,
    source_repository: &'static str,
    source_commit: &'static str,
    source_tree_digest: &'static str,
    toolchain_identity: &'static str,
    target_triple: &'static str,
    build_profile: &'static str,
    enabled_features_json: &'static str,
    cargo_lock_digest: &'static str,
}

#[must_use]
pub const fn build_information() -> BuildInformation {
    BuildInformation {
        schema: BUILD_INFO_SCHEMA,
        component: "constellation-host-posture",
        version: env!("CARGO_PKG_VERSION"),
        source_repository: SOURCE_REPOSITORY,
        source_commit: SOURCE_COMMIT,
        source_tree_digest: SOURCE_TREE_DIGEST,
        toolchain_identity: TOOLCHAIN_IDENTITY,
        target_triple: TARGET_TRIPLE,
        build_profile: BUILD_PROFILE,
        enabled_features_json: ENABLED_FEATURES,
        cargo_lock_digest: CARGO_LOCK_DIGEST,
    }
}

#[derive(Debug)]
pub struct HostPostureError {
    pub code: &'static str,
    pub detail: String,
}

impl HostPostureError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for HostPostureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for HostPostureError {}

type Result<T> = std::result::Result<T, HostPostureError>;

fn map_error(code: &'static str, error: impl std::fmt::Display) -> HostPostureError {
    HostPostureError::new(code, error.to_string())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPostureConfig {
    #[serde(skip)]
    loaded_from: PathBuf,
    #[serde(skip)]
    loaded_digest: Option<DigestV1>,
    pub service_uid: u32,
    pub profile_path: PathBuf,
    pub nq_executable: PathBuf,
    pub nq_config: PathBuf,
    pub qualification_package_dir: PathBuf,
    pub state_root: PathBuf,
    pub publication_root: PathBuf,
    pub receiver_id: String,
    pub mountpoint_label: String,
    pub acquisition_interval_ms: u64,
    pub projection_interval_ms: u64,
    pub withdrawal_publication_tolerance_ms: u64,
    pub maximum_trusted_lifetime_ms: u64,
    pub maximum_occurrences: u64,
    pub maximum_publications: u64,
    pub runtime_bounds: RuntimeBoundsV1,
    pub journal_bounds: JournalBoundsV1,
    pub reactor: ReactorConfigV1,
    pub enrollment: EnrollmentConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<QualificationPreparationConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentConfig {
    pub instance_id: String,
    pub observer_id: String,
    pub consumer_id: String,
    pub policy_generation: String,
    pub observation_policy_generation: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationPreparationConfig {
    pub corpus_path: PathBuf,
    pub results_path: PathBuf,
    pub source: SourceIdentityV1,
    pub build: BuildIdentityV1,
    pub platform_assumptions: Vec<String>,
    pub declared_claims: Vec<String>,
    pub nonclaims: Vec<String>,
    #[serde(default)]
    pub supersedes_manifest_digests: Vec<DigestV1>,
    pub lifecycle_authority_id: String,
    pub issuance_id: String,
    pub issuer_id: String,
}

impl HostPostureConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(HostPostureError::new(
                "relative_path",
                "runner configuration path must be absolute",
            ));
        }
        let bytes = read_regular_bounded(path, MAX_CONFIG_BYTES)
            .map_err(|error| map_error("config_read", error))?;
        let text =
            std::str::from_utf8(&bytes).map_err(|error| map_error("config_decode", error))?;
        let mut config: Self =
            toml::from_str(text).map_err(|error| map_error("config_decode", error))?;
        config.loaded_from = path.to_path_buf();
        config.loaded_digest = Some(artifact_content_digest(&bytes));
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.service_uid == 0 {
            return Err(HostPostureError::new(
                "invalid_service_uid",
                "runner service uid must be a dedicated non-root identity",
            ));
        }
        for (name, path) in [
            ("profile_path", &self.profile_path),
            ("nq_executable", &self.nq_executable),
            ("nq_config", &self.nq_config),
            ("qualification_package_dir", &self.qualification_package_dir),
            ("state_root", &self.state_root),
            ("publication_root", &self.publication_root),
        ] {
            if !path.is_absolute() {
                return Err(HostPostureError::new(
                    "relative_path",
                    format!("{name} must be absolute"),
                ));
            }
        }
        if self.acquisition_interval_ms == 0
            || self.projection_interval_ms == 0
            || self.withdrawal_publication_tolerance_ms == 0
            || self.maximum_trusted_lifetime_ms == 0
            || self.maximum_occurrences == 0
            || self.maximum_publications == 0
        {
            return Err(HostPostureError::new(
                "invalid_bound",
                "intervals, trusted lifetime, and occurrence bound must be positive",
            ));
        }
        if self.projection_interval_ms > self.withdrawal_publication_tolerance_ms
            || self.withdrawal_publication_tolerance_ms > 5_000
        {
            return Err(HostPostureError::new(
                "invalid_projection_cadence",
                "projection cadence must meet the explicit withdrawal tolerance, which may not exceed 5000 ms for this installed profile",
            ));
        }
        let withdrawal_delay = self
            .projection_interval_ms
            .checked_add(self.reactor.command_response_timeout_ms)
            .ok_or_else(|| {
                HostPostureError::new(
                    "invalid_projection_cadence",
                    "projection interval plus reactor command timeout overflows",
                )
            })?;
        if self.reactor.command_response_timeout_ms == 0
            || withdrawal_delay > self.withdrawal_publication_tolerance_ms
        {
            return Err(HostPostureError::new(
                "invalid_projection_cadence",
                "projection interval plus reactor command timeout must fit the explicit withdrawal-publication tolerance",
            ));
        }
        if self.reactor.deliberate_deadline_delay_ms != 0
            || self.reactor.journal_durability != pulse_runtime::JournalDurabilityModeV1::FileSynced
        {
            return Err(HostPostureError::new(
                "invalid_reactor_config",
                "installed runner requires zero deliberate deadline delay and file-synced journal durability",
            ));
        }
        if self.publication_root != self.state_root.join("status") {
            return Err(HostPostureError::new(
                "invalid_publication_root",
                "publication_root must be the status child of state_root so one writer lock covers both stores",
            ));
        }
        if self.acquisition_interval_ms
            >= QuestionV1::HostFilesystemCapacityPressureV1.frame_validity_ms()
        {
            return Err(HostPostureError::new(
                "invalid_cadence",
                "acquisition cadence must be shorter than the Pulse frame-validity window",
            ));
        }
        self.runtime_bounds
            .validate()
            .map_err(|error| map_error("runtime_config", error))?;
        self.journal_bounds
            .validate()
            .map_err(|error| map_error("journal_config", error))?;
        if self.receiver_id.is_empty() || self.mountpoint_label.is_empty() {
            return Err(HostPostureError::new(
                "invalid_config",
                "receiver identity and mountpoint label must be nonempty",
            ));
        }
        if let Some(qualification) = &self.qualification {
            for (name, path) in [
                ("qualification.corpus_path", &qualification.corpus_path),
                ("qualification.results_path", &qualification.results_path),
            ] {
                if !path.is_absolute() {
                    return Err(HostPostureError::new(
                        "relative_path",
                        format!("{name} must be absolute"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn journal_path(&self) -> PathBuf {
        self.state_root.join("pulse.journal")
    }
    fn intent_dir(&self) -> PathBuf {
        self.state_root.join("intent")
    }
    fn audit_dir(&self) -> PathBuf {
        self.state_root.join("audit")
    }
    fn lock_path(&self) -> PathBuf {
        self.state_root.join("writer.lock")
    }
}

pub struct LinuxBootWitness;

impl SubjectIncarnationWitness for LinuxBootWitness {
    fn current(&self) -> std::result::Result<IncarnationId, CorrespondenceError> {
        let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| CorrespondenceError::new("boot_identity", error.to_string()))?;
        let value = value.trim();
        if value.is_empty() {
            return Err(CorrespondenceError::new(
                "boot_identity",
                "Linux boot identity is empty",
            ));
        }
        Ok(IncarnationId::new(format!("linux-boot:{value}")))
    }
}

#[derive(Clone)]
struct ProcessIdentity {
    receiver_incarnation: IncarnationId,
    clock_id: ClockId,
    epoch_id: IncarnationId,
    activation_id: String,
}

fn fresh_process_identity() -> Result<ProcessIdentity> {
    let mut random = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| map_error("process_identity_randomness", error))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(ProcessIdentity {
        receiver_incarnation: IncarnationId::new(format!(
            "receiver-incarnation:host-posture:{suffix}"
        )),
        clock_id: ClockId::new(format!("clock:host-posture:{suffix}")),
        epoch_id: IncarnationId::new(format!("epoch:host-posture:{suffix}")),
        activation_id: format!("activation:host-posture:{suffix}"),
    })
}

fn load_profile(config: &HostPostureConfig) -> Result<CorrespondenceProfileV1> {
    let bytes = read_regular_bounded(&config.profile_path, MAX_PROFILE_BYTES)
        .map_err(|error| map_error("profile_read", error))?;
    let profile = CorrespondenceProfileV1::decode(&bytes)
        .map_err(|error| map_error("profile_decode", error))?;
    if profile
        .question()
        .map_err(|error| map_error("profile_decode", error))?
        != QuestionV1::HostFilesystemCapacityPressureV1
    {
        return Err(HostPostureError::new(
            "profile_question",
            "runner accepts only the filesystem-capacity-pressure question",
        ));
    }
    if profile.nq.executable_path != config.nq_executable
        || profile.nq.config_path != config.nq_config
        || profile.nq.instance_id != config.enrollment.instance_id
        || profile.pulse.observer_id != config.enrollment.observer_id
        || profile.pulse.consumer_id != config.enrollment.consumer_id
        || profile.pulse.policy_generation != config.enrollment.policy_generation
        || profile.pulse.observation_policy_generation
            != config.enrollment.observation_policy_generation
    {
        return Err(HostPostureError::new(
            "profile_enrollment",
            "profile NQ or Pulse enrollment differs from runner configuration",
        ));
    }
    Ok(profile)
}

fn embedded_source_and_build() -> Result<(SourceIdentityV1, BuildIdentityV1)> {
    for (name, value) in [
        ("source repository", SOURCE_REPOSITORY),
        ("source commit", SOURCE_COMMIT),
        ("source tree digest", SOURCE_TREE_DIGEST),
        ("toolchain identity", TOOLCHAIN_IDENTITY),
        ("target triple", TARGET_TRIPLE),
        ("build profile", BUILD_PROFILE),
        ("enabled features", ENABLED_FEATURES),
        ("Cargo.lock digest", CARGO_LOCK_DIGEST),
    ] {
        if value == UNAVAILABLE {
            return Err(HostPostureError::new(
                "build_identity_unavailable",
                format!("the executable was built without an embedded {name}"),
            ));
        }
    }
    let enabled_features = serde_json::from_str::<Vec<String>>(ENABLED_FEATURES)
        .map_err(|error| map_error("build_identity", error))?;
    let source = SourceIdentityV1 {
        repository_identity: SOURCE_REPOSITORY.to_owned(),
        commit: SOURCE_COMMIT.to_owned(),
        source_tree_digest: DigestV1(SOURCE_TREE_DIGEST.to_owned()),
        dirty: false,
    };
    let build = BuildIdentityV1 {
        toolchain_identity: TOOLCHAIN_IDENTITY.to_owned(),
        target_triple: TARGET_TRIPLE.to_owned(),
        build_profile: BUILD_PROFILE.to_owned(),
        enabled_features,
        runtime_dependencies: vec![RuntimeDependencyIdentityV1 {
            name: "workspace-cargo-lock".to_owned(),
            version: "Cargo.lock-v4".to_owned(),
            source_digest: DigestV1(CARGO_LOCK_DIGEST.to_owned()),
        }],
    };
    Ok((source, build))
}

/// Render the authoring example with the executable's actual embedded build
/// record. An unqualified development build prints explicit `unavailable`
/// values rather than inventing a source identity.
#[must_use]
pub fn example_config() -> String {
    let rendered_features = if ENABLED_FEATURES == UNAVAILABLE {
        "[\"unavailable\"]"
    } else {
        ENABLED_FEATURES
    };
    include_str!("../examples/host-posture.toml")
        .replace("REPLACE_SOURCE_REPOSITORY", SOURCE_REPOSITORY)
        .replace("REPLACE_WITH_CLEAN_40_HEX_COMMIT", SOURCE_COMMIT)
        .replace("REPLACE_SOURCE_TREE_DIGEST", SOURCE_TREE_DIGEST)
        .replace("REPLACE_TOOLCHAIN_IDENTITY", TOOLCHAIN_IDENTITY)
        .replace("REPLACE_TARGET_TRIPLE", TARGET_TRIPLE)
        .replace("REPLACE_BUILD_PROFILE", BUILD_PROFILE)
        .replace("REPLACE_ENABLED_FEATURES_JSON", rendered_features)
        .replace("REPLACE_CARGO_LOCK_DIGEST", CARGO_LOCK_DIGEST)
}

fn emit_runtime_identity(
    phase: &str,
    config: &HostPostureConfig,
    profile: &CorrespondenceProfileV1,
    process: &ProcessIdentity,
) -> Result<()> {
    let config_digest = config.loaded_digest.as_ref().ok_or_else(|| {
        HostPostureError::new(
            "config_identity",
            "configuration has no digest of its exact loaded bytes",
        )
    })?;
    println!(
        "identity phase={phase} pid={} config={} profile={} receiver_incarnation={} clock={} activation={}",
        std::process::id(),
        config_digest,
        profile.digest(),
        process.receiver_incarnation.as_str(),
        process.clock_id.as_str(),
        process.activation_id,
    );
    Ok(())
}

fn runtime_config(config: &HostPostureConfig, process: &ProcessIdentity) -> RuntimeConfigV1 {
    RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new(config.receiver_id.clone()),
        receiver_incarnation: process.receiver_incarnation.clone(),
        clock_id: process.clock_id.clone(),
        transport_custody_policy: None,
        bounds: config.runtime_bounds,
    }
}

struct PackageBytes {
    manifest: Vec<u8>,
    report: Vec<u8>,
    certificate: Vec<u8>,
    acceptance: LocalActivationAcceptanceV1,
}

fn load_package(directory: &Path) -> Result<PackageBytes> {
    let manifest = read_regular_bounded(&directory.join("manifest.json"), MAX_PACKAGE_BYTES)
        .map_err(|error| map_error("qualification_package", error))?;
    QualifiedArtifactManifestV1::decode_canonical(&manifest)
        .map_err(|error| map_error("qualification_package", error))?;
    let report = read_regular_bounded(&directory.join("report.json"), MAX_PACKAGE_BYTES)
        .map_err(|error| map_error("qualification_package", error))?;
    QualificationEvidenceReportV1::decode_canonical(&report)
        .map_err(|error| map_error("qualification_package", error))?;
    let certificate = read_regular_bounded(&directory.join("certificate.json"), MAX_PACKAGE_BYTES)
        .map_err(|error| map_error("qualification_package", error))?;
    QualificationCertificateV1::decode_canonical(&certificate)
        .map_err(|error| map_error("qualification_package", error))?;
    let acceptance_bytes =
        read_regular_bounded(&directory.join("acceptance.json"), MAX_PACKAGE_BYTES)
            .map_err(|error| map_error("qualification_package", error))?;
    let acceptance: LocalActivationAcceptanceV1 = serde_json::from_slice(&acceptance_bytes)
        .map_err(|error| map_error("qualification_package", error))?;
    acceptance
        .validate()
        .map_err(|error| map_error("qualification_package", error))?;
    if canonical_artifact_bytes(&acceptance)
        .map_err(|error| map_error("qualification_package", error))?
        != acceptance_bytes
    {
        return Err(HostPostureError::new(
            "qualification_package",
            "acceptance bytes are not canonical",
        ));
    }
    Ok(PackageBytes {
        manifest,
        report,
        certificate,
        acceptance,
    })
}

fn json_field<'a>(value: &'a Value, pointer: &str) -> Result<&'a Value> {
    value.pointer(pointer).ok_or_else(|| {
        HostPostureError::new(
            "initial_artifact",
            format!("initial NQ artifact has no {pointer}"),
        )
    })
}

fn json_string(value: &Value, pointer: &str) -> Result<String> {
    json_field(value, pointer)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            HostPostureError::new(
                "initial_artifact",
                format!("initial NQ artifact {pointer} is not a string"),
            )
        })
}

fn json_identity(value: &Value, pointer: &str) -> Result<SemanticIdentityV1> {
    serde_json::from_value(json_field(value, pointer)?.clone())
        .map_err(|error| map_error("initial_artifact", error))
}

/// Seal the existing correspondence profile from one retained initial native
/// NQ diagnostic. NQ owns every copied diagnostic identity; the deployment
/// supplies only its Pulse enrollment identities.
pub fn enroll(config: &HostPostureConfig, initial_artifact: &Path) -> Result<String> {
    let bytes = read_regular_bounded(initial_artifact, MAX_NQ_ARTIFACT_BYTES)
        .map_err(|error| map_error("initial_artifact", error))?;
    let artifact: Value =
        serde_json::from_slice(&bytes).map_err(|error| map_error("initial_artifact", error))?;
    let question = QuestionV1::HostFilesystemCapacityPressureV1;
    if json_string(&artifact, "/schema")? != NQ_ARTIFACT_SCHEMA
        || json_identity(&artifact, "/profile")? != question.nq_profile_identity()
        || json_identity(&artifact, "/question")? != question.question_identity()
    {
        return Err(HostPostureError::new(
            "initial_artifact",
            "initial diagnostic does not name the filesystem-capacity question and profile",
        ));
    }
    let profile = CorrespondenceProfileV1::seal_for(
        question,
        NqEnrollmentV1 {
            instance_id: config.enrollment.instance_id.clone(),
            subject_id: json_string(&artifact, "/subject/id")?,
            subject_scope: json_identity(&artifact, "/subject/scope")?,
            vantage: json_identity(&artifact, "/vantage")?,
            profile_semantic_id: json_string(&artifact, "/profile_semantic_id")?,
            threshold_policy: json_identity(&artifact, "/threshold_policy")?,
            evaluator: json_identity(&artifact, "/evaluator")?,
            state_model: json_identity(&artifact, "/state_model")?,
            producer: serde_json::from_value::<NqProducerV1>(
                json_field(&artifact, "/producer")?.clone(),
            )
            .map_err(|error| map_error("initial_artifact", error))?,
            executable_path: config.nq_executable.clone(),
            executable_sha256: sha256_hex_of_file(&config.nq_executable, MAX_NQ_EXECUTABLE_BYTES)
                .map_err(|error| map_error("nq_executable", error))?,
            config_path: config.nq_config.clone(),
            config_sha256: sha256_hex_of_file(&config.nq_config, MAX_NQ_CONFIG_BYTES)
                .map_err(|error| map_error("nq_config", error))?,
        },
        PulseEnrollmentV1 {
            observer_id: config.enrollment.observer_id.clone(),
            consumer_id: config.enrollment.consumer_id.clone(),
            policy_generation: config.enrollment.policy_generation.clone(),
            observation_policy_generation: config.enrollment.observation_policy_generation.clone(),
        },
    )
    .map_err(|error| map_error("profile_enrollment", error))?;
    let profile_bytes =
        serde_jcs::to_vec(&profile).map_err(|error| map_error("profile_enrollment", error))?;
    write_create_new(&config.profile_path, &profile_bytes, 0o640)
        .map_err(|error| map_error("profile_write", error))?;
    Ok(profile.digest().to_owned())
}

fn qualification_inputs(config: &HostPostureConfig) -> Result<LocalQualificationInputsV1> {
    let qualification = config.qualification.as_ref().ok_or_else(|| {
        HostPostureError::new(
            "qualification_config",
            "offline preparation requires the qualification configuration section",
        )
    })?;
    let corpus_bytes = read_regular_bounded(&qualification.corpus_path, MAX_PACKAGE_BYTES)
        .map_err(|error| map_error("qualification_corpus", error))?;
    let corpus = QualificationCorpusArtifactV1::decode_canonical(&corpus_bytes)
        .map_err(|error| map_error("qualification_corpus", error))?;
    let results_bytes = read_regular_bounded(&qualification.results_path, MAX_PACKAGE_BYTES)
        .map_err(|error| map_error("qualification_results", error))?;
    let results = QualificationResultsArtifactV1::decode_canonical(&results_bytes)
        .map_err(|error| map_error("qualification_results", error))?;
    let (embedded_source, embedded_build) = embedded_source_and_build()?;
    if qualification.source != embedded_source || qualification.build != embedded_build {
        return Err(HostPostureError::new(
            "qualification_build_mismatch",
            "qualification source/build does not exactly match the executable's embedded clean-build record",
        ));
    }
    Ok(LocalQualificationInputsV1 {
        source: embedded_source,
        build: embedded_build,
        platform_assumptions: qualification.platform_assumptions.clone(),
        declared_claims: qualification.declared_claims.clone(),
        nonclaims: qualification.nonclaims.clone(),
        supersedes_manifest_digests: qualification.supersedes_manifest_digests.clone(),
        lifecycle_authority_id: qualification.lifecycle_authority_id.clone(),
        corpus_bytes,
        results_bytes,
        command_results: results.command_results,
        hostile_scenarios: corpus.hostile_scenarios,
        total_tests_passed: results.total_tests_passed,
        issuance_id: qualification.issuance_id.clone(),
        issuer_id: qualification.issuer_id.clone(),
    })
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)
        .map_err(|error| map_error("qualification_write", error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| map_error("qualification_write", error))
}

/// Assemble a reusable exact package from retained, canonical, already-run
/// qualification evidence. This command executes no qualification command and
/// cannot turn a declared requirement into a passing observation.
pub fn prepare_qualification(config: &HostPostureConfig, output: &Path) -> Result<String> {
    if !output.is_absolute() {
        return Err(HostPostureError::new(
            "relative_path",
            "qualification output directory must be absolute",
        ));
    }
    let profile = load_profile(config)?;
    let process = fresh_process_identity()?;
    emit_runtime_identity("prepare-qualification", config, &profile, &process)?;
    let runtime_config = runtime_config(config, &process);
    let subject_incarnation = LinuxBootWitness
        .current()
        .map_err(|error| map_error("boot_identity", error))?;
    let registration = profile
        .consumer_registration(subject_incarnation, &process.activation_id)
        .map_err(|error| map_error("registration", error))?;
    let package = build_local_qualification_package(
        &runtime_config,
        &registration,
        qualification_inputs(config)?,
    )
    .map_err(|error| map_error("qualification_prepare", error))?;
    fs::create_dir(output).map_err(|error| map_error("qualification_write", error))?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o700))
        .map_err(|error| map_error("qualification_write", error))?;
    write_new_file(
        &output.join("manifest.json"),
        &package
            .manifest_bytes()
            .map_err(|error| map_error("qualification_prepare", error))?,
    )?;
    write_new_file(
        &output.join("report.json"),
        &package
            .report_bytes()
            .map_err(|error| map_error("qualification_prepare", error))?,
    )?;
    write_new_file(
        &output.join("certificate.json"),
        &package
            .certificate_bytes()
            .map_err(|error| map_error("qualification_prepare", error))?,
    )?;
    write_new_file(
        &output.join("acceptance.json"),
        &canonical_artifact_bytes(&package.acceptance)
            .map_err(|error| map_error("qualification_prepare", error))?,
    )?;
    File::open(output)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| map_error("qualification_write", error))?;
    Ok(package.certificate.certificate_digest.as_str().to_owned())
}

fn validate_private_directory(path: &Path, name: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| map_error("path", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HostPostureError::new(
            "path",
            format!("{name} must be a real directory"),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(HostPostureError::new(
            "path_permissions",
            format!("{name} must not grant group or other permissions"),
        ));
    }
    Ok(())
}

fn validate_service_directory(path: &Path, name: &str, service_uid: u32) -> Result<()> {
    validate_private_directory(path, name)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| map_error("path", error))?;
    if metadata.uid() != service_uid {
        return Err(HostPostureError::new(
            "path_owner",
            format!("{name} must be owned by the configured service uid"),
        ));
    }
    Ok(())
}

fn ensure_service_store_directory(path: &Path, name: &str, service_uid: u32) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|error| map_error("store_directory", error))?;
    }
    validate_service_directory(path, name, service_uid)
}

fn ensure_service_store_directories(config: &HostPostureConfig) -> Result<()> {
    ensure_service_store_directory(&config.intent_dir(), "intent store", config.service_uid)?;
    ensure_service_store_directory(&config.audit_dir(), "audit store", config.service_uid)
}

fn validate_service_readonly_path(
    path: &Path,
    name: &str,
    service_uid: u32,
    directory: bool,
) -> Result<()> {
    let mut current = Some(path);
    let mut leaf = true;
    while let Some(candidate) = current {
        let metadata = fs::symlink_metadata(candidate).map_err(|error| map_error("path", error))?;
        if metadata.file_type().is_symlink()
            || (leaf && directory && !metadata.is_dir())
            || (leaf && !directory && !metadata.is_file())
            || (!leaf && !metadata.is_dir())
        {
            return Err(HostPostureError::new(
                "path",
                format!("{name} and every ancestor must have the expected real file type"),
            ));
        }
        if metadata.uid() == service_uid || metadata.permissions().mode() & 0o022 != 0 {
            return Err(HostPostureError::new(
                "path_permissions",
                format!(
                    "{name} and every ancestor must be owned outside the service uid and not group- or other-writable"
                ),
            ));
        }
        current = candidate.parent();
        leaf = false;
    }
    Ok(())
}

fn validate_installed_custody(config: &HostPostureConfig) -> Result<()> {
    validate_service_readonly_path(
        &config.loaded_from,
        "runner config",
        config.service_uid,
        false,
    )?;
    validate_service_readonly_path(
        &config.profile_path,
        "correspondence profile",
        config.service_uid,
        false,
    )?;
    validate_service_readonly_path(
        &config.nq_executable,
        "NQ executable",
        config.service_uid,
        false,
    )?;
    validate_service_readonly_path(&config.nq_config, "NQ config", config.service_uid, false)?;
    validate_service_readonly_path(
        &config.qualification_package_dir,
        "qualification package directory",
        config.service_uid,
        true,
    )?;
    for name in [
        "manifest.json",
        "report.json",
        "certificate.json",
        "acceptance.json",
    ] {
        validate_service_readonly_path(
            &config.qualification_package_dir.join(name),
            "qualification package file",
            config.service_uid,
            false,
        )?;
    }
    let running_executable = fs::canonicalize("/proc/self/exe")
        .map_err(|error| map_error("running_executable", error))?;
    validate_service_readonly_path(
        &running_executable,
        "running executable",
        config.service_uid,
        false,
    )?;
    Ok(())
}

fn effective_uid() -> Result<u32> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| map_error("process_identity", error))?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| {
            HostPostureError::new("process_identity", "/proc/self/status has no Uid row")
        })?;
    uid_line
        .split_ascii_whitespace()
        .nth(2)
        .ok_or_else(|| HostPostureError::new("process_identity", "Uid row has no effective uid"))?
        .parse::<u32>()
        .map_err(|error| map_error("process_identity", error))
}

fn validate_service_identity(config: &HostPostureConfig) -> Result<()> {
    let effective = effective_uid()?;
    if effective != config.service_uid {
        return Err(HostPostureError::new(
            "process_identity",
            format!(
                "effective uid {effective} differs from configured service uid {}",
                config.service_uid
            ),
        ));
    }
    Ok(())
}

fn count_regular_store_entries(path: &Path, bound: u64, name: &str) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| map_error("store_bound", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HostPostureError::new(
            "store_bound",
            format!("{name} must be a real directory"),
        ));
    }
    let mut count = 0_u64;
    for entry in fs::read_dir(path).map_err(|error| map_error("store_bound", error))? {
        let entry = entry.map_err(|error| map_error("store_bound", error))?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|error| map_error("store_bound", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HostPostureError::new(
                "store_bound",
                format!("{name} contains a non-regular entry"),
            ));
        }
        count = count.saturating_add(1);
        if count > bound {
            return Err(HostPostureError::new(
                "store_bound",
                format!("{name} exceeds its configured aggregate entry bound"),
            ));
        }
    }
    Ok(count)
}

fn validate_store_bounds(config: &HostPostureConfig) -> Result<u64> {
    let intent_count = count_regular_store_entries(
        &config.intent_dir(),
        config.maximum_occurrences,
        "occurrence intent store",
    )?;
    let _ = count_regular_store_entries(
        &config.audit_dir(),
        config.maximum_occurrences,
        "correspondence audit store",
    )?;
    let objects = count_regular_store_entries(
        &config.publication_root.join("objects"),
        config.maximum_publications,
        "publication object store",
    )?;
    let temporary = count_regular_store_entries(
        &config.publication_root.join("tmp"),
        config.maximum_publications,
        "publication temporary store",
    )?;
    if objects.saturating_add(temporary) > config.maximum_publications {
        return Err(HostPostureError::new(
            "store_bound",
            "publication store exceeds its configured aggregate entry bound",
        ));
    }
    Ok(intent_count)
}

fn activate_package(
    runtime: &mut ReceiverSchedulerRuntime,
    registration: &pulse_runtime::ConsumerRegistrationV1,
    package: PackageBytes,
) -> Result<DigestV1> {
    let activation = runtime
        .activate_qualified_binding(
            registration,
            Some(&package.manifest),
            Some(&package.certificate),
            Some(&package.report),
            package.acceptance,
            runtime.current_monotonic_ms(),
        )
        .map_err(|error| map_error("qualification_activation", error))?;
    if activation.receipt.body.state != RuntimeBindingStateV1::QualifiedAndMatched {
        return Err(HostPostureError::new(
            "qualification_activation",
            format!(
                "accepted package remeasurement produced {:?}, not QualifiedAndMatched",
                activation.receipt.body.state
            ),
        ));
    }
    Ok(activation.receipt.receipt_digest)
}

/// Validate every non-mutating installed premise, including a fresh in-memory
/// exact-package activation. No journal, acquisition, or publication is made.
pub fn preflight(config: &HostPostureConfig) -> Result<()> {
    validate_service_identity(config)?;
    validate_service_directory(&config.state_root, "state_root", config.service_uid)?;
    validate_service_directory(
        &config.publication_root,
        "publication_root",
        config.service_uid,
    )?;
    validate_installed_custody(config)?;
    let _lock = StateLock::acquire(&config.lock_path())?;
    ensure_service_store_directories(config)?;
    let _ = validate_store_bounds(config)?;
    let profile = load_profile(config)?;
    PinnedNqExecutable::from_enrollment(&profile.nq).map_err(|error| map_error("nq_pin", error))?;
    let process = fresh_process_identity()?;
    emit_runtime_identity("preflight", config, &profile, &process)?;
    let runtime_config = runtime_config(config, &process);
    let incarnation = LinuxBootWitness
        .current()
        .map_err(|error| map_error("boot_identity", error))?;
    let registration = profile
        .consumer_registration(incarnation, &process.activation_id)
        .map_err(|error| map_error("registration", error))?;
    let mut runtime = ReceiverSchedulerRuntime::new(runtime_config)
        .map_err(|error| map_error("runtime", error))?;
    let activation_receipt = activate_package(
        &mut runtime,
        &registration,
        load_package(&config.qualification_package_dir)?,
    )?;
    println!("activation_receipt={activation_receipt}");
    if config.journal_path().exists() {
        let journal_config = JournalConfigV1 {
            schema_version: SCHEMA_VERSION_V1,
            journal_id: format!("journal:{}", config.receiver_id),
            bounds: config.journal_bounds,
        };
        let report = HistoricalJournal::scan(config.journal_path(), &journal_config)
            .map_err(|error| map_error("journal_recovery", error))?;
        if report.outcome != pulse_runtime::JournalRecoveryOutcomeV1::Clean {
            return Err(HostPostureError::new(
                "journal_recovery",
                format!(
                    "journal is not clean: {:?} {:?}",
                    report.outcome, report.damage
                ),
            ));
        }
        report
            .project_history()
            .map_err(|error| map_error("journal_recovery", error))?;
    }
    Ok(())
}

struct StateLock {
    _file: File,
}

impl StateLock {
    fn acquire(path: &Path) -> Result<Self> {
        if path.exists() {
            let metadata =
                fs::symlink_metadata(path).map_err(|error| map_error("state_lock", error))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(HostPostureError::new(
                    "state_lock",
                    "writer lock path must be a regular file",
                ));
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|error| map_error("state_lock", error))?;
        file.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => HostPostureError::new(
                "concurrent_writer",
                "another runner owns the state directory",
            ),
            TryLockError::Error(error) => map_error("state_lock", error),
        })?;
        Ok(Self { _file: file })
    }
}

fn condition_policy(selector: LiveSupportSelectorV1, mountpoint: &str) -> ProjectionPolicyV1 {
    ProjectionPolicyV1 {
        schema: PROJECTION_POLICY_SCHEMA_V1.to_owned(),
        projection_id: "operator-filesystem-capacity".to_owned(),
        generation: "filesystem-capacity-v1".to_owned(),
        root_component: CONDITION_KEY.to_owned(),
        maximum_age_ms: QuestionV1::HostFilesystemCapacityPressureV1
            .spec()
            .reliance_window_ms,
        admitted_clock_uncertainty_ms: 250,
        timestamp_granularity_ms: 1_000,
        components: vec![ComponentPolicyV1 {
            key: CONDITION_KEY.to_owned(),
            output: Some(OutputComponentV1 {
                id: CONDITION_OUTPUT.to_owned(),
                display_name: operator_component_label(mountpoint),
            }),
            required_facts: vec![FactRequirementV1 {
                fact_id: FACT_ID.to_owned(),
                owner: FACT_OWNER.to_owned(),
                native_schema: CONSEQUENCE_SCHEMA_V1.to_owned(),
                class: SourceFactClassV1::DerivedAdmitted,
                live_support: selector,
            }],
            maintenance_assertion_ids: Vec::new(),
        }],
        dependencies: Vec::new(),
        disclosure: DisclosurePolicyV1 {
            audience: AudienceClassV1::Operator,
            component_fields: vec![
                ComponentOutputFieldV1::DisplayName,
                ComponentOutputFieldV1::State,
                ComponentOutputFieldV1::Mode,
                ComponentOutputFieldV1::Reason,
                ComponentOutputFieldV1::Detail,
            ],
            safe_reasons: recommended_safe_reasons(),
            include_basis_digest: true,
            include_observation_window: false,
        },
    }
}

fn journal_config(config: &HostPostureConfig) -> JournalConfigV1 {
    JournalConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        journal_id: format!("journal:{}", config.receiver_id),
        bounds: config.journal_bounds,
    }
}

fn start_reactor(
    config: &HostPostureConfig,
    profile: &CorrespondenceProfileV1,
    incarnation: IncarnationId,
    process: &ProcessIdentity,
) -> Result<(LocalCrashReactor, DigestV1)> {
    let runtime_config = runtime_config(config, process);
    let registration = profile
        .consumer_registration(incarnation, &process.activation_id)
        .map_err(|error| map_error("registration", error))?;
    let journal_path = config.journal_path();
    let journal_config = journal_config(config);
    let package = load_package(&config.qualification_package_dir)?;
    let (mut runtime, journal) = if journal_path.exists() {
        let (journal, recovery) = HistoricalJournal::open_clean(&journal_path, journal_config)
            .map_err(|error| map_error("journal_recovery", error))?;
        let projection = recovery
            .project_history()
            .map_err(|error| map_error("journal_recovery", error))?;
        let (runtime, _) = ReceiverSchedulerRuntime::recover(
            runtime_config.clone(),
            vec![registration.clone()],
            projection.history,
            0,
        )
        .map_err(|error| map_error("runtime_recovery", error))?;
        (runtime, journal)
    } else {
        let journal = HistoricalJournal::create_new(&journal_path, journal_config)
            .map_err(|error| map_error("journal_create", error))?;
        let runtime = ReceiverSchedulerRuntime::new(runtime_config.clone())
            .map_err(|error| map_error("runtime", error))?;
        (runtime, journal)
    };
    let activation_receipt = activate_package(&mut runtime, &registration, package)?;
    if runtime
        .current_certificate(&profile.subject(), &profile.consumer())
        .is_none()
    {
        runtime
            .register_consumer(registration, runtime.current_monotonic_ms())
            .map_err(|error| map_error("registration", error))?;
    }
    let epoch = MonotonicEpochV1 {
        schema_version: SCHEMA_VERSION_V1,
        epoch_id: process.epoch_id.clone(),
        receiver: runtime_config.receiver,
        receiver_incarnation: runtime_config.receiver_incarnation,
        clock_id: runtime_config.clock_id,
        origin_runtime_monotonic_ms: runtime.current_monotonic_ms(),
        clock_source: "std::time::Instant/process-local".to_owned(),
    };
    let reactor = LocalCrashReactor::start(runtime, journal, epoch, config.reactor)
        .map_err(|error| map_error("reactor_start", error))?;
    reactor
        .wait_until(Duration::from_secs(5), |snapshot| {
            snapshot.condition == ReactorConditionV1::Operational
        })
        .map_err(|error| map_error("reactor_start", error))?;
    Ok((reactor, activation_receipt))
}

fn unix_now_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| map_error("wall_clock", error))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| HostPostureError::new("wall_clock", "Unix millisecond timestamp exceeds u64"))
}

fn publish_projection(
    config: &HostPostureConfig,
    reactor: &LocalCrashReactor,
    policy: &ProjectionPolicyV1,
    verified: Option<&VerifiedCorrespondenceV1>,
    nonce_sequence: u64,
    last_published_unix_ms: &mut u64,
) -> Result<(String, ProjectedStateV1)> {
    let objects = count_regular_store_entries(
        &config.publication_root.join("objects"),
        config.maximum_publications,
        "publication object store",
    )?;
    let temporary = count_regular_store_entries(
        &config.publication_root.join("tmp"),
        config.maximum_publications,
        "publication temporary store",
    )?;
    if objects.saturating_add(temporary) >= config.maximum_publications {
        return Err(HostPostureError::new(
            "publication_capacity",
            "configured aggregate publication capacity is exhausted",
        ));
    }
    let mut facts = Vec::new();
    let mut support = Vec::new();
    let mut details = Vec::new();
    if let Some(verified) = verified {
        facts.push(
            fact_for(verified, policy, CONDITION_KEY)
                .map_err(|error| map_error("consequence", error))?,
        );
        if let Some(detail) = operator_detail(verified, policy, CONDITION_KEY)
            .map_err(|error| map_error("consequence", error))?
        {
            details.push(detail);
        }
        match admit_live(
            verified,
            policy,
            CONDITION_KEY,
            reactor,
            &format!("nonce:host-posture:{nonce_sequence}"),
            config.maximum_trusted_lifetime_ms,
        ) {
            Ok(observation) => support.push(observation),
            Err(error) => eprintln!(
                "projection support unavailable code={} detail={}",
                error.code, error.detail
            ),
        }
    }
    let generated_at = unix_now_ms()?.max(*last_published_unix_ms);
    let moment = ProjectionMomentV1::now(generated_at);
    let artifact = project_with_details(policy, &facts, &support, &[], &details, moment)
        .map_err(|error| map_error("projection", error))?;
    let aggregate_state = artifact.aggregate_state;
    let artifact_id = stage_publication(&config.publication_root, &artifact)
        .map_err(|error| map_error("publication", error))?
        .commit()
        .map_err(|error| map_error("publication", error))?;
    *last_published_unix_ms = generated_at;
    Ok((artifact_id, aggregate_state))
}

fn initial_publication_time(root: &Path) -> Result<u64> {
    match read_current_artifact(root) {
        Ok(artifact) => Ok(artifact.generated_at_unix_ms),
        Err(error) if error.code == "not_found" => Ok(0),
        Err(error) => Err(map_error("publication", error)),
    }
}

/// Run the one installed filesystem-capacity vertical. This process owns the
/// selected NQ successor cadence; deployments must not also run `nqd` for the
/// same watcher obligation.
pub fn run(config: &HostPostureConfig) -> Result<()> {
    validate_service_identity(config)?;
    validate_service_directory(&config.state_root, "state_root", config.service_uid)?;
    validate_service_directory(
        &config.publication_root,
        "publication_root",
        config.service_uid,
    )?;
    validate_installed_custody(config)?;
    let _lock = StateLock::acquire(&config.lock_path())?;
    ensure_service_store_directories(config)?;
    let existing_occurrences = validate_store_bounds(config)?;
    let profile = load_profile(config)?;
    let port = PinnedNqExecutable::from_enrollment(&profile.nq)
        .map_err(|error| map_error("nq_pin", error))?;
    let witness = LinuxBootWitness;
    let incarnation = witness
        .current()
        .map_err(|error| map_error("boot_identity", error))?;
    let process = fresh_process_identity()?;
    emit_runtime_identity("run", config, &profile, &process)?;
    let (reactor, activation_receipt) = start_reactor(config, &profile, incarnation, &process)?;
    println!("activation_receipt={activation_receipt}");
    let selector = live_support_selector(&reactor.snapshot(), &profile.consumer())
        .map_err(|error| map_error("projection_selector", error))?;
    let policy = condition_policy(selector, &config.mountpoint_label);
    policy
        .validate()
        .map_err(|error| map_error("projection_policy", error))?;
    let stopping = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stopping);
    ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))
        .map_err(|error| map_error("signal_handler", error))?;

    let mut last_published = initial_publication_time(&config.publication_root)?;
    let mut nonce_sequence = 1_u64;
    let (initial, initial_state) = publish_projection(
        config,
        &reactor,
        &policy,
        None,
        nonce_sequence,
        &mut last_published,
    )?;
    println!(
        "initial_state={} artifact={initial}",
        initial_state.as_str()
    );
    nonce_sequence = nonce_sequence.saturating_add(1);

    let acquisition_interval = Duration::from_millis(config.acquisition_interval_ms);
    let projection_interval = Duration::from_millis(config.projection_interval_ms);
    let mut next_projection = Instant::now() + projection_interval;
    let mut latest: Option<VerifiedCorrespondenceV1> = None;
    let mut terminal_error: Option<HostPostureError> = None;

    enum AcquisitionMessage {
        Verified {
            sequence: u64,
            state: String,
            record_path: PathBuf,
            value: Box<VerifiedCorrespondenceV1>,
        },
        AuditOnly {
            sequence: u64,
            refusal: String,
        },
        Refused {
            code: &'static str,
            detail: String,
        },
        Exhausted,
        Stopped,
    }

    let worker_result = thread::scope(|scope| -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel::<AcquisitionMessage>(1);
        let worker_stop = Arc::clone(&stopping);
        let intent_dir = config.intent_dir();
        let audit_dir = config.audit_dir();
        let maximum_occurrences = config.maximum_occurrences;
        let worker_profile = &profile;
        let worker_port = &port;
        let worker_witness = &witness;
        let worker_reactor = &reactor;
        let worker = scope.spawn(move || {
            let mut coproducer = match Coproducer::begin(
                worker_profile,
                worker_port,
                worker_witness,
                &intent_dir,
                &audit_dir,
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = sender.send(AcquisitionMessage::Refused {
                        code: error.code,
                        detail: error.detail,
                    });
                    let _ = sender.send(AcquisitionMessage::Stopped);
                    return;
                }
            };
            let mut occurrences = existing_occurrences;
            while !worker_stop.load(Ordering::SeqCst) {
                if occurrences >= maximum_occurrences {
                    let _ = sender.send(AcquisitionMessage::Exhausted);
                    break;
                }
                occurrences = occurrences.saturating_add(1);
                let message = match coproducer.run_occurrence(worker_reactor) {
                    Ok(result) => {
                        let sequence = result.sequence;
                        match result.outcome {
                            OccurrenceOutcomeV1::Verified(value) => AcquisitionMessage::Verified {
                                sequence,
                                state: result.nq_detector_state.as_str().to_owned(),
                                record_path: result.record_path,
                                value,
                            },
                            OccurrenceOutcomeV1::AuditOnly { refusal } => {
                                AcquisitionMessage::AuditOnly {
                                    sequence,
                                    refusal: refusal.to_string(),
                                }
                            }
                        }
                    }
                    Err(error) => AcquisitionMessage::Refused {
                        code: error.code,
                        detail: error.detail,
                    },
                };
                if sender.send(message).is_err() {
                    return;
                }
                let sleep_started = Instant::now();
                while !worker_stop.load(Ordering::SeqCst)
                    && sleep_started.elapsed() < acquisition_interval
                {
                    thread::sleep(
                        acquisition_interval
                            .saturating_sub(sleep_started.elapsed())
                            .min(Duration::from_millis(200)),
                    );
                }
            }
            let _ = sender.send(AcquisitionMessage::Stopped);
        });

        let mut worker_stopped = false;
        let mut loop_error = None;
        while !worker_stopped {
            let wait = next_projection
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(200));
            match receiver.recv_timeout(wait) {
                Ok(AcquisitionMessage::Verified {
                    sequence,
                    state,
                    record_path,
                    value,
                }) => {
                    println!(
                        "occurrence={sequence} state={state} record={}",
                        record_path.display()
                    );
                    latest = Some(*value);
                    next_projection = Instant::now();
                }
                Ok(AcquisitionMessage::AuditOnly { sequence, refusal }) => {
                    eprintln!("occurrence={sequence} audit_only refusal={refusal}");
                }
                Ok(AcquisitionMessage::Refused { code, detail }) => {
                    eprintln!("acquisition_refused code={code} detail={detail}");
                }
                Ok(AcquisitionMessage::Exhausted) => {
                    terminal_error = Some(HostPostureError::new(
                        "occurrence_capacity",
                        "configured occurrence capacity is exhausted",
                    ));
                    stopping.store(true, Ordering::SeqCst);
                }
                Ok(AcquisitionMessage::Stopped) => worker_stopped = true,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => worker_stopped = true,
            }
            if Instant::now() >= next_projection && loop_error.is_none() {
                match publish_projection(
                    config,
                    &reactor,
                    &policy,
                    latest.as_ref(),
                    nonce_sequence,
                    &mut last_published,
                ) {
                    Ok((artifact, state)) => {
                        println!("projection state={} artifact={artifact}", state.as_str())
                    }
                    Err(error) => {
                        loop_error = Some(error);
                        stopping.store(true, Ordering::SeqCst);
                    }
                }
                nonce_sequence = nonce_sequence.saturating_add(1);
                next_projection = Instant::now() + projection_interval;
            }
        }
        worker.join().map_err(|_| {
            HostPostureError::new("acquisition_worker", "acquisition worker panicked")
        })?;
        if let Some(error) = loop_error {
            return Err(error);
        }
        Ok(())
    });
    let primary_error = worker_result.err().or(terminal_error);
    let blindness_result = reactor
        .declare_blindness("host-posture runner is stopping")
        .map_err(|error| map_error("reactor_blindness", error));
    let final_result = publish_projection(
        config,
        &reactor,
        &policy,
        None,
        nonce_sequence,
        &mut last_published,
    );
    if let Ok((artifact, state)) = &final_result {
        println!("final_state={} artifact={artifact}", state.as_str());
    }
    let shutdown_result = match reactor.shutdown() {
        Ok(snapshot) if snapshot.clean_shutdown => Ok(()),
        Ok(_) => Err(HostPostureError::new(
            "reactor_shutdown",
            "reactor did not record a clean shutdown",
        )),
        Err(error) => Err(map_error("reactor_shutdown", error)),
    };
    if let Some(error) = primary_error {
        return Err(error);
    }
    blindness_result?;
    let (final_artifact, final_state) = final_result?;
    if final_state != ProjectedStateV1::Unknown {
        return Err(HostPostureError::new(
            "final_projection",
            format!(
                "terminal publication {final_artifact} projected {}, not unknown",
                final_state.as_str()
            ),
        ));
    }
    shutdown_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_example_decodes_with_the_owner_schema() {
        let rendered = example_config();
        let parsed = toml::from_str::<HostPostureConfig>(&rendered)
            .expect("packaged example must decode as runner configuration");
        parsed
            .validate()
            .expect("packaged example must pass service-local bounds");
        assert_eq!(parsed.maximum_occurrences, 2_048);
        assert_eq!(parsed.maximum_publications, 65_536);
        assert_eq!(parsed.withdrawal_publication_tolerance_ms, 5_000);
        assert_eq!(
            parsed.reactor.journal_durability,
            pulse_runtime::JournalDurabilityModeV1::FileSynced
        );
    }

    #[test]
    fn service_local_custody_and_withdrawal_bounds_fail_closed() {
        let rendered = example_config();
        let baseline = toml::from_str::<HostPostureConfig>(&rendered)
            .expect("packaged example must decode as runner configuration");

        let mut separate_publication = baseline.clone();
        separate_publication.publication_root = PathBuf::from("/var/lib/other-status");
        assert_eq!(
            separate_publication.validate().unwrap_err().code,
            "invalid_publication_root"
        );

        let mut weak_durability = baseline.clone();
        weak_durability.reactor.journal_durability =
            pulse_runtime::JournalDurabilityModeV1::Written;
        assert_eq!(
            weak_durability.validate().unwrap_err().code,
            "invalid_reactor_config"
        );

        let mut delayed_deadline = baseline.clone();
        delayed_deadline.reactor.deliberate_deadline_delay_ms = 1;
        assert_eq!(
            delayed_deadline.validate().unwrap_err().code,
            "invalid_reactor_config"
        );

        let mut late_withdrawal = baseline;
        late_withdrawal.reactor.command_response_timeout_ms = 1_001;
        assert_eq!(
            late_withdrawal.validate().unwrap_err().code,
            "invalid_projection_cadence"
        );
    }

    #[test]
    fn build_probe_never_invents_an_unset_identity() {
        let encoded =
            serde_json::to_value(build_information()).expect("serialize build information");
        for field in [
            "source_repository",
            "source_commit",
            "source_tree_digest",
            "toolchain_identity",
            "target_triple",
            "build_profile",
            "enabled_features_json",
            "cargo_lock_digest",
        ] {
            assert!(encoded[field].is_string());
        }
    }
}
