//! Real CLI/file custody tests with signed substitution fixtures. These do not
//! claim a native filesystem acquisition or operator qualification occurred.
use ed25519_dalek::{Signer as _, SigningKey};
use nq_profiles::host_filesystem as native;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn identify(value: &mut Value, field: &str) {
    let mut preimage = value.clone();
    preimage.as_object_mut().unwrap().remove(field);
    value[field] = json!(digest(&canonical(&preimage)));
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn instant() -> (String, u64) {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let uptime = fs::read_to_string("/proc/uptime").unwrap();
    let (seconds, fraction) = uptime
        .split_whitespace()
        .next()
        .unwrap()
        .split_once('.')
        .unwrap();
    let padded = format!("{fraction:0<3}");
    (
        format!("pulse-linux-boottime:{}", digest(boot.trim().as_bytes())),
        seconds.parse::<u64>().unwrap() * 1000 + padded[..3].parse::<u64>().unwrap(),
    )
}
struct Fixture {
    _temp: tempfile::TempDir,
    binary: PathBuf,
    config: Value,
    path: PathBuf,
    key: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let binary = std::env::var_os("PULSE_FS_TEST_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_pulse-nq-filesystem-support")));
        let probe = Command::new(&binary).arg("--build-info").output().unwrap();
        assert!(probe.status.success());
        let build: Value = serde_json::from_slice(&probe.stdout).unwrap();
        let source=build["source_commit"].as_str().expect("CLI custody qualification requires a truthful committed build; do not invent the old HEAD for WIP");
        let mut config: Value = serde_json::from_str(include_str!(
            "../../../artifacts/nightshift-filesystem-support-v1/config.json"
        ))
        .unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        config["producer_public_key_hex"] = json!(hex(key.verifying_key().as_bytes()));
        config["producer_private_key_path"] = json!(temp.path().join("producer.key"));
        config["outgoing_directory"] = json!(temp.path().join("outgoing"));
        config["receipt_directory"] = json!(temp.path().join("receiver"));
        for name in ["outgoing", "receiver"] {
            let directory = temp.path().join(name);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o2750)).unwrap();
        }
        let key_path = temp.path().join("producer.key");
        fs::write(&key_path, hex(&[7; 32])).unwrap();
        fs::set_permissions(key_path, fs::Permissions::from_mode(0o600)).unwrap();
        config["realization"]["executable_sha256"] = json!(digest(&fs::read(&binary).unwrap()));
        config["realization"]["monitor_source_commit"] = json!(source);
        config["realization"]["monitor_cargo_lock_digest"] = json!(digest(
            &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock")).unwrap()
        ));
        let mut template = config.clone();
        template.as_object_mut().unwrap().remove("realization");
        template
            .as_object_mut()
            .unwrap()
            .remove("expected_diagnostic");
        config["realization"]["configuration_digest"] = json!(digest(&canonical(&template)));
        identify(&mut config["realization"], "realization_id");
        let path = temp.path().join("config.json");
        let x = Self {
            _temp: temp,
            binary,
            config,
            path,
            key,
        };
        x.save();
        x
    }
    fn save(&self) {
        fs::write(&self.path, canonical(&self.config)).unwrap();
    }
    fn path(&self, kind: &str, name: &str) -> PathBuf {
        PathBuf::from(self.config[kind].as_str().unwrap()).join(name)
    }
    fn query(&self) -> Value {
        let mut q: Value = serde_json::from_str(include_str!(
            "../../../artifacts/nightshift-filesystem-support-v1/query.json"
        ))
        .unwrap();
        for field in ["subject_id", "scope_id"] {
            q[field] = self.config[field].clone();
        }
        for field in ["diagnostic_inputs_id", "artifact_ids"] {
            q[field] = self.config["expected_diagnostic"][field].clone();
        }
        identify(&mut q, "query_id");
        q
    }
    fn command(&self, role: &str, query: Option<&Value>) -> Output {
        use std::io::Write as _;
        let mut cmd = Command::new(&self.binary);
        cmd.args([role, "--config"]).arg(&self.path);
        if role == "ingest" {
            cmd.args(["--acquisition-id", "fixture:acquisition"]);
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if let Some(q) = query {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&canonical(q))
                .unwrap();
        } else {
            drop(child.stdin.take());
        }
        child.wait_with_output().unwrap()
    }
    fn support(&self, expected: &str) {
        let out = self.command("resolve", Some(&self.query()));
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["standing"], expected);
    }
    fn envelope(&self, clock: &str, tick: u64) -> Value {
        let scope = self.config["scope"].clone();
        let mut enrollment = self.config.clone();
        enrollment
            .as_object_mut()
            .unwrap()
            .remove("expected_diagnostic");
        let payload = json!({"evidence_basis":{"scope":{"kind":native::SCOPE_KIND,"value":scope},"vantage":self.config["vantage"],"access_path":native::ACCESS_PATH,"basis":"kernel_snapshot","regime":"normal","capabilities_used":native::CAPABILITIES},
            "machine_id":scope["machine_id"],"filesystem_uuid":scope["filesystem_uuid"],"filesystem_type":scope["filesystem_type"],"mountpoint":scope["mountpoint"],"mount_id":1,"device_major":8,"device_minor":1,
            "fsid_hex":native::ext4_fsid_hex(scope["filesystem_uuid"].as_str().unwrap()).unwrap(),"fragment_size":4096,"blocks_total":1000,"blocks_free":500,"blocks_available":500,"inodes_total":1000,"inodes_free":500});
        let mut e = json!({"schema":"pulse.nq_filesystem_capacity_support_evidence.v1","evidence_id":"","acquisition_id":"fixture:acquisition",
            "authority_id":self.config["authority_id"],"consumer_id":self.config["consumer_id"],"producer_id":self.config["producer_id"],"producer_key_id":self.config["producer_key_id"],"subject_id":self.config["subject_id"],"scope_id":self.config["scope_id"],"profile_semantic_id":self.config["profile_semantic_id"],
            "realization_id":self.config["realization"]["realization_id"],"enrollment_id":digest(&canonical(&enrollment)),"diagnostic_inputs_id":self.config["expected_diagnostic"]["diagnostic_inputs_id"],"artifact_ids":self.config["expected_diagnostic"]["artifact_ids"],
            "observation_started":{"clock_id":clock,"tick_ms":tick},"observation_ended":{"clock_id":clock,"tick_ms":tick},"payload":payload,"state":"explicitly_absent"});
        identify(&mut e, "evidence_id");
        let mut message = b"pulse/nq-filesystem-capacity-support/evidence/v1\0".to_vec();
        message.extend(canonical(&e));
        json!({"schema":"pulse.nq_filesystem_capacity_support_envelope.v1","evidence":e,"signature_hex":hex(&self.key.sign(&message).to_bytes())})
    }
    fn send(&self, envelope: &Value) {
        fs::write(
            self.path("outgoing_directory", "current-envelope.json"),
            canonical(envelope),
        )
        .unwrap();
    }
    fn receipt_fixture(&self, clock: &str, tick: u64) {
        let mut receipt = json!({"schema":"pulse.nq_filesystem_capacity_support_receipt.v1","receipt_id":"","envelope":self.envelope(clock,tick),"received_at":{"clock_id":clock,"tick_ms":tick},"expiry_tick_ms":tick+300000});
        identify(&mut receipt, "receipt_id");
        fs::write(
            self.path("receipt_directory", "current-receipt.json"),
            canonical(&receipt),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "requires a truthful committed adapter build and native SDK boot-age preflight; qualification must run explicitly with --ignored"]
fn cli_missing_current_replay_contradiction_and_new_basis_use_real_files() {
    let mut f = Fixture::new();
    f.support("unknown");
    let (clock, tick) = instant();
    f.send(&f.envelope(&clock, tick));
    let intake = f.command("ingest", None);
    assert!(
        intake.status.success(),
        "{}",
        String::from_utf8_lossy(&intake.stderr)
    );
    f.support("current");
    let receipt = f.path("receipt_directory", "current-receipt.json");
    let original = fs::read(&receipt).unwrap();
    assert!(f.command("ingest", None).status.success());
    assert_eq!(
        fs::read(&receipt).unwrap(),
        original,
        "replay renewed receiver custody"
    );
    f.config["expected_diagnostic"]["expected_state"] = json!("present");
    f.save();
    f.support("contradictory");
    f.config["expected_diagnostic"]["diagnostic_inputs_id"] =
        json!(format!("sha256:{}", "d".repeat(64)));
    f.save();
    f.support("unsupported");
    let mut stale = f.query();
    stale["diagnostic_inputs_id"] = json!(format!("sha256:{}", "a".repeat(64)));
    identify(&mut stale, "query_id");
    assert!(!f.command("resolve", Some(&stale)).status.success());
    assert_eq!(fs::read(receipt).unwrap(), original);
}

#[test]
#[ignore = "requires a truthful committed adapter build and native SDK boot-age preflight; qualification must run explicitly with --ignored"]
fn cli_source_expiry_and_previous_boot_do_not_become_current() {
    let f = Fixture::new();
    let (clock, tick) = instant();
    assert!(
        tick > 300010,
        "native SDK preflight must establish boot age above 300010 ms; no silent skip or five-minute live wait"
    );
    f.receipt_fixture(&clock, tick - 300010);
    f.support("expired");
    f.receipt_fixture("fixture:previous-boot", tick);
    f.support("unknown");
}

#[test]
#[ignore = "requires a truthful committed adapter build and native SDK boot-age preflight; qualification must run explicitly with --ignored"]
fn cli_bad_signature_and_equal_acquisition_are_refused() {
    let f = Fixture::new();
    let (clock, tick) = instant();
    let mut envelope = f.envelope(&clock, tick);
    envelope["signature_hex"] = json!("0".repeat(128));
    f.send(&envelope);
    assert!(!f.command("ingest", None).status.success());
    f.send(&f.envelope(&clock, tick));
    assert!(f.command("ingest", None).status.success());
    let receipt = f.path("receipt_directory", "current-receipt.json");
    let original = fs::read(&receipt).unwrap();
    // Same time but distinct signed acquisition cannot supersede existing custody.
    let mut envelope = f.envelope(&clock, tick);
    envelope["evidence"]["acquisition_id"] = json!("fixture:older");
    identify(&mut envelope["evidence"], "evidence_id");
    let mut message = b"pulse/nq-filesystem-capacity-support/evidence/v1\0".to_vec();
    message.extend(canonical(&envelope["evidence"]));
    envelope["signature_hex"] = json!(hex(&f.key.sign(&message).to_bytes()));
    f.send(&envelope);
    // Ask for this occurrence so refusal comes from ordering rather than the ID argument.
    let out = Command::new(&f.binary)
        .arg("ingest")
        .arg("--config")
        .arg(&f.path)
        .args(["--acquisition-id", "fixture:older"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(fs::read(receipt).unwrap(), original);
}

#[test]
#[ignore = "requires a truthful committed adapter build and native SDK boot-age preflight; qualification must run explicitly with --ignored"]
fn same_declared_semantics_wrong_runtime_realization_cannot_establish_current() {
    for field in [
        "executable_sha256",
        "monitor_source_commit",
        "monitor_cargo_lock_digest",
    ] {
        let mut f = Fixture::new();
        let semantic = f.config["profile_semantic_id"].clone();
        f.config["realization"][field] = if field == "monitor_source_commit" {
            json!("f".repeat(40))
        } else {
            json!(format!("sha256:{}", "f".repeat(64)))
        };
        identify(&mut f.config["realization"], "realization_id");
        f.save();
        assert_eq!(f.config["profile_semantic_id"], semantic);
        let (clock, tick) = instant();
        f.send(&f.envelope(&clock, tick));
        let intake = f.command("ingest", None);
        let support = f.command("resolve", Some(&f.query()));
        let current = support.status.success()
            && serde_json::from_slice::<Value>(&support.stdout).unwrap()["standing"] == "current";
        assert!(
            !current,
            "behavioral counterfactual: same semantic ID with wrong {field} established Current"
        );
        assert!(
            !intake.status.success(),
            "wrong {field} created receiver custody"
        );
    }
}
