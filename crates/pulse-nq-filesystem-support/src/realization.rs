//! Deployment-accepted identity of this independent adapter, never NQ execution.
use crate::{
    build_info,
    custody::{object_id, require_digest, require_hex},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{fs, io::Read as _};

pub const REALIZATION_SCHEMA: &str = "pulse.nq_filesystem_capacity_adapter_realization.v1";
pub const NQ_SOURCE_COMMIT: &str = "e7219396ab6c491d45bdd0f1ec17f48edb6aa20e";
include!(concat!(env!("OUT_DIR"), "/filesystem_realization.rs"));

/// Root-controlled qualification pins. Digests identify retained records; they
/// do not establish that a qualification occurred. The acceptance owner checks
/// those records and installs this enrollment outside the runtime writers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRealizationV1 {
    pub schema: String,
    pub realization_id: String,
    pub executable_sha256: String,
    pub monitor_source_commit: String,
    pub monitor_source_tree_digest: String,
    pub monitor_cargo_lock_digest: String,
    pub resolved_dependency_inventory_digest: String,
    pub qualification_receipt_digest: String,
    pub configuration_digest: String,
    pub nq_source_commit: String,
}

impl AdapterRealizationV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != REALIZATION_SCHEMA || self.nq_source_commit != NQ_SOURCE_COMMIT {
            return Err("not the accepted independent filesystem adapter source family".into());
        }
        require_hex("monitor_source_commit", &self.monitor_source_commit, 20)?;
        for (name, value) in [
            ("realization_id", &self.realization_id),
            ("executable_sha256", &self.executable_sha256),
            (
                "monitor_source_tree_digest",
                &self.monitor_source_tree_digest,
            ),
            ("monitor_cargo_lock_digest", &self.monitor_cargo_lock_digest),
            (
                "resolved_dependency_inventory_digest",
                &self.resolved_dependency_inventory_digest,
            ),
            (
                "qualification_receipt_digest",
                &self.qualification_receipt_digest,
            ),
            ("configuration_digest", &self.configuration_digest),
        ] {
            require_digest(name, value)?;
        }
        if object_id(self, "realization_id")? != self.realization_id {
            return Err("filesystem adapter realization preimage differs".into());
        }
        Ok(())
    }

    pub(crate) fn validate_running(
        &self,
        executable: &str,
        source: Option<&str>,
        lock: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if executable != self.executable_sha256
            || source != Some(self.monitor_source_commit.as_str())
            || lock != self.monitor_cargo_lock_digest
        {
            return Err("running filesystem adapter ELF/source/Monitor lock differs from accepted realization".into());
        }
        Ok(())
    }

    pub(crate) fn validate_current_process(&self) -> Result<(), String> {
        // Linux provides the actual running executable inode, including after
        // unlink/replacement of its pathname. Never hash an attacker-selected path.
        let mut file = fs::File::open("/proc/self/exe").map_err(|e| e.to_string())?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        let executable = format!("sha256:{:x}", digest.finalize());
        self.validate_running(
            &executable,
            build_info::SOURCE_COMMIT,
            MONITOR_CARGO_LOCK_DIGEST,
        )
    }
}
