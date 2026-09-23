use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

use crate::{CURRENT_POINTER_SCHEMA_V1, ProjectionError, StatusArtifactV1, validate_sha256};

static CANDIDATE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentPointerV1 {
    pub schema: String,
    pub artifact_id: String,
}

pub struct StagedPublication {
    root: PathBuf,
    pointer_path: PathBuf,
    artifact_id: String,
}

impl StagedPublication {
    /// Atomically replaces only the reduced current pointer. The immutable
    /// object was already written, synchronized, and revalidated by staging.
    pub fn commit(self) -> Result<String, ProjectionError> {
        let pointer_bytes = read_bounded_regular(&self.pointer_path, 4096, "staged pointer")?;
        let pointer = decode_pointer(&pointer_bytes)?;
        if pointer.artifact_id != self.artifact_id {
            return Err(ProjectionError::new(
                "pointer_substitution",
                "staged pointer no longer identifies the staged artifact",
            ));
        }
        let artifact = read_object(&self.root, &self.artifact_id)?;
        if artifact.artifact_id != self.artifact_id {
            return Err(ProjectionError::new(
                "object_substitution",
                "immutable object identity changed before commit",
            ));
        }
        match read_current_artifact(&self.root) {
            Ok(current) => {
                if current.projection_id != artifact.projection_id {
                    return Err(ProjectionError::new(
                        "projection_mismatch",
                        "replacement artifact belongs to a different projection",
                    ));
                }
                if artifact.generated_at_unix_ms < current.generated_at_unix_ms {
                    return Err(ProjectionError::new(
                        "stale_replacement",
                        "replacement artifact predates the current artifact",
                    ));
                }
            }
            Err(error) if error.code == "not_found" => {}
            Err(error) => return Err(error),
        }
        fs::rename(&self.pointer_path, self.root.join("CURRENT")).map_err(io_error)?;
        let artifact_id = self.artifact_id.clone();
        sync_directory(&self.root)
            .and_then(|()| sync_directory(&self.root.join("tmp")))
            .map_err(|error| {
                ProjectionError::new(
                    "committed_unsynced",
                    format!("CURRENT changed but directory sync failed: {error}"),
                )
            })?;
        Ok(artifact_id)
    }

    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }
}

impl Drop for StagedPublication {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.pointer_path);
    }
}

/// Write and validate an immutable candidate plus a synchronized replacement
/// pointer, but do not change `CURRENT` until `StagedPublication::commit`.
pub fn stage_publication(
    root: &Path,
    artifact: &StatusArtifactV1,
) -> Result<StagedPublication, ProjectionError> {
    ensure_publish_root(root)?;
    let bytes = artifact.canonical_bytes()?;
    let hex = digest_hex(&artifact.artifact_id)?;
    let sequence = CANDIDATE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let candidate = root.join("tmp").join(format!(
        "{hex}.{}.{}.candidate",
        std::process::id(),
        sequence
    ));
    write_exclusive(&candidate, &bytes)?;
    let candidate_guard = TemporaryPath(candidate.clone());
    let candidate_bytes = read_bounded_regular(&candidate, crate::MAX_ARTIFACT_BYTES, "candidate")?;
    let decoded = StatusArtifactV1::decode_canonical(&candidate_bytes)?;
    if decoded.artifact_id != artifact.artifact_id || candidate_bytes != bytes {
        return Err(ProjectionError::new(
            "candidate_substitution",
            "candidate failed byte-exact validation",
        ));
    }

    let object_path = root.join("objects").join(format!("{hex}.json"));
    match fs::hard_link(&candidate, &object_path) {
        Ok(()) => sync_directory(&root.join("objects"))?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing =
                read_bounded_regular(&object_path, crate::MAX_ARTIFACT_BYTES, "immutable object")?;
            if existing != bytes {
                return Err(ProjectionError::new(
                    "object_conflict",
                    "existing immutable object differs from the candidate",
                ));
            }
            sync_directory(&root.join("objects"))?;
        }
        Err(error) => return Err(io_error(error)),
    }
    drop(candidate_guard);

    let pointer = CurrentPointerV1 {
        schema: CURRENT_POINTER_SCHEMA_V1.to_owned(),
        artifact_id: artifact.artifact_id.clone(),
    };
    let pointer_bytes = serde_jcs::to_vec(&pointer)
        .map_err(|error| ProjectionError::new("encode", error.to_string()))?;
    let pointer_path = root.join("tmp").join(format!(
        "CURRENT.{}.{}.candidate",
        std::process::id(),
        sequence
    ));
    write_exclusive(&pointer_path, &pointer_bytes)?;
    if decode_pointer(&read_bounded_regular(
        &pointer_path,
        4096,
        "staged pointer",
    )?)? != pointer
    {
        return Err(ProjectionError::new(
            "pointer_substitution",
            "staged pointer failed validation",
        ));
    }
    Ok(StagedPublication {
        root: root.to_path_buf(),
        pointer_path,
        artifact_id: artifact.artifact_id.clone(),
    })
}

pub fn read_current_artifact(root: &Path) -> Result<StatusArtifactV1, ProjectionError> {
    validate_existing_directory(root, "publish root")?;
    let pointer_path = root.join("CURRENT");
    let pointer_bytes = match read_bounded_regular(&pointer_path, 4096, "current pointer") {
        Err(error) if error.code == "io" && !pointer_path.exists() => {
            return Err(ProjectionError::new("not_found", "CURRENT does not exist"));
        }
        result => result?,
    };
    let pointer = decode_pointer(&pointer_bytes)?;
    read_object(root, &pointer.artifact_id)
}

fn ensure_publish_root(root: &Path) -> Result<(), ProjectionError> {
    validate_existing_directory(root, "publish root")?;
    let mode = fs::symlink_metadata(root)
        .map_err(io_error)?
        .permissions()
        .mode();
    if mode & 0o022 != 0 {
        return Err(ProjectionError::new(
            "unsafe_publish_root",
            "publish root is group- or other-writable",
        ));
    }
    ensure_child_directory(&root.join("objects"))?;
    ensure_child_directory(&root.join("tmp"))?;
    Ok(())
}

fn ensure_child_directory(path: &Path) -> Result<(), ProjectionError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            validate_existing_directory(path, "publication child directory")?;
        }
        Err(error) => return Err(io_error(error)),
    }
    if fs::symlink_metadata(path)
        .map_err(io_error)?
        .permissions()
        .mode()
        & 0o022
        != 0
    {
        return Err(ProjectionError::new(
            "unsafe_publish_root",
            "publication child directory is group- or other-writable",
        ));
    }
    Ok(())
}

fn validate_existing_directory(path: &Path, name: &str) -> Result<(), ProjectionError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProjectionError::new(
            "invalid_publish_path",
            format!("{name} must be a real directory"),
        ));
    }
    Ok(())
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), ProjectionError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn read_object(root: &Path, artifact_id: &str) -> Result<StatusArtifactV1, ProjectionError> {
    let hex = digest_hex(artifact_id)?;
    let path = root.join("objects").join(format!("{hex}.json"));
    let bytes = read_bounded_regular(&path, crate::MAX_ARTIFACT_BYTES, "current object")?;
    let artifact = StatusArtifactV1::decode_canonical(&bytes)?;
    if artifact.artifact_id != artifact_id {
        return Err(ProjectionError::new(
            "pointer_mismatch",
            "current pointer does not identify the object content",
        ));
    }
    Ok(artifact)
}

fn decode_pointer(bytes: &[u8]) -> Result<CurrentPointerV1, ProjectionError> {
    if bytes.len() > 4096 {
        return Err(ProjectionError::new(
            "pointer_bound",
            "current pointer exceeds its bound",
        ));
    }
    let pointer: CurrentPointerV1 = serde_json::from_slice(bytes)
        .map_err(|error| ProjectionError::new("decode", error.to_string()))?;
    if pointer.schema != CURRENT_POINTER_SCHEMA_V1 {
        return Err(ProjectionError::new(
            "unsupported_schema",
            "current pointer schema",
        ));
    }
    validate_sha256("current artifact id", &pointer.artifact_id)?;
    if serde_jcs::to_vec(&pointer)
        .map_err(|error| ProjectionError::new("encode", error.to_string()))?
        != bytes
    {
        return Err(ProjectionError::new(
            "noncanonical",
            "current pointer is not canonical",
        ));
    }
    Ok(pointer)
}

fn digest_hex(value: &str) -> Result<&str, ProjectionError> {
    validate_sha256("artifact id", value)?;
    Ok(value.trim_start_matches("sha256:"))
}

fn sync_directory(path: &Path) -> Result<(), ProjectionError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

struct TemporaryPath(PathBuf);

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn read_bounded_regular(path: &Path, bound: usize, name: &str) -> Result<Vec<u8>, ProjectionError> {
    let named = fs::symlink_metadata(path).map_err(io_error)?;
    if named.file_type().is_symlink() || !named.is_file() {
        return Err(ProjectionError::new(
            "invalid_publish_path",
            format!("{name} must be a regular file"),
        ));
    }
    let file = File::open(path).map_err(io_error)?;
    let opened = file.metadata().map_err(io_error)?;
    if named.dev() != opened.dev() || named.ino() != opened.ino() {
        return Err(ProjectionError::new(
            "pathname_replacement",
            format!("{name} changed while opening"),
        ));
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(bound).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > bound {
        return Err(ProjectionError::new(
            "input_bound",
            format!("{name} exceeds its byte bound"),
        ));
    }
    Ok(bytes)
}

fn io_error(error: std::io::Error) -> ProjectionError {
    ProjectionError::new("io", error.to_string())
}
