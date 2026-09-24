//! Create-new file writes and bounded regular-file reads.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use crate::{CorrespondenceError, sha256_prefixed};

/// Write bytes to a path that must not already exist, then synchronize the
/// file. An existing path is a refusal, never a replacement.
pub fn write_create_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CorrespondenceError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| {
            CorrespondenceError::new(
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    "already_exists"
                } else {
                    "io"
                },
                format!("{}: {error}", path.display()),
            )
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| CorrespondenceError::new("io", format!("{}: {error}", path.display())))
}

/// Read a non-symlink regular file of at most `maximum` bytes.
pub fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, CorrespondenceError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| CorrespondenceError::new("io", format!("{}: {error}", path.display())))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CorrespondenceError::new(
            "not_regular_file",
            format!("{} must be a non-symlink regular file", path.display()),
        ));
    }
    let limit = u64::try_from(maximum)
        .map_err(|error| CorrespondenceError::new("bound", error.to_string()))?
        .saturating_add(1);
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| CorrespondenceError::new("io", format!("{}: {error}", path.display())))?
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| CorrespondenceError::new("io", format!("{}: {error}", path.display())))?;
    if bytes.len() > maximum {
        return Err(CorrespondenceError::new(
            "bound_exceeded",
            format!("{} exceeds its byte bound", path.display()),
        ));
    }
    Ok(bytes)
}

/// `sha256:<hex>` of a bounded regular file's exact bytes.
pub fn sha256_hex_of_file(path: &Path, maximum: usize) -> Result<String, CorrespondenceError> {
    Ok(sha256_prefixed(&read_regular_bounded(path, maximum)?))
}
