//! Incremental publication accounting under the runner's existing writer lock.
//!
//! Namespace events invalidate the initial exact census. Every successful
//! publication reconciles only its own finite namespace changes; event loss or
//! directory replacement refuses rather than trusting an obsolete count.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use constellation_status_projection::{StatusArtifactV1, stage_publication};
use nix::errno::Errno;
use nix::sys::inotify::{AddWatchFlags as Mask, InitFlags, Inotify, InotifyEvent, WatchDescriptor};

use crate::{HostPostureError, Result, StateLock, count_regular_store_entries, map_error};

type EventKey = (WatchDescriptor, String, u32);

pub(super) struct PublicationBudget<'writer> {
    root: PathBuf,
    maximum: u64,
    entries: u64,
    valid: bool,
    watch_lost: bool,
    inotify: Inotify,
    watches: [WatchDescriptor; 3],
    identities: [(u64, u64); 3],
    // A budget cannot outlive the process's exclusive writer custody.
    _writer: &'writer StateLock,
}

fn directory_identity(path: &Path) -> Result<(u64, u64)> {
    let metadata = fs::symlink_metadata(path).map_err(|error| map_error("store_bound", error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HostPostureError::new(
            "store_bound",
            format!(
                "publication path {} must be a real directory",
                path.display()
            ),
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn changed(detail: &str) -> HostPostureError {
    HostPostureError::new("publication_changed", detail)
}

impl<'writer> PublicationBudget<'writer> {
    pub(super) fn new(root: &Path, maximum: u64, writer: &'writer StateLock) -> Result<Self> {
        directory_identity(root)?;
        for name in ["objects", "tmp"] {
            match fs::DirBuilder::new().mode(0o700).create(root.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => return Err(map_error("store_bound", error)),
            }
        }
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)
            .map_err(|error| map_error("publication_watch", error))?;
        let paths = [root.to_owned(), root.join("objects"), root.join("tmp")];
        let identities = [
            directory_identity(&paths[0])?,
            directory_identity(&paths[1])?,
            directory_identity(&paths[2])?,
        ];
        let mask = Mask::IN_CREATE
            | Mask::IN_DELETE
            | Mask::IN_MOVED_FROM
            | Mask::IN_MOVED_TO
            | Mask::IN_DELETE_SELF
            | Mask::IN_MOVE_SELF
            | Mask::IN_ONLYDIR
            | Mask::IN_DONT_FOLLOW;
        let watch = |path: &Path| {
            inotify
                .add_watch(path, mask)
                .map_err(|error| map_error("publication_watch", error))
        };
        let watches = [watch(&paths[0])?, watch(&paths[1])?, watch(&paths[2])?];
        let mut budget = Self {
            root: root.to_owned(),
            maximum,
            entries: 0,
            valid: false,
            watch_lost: false,
            inotify,
            watches,
            identities,
            _writer: writer,
        };
        budget.refresh()?;
        Ok(budget)
    }

    fn verify_directories(&self) -> Result<()> {
        for (index, path) in [
            self.root.clone(),
            self.root.join("objects"),
            self.root.join("tmp"),
        ]
        .iter()
        .enumerate()
        {
            if directory_identity(path)? != self.identities[index] {
                return Err(changed(
                    "publication directory identity changed while writer lock was held",
                ));
            }
        }
        Ok(())
    }

    fn events(&mut self) -> Result<Vec<InotifyEvent>> {
        if self.watch_lost {
            return Err(changed(
                "publication namespace watch previously lost continuity",
            ));
        }
        match self.read_events() {
            Ok(events) => Ok(events),
            Err(error) => {
                self.valid = false;
                self.watch_lost = true;
                Err(error)
            }
        }
    }

    fn read_events(&self) -> Result<Vec<InotifyEvent>> {
        let mut events = Vec::new();
        // Each read is at most 4096 bytes. An unbounded concurrent producer
        // cannot keep this finite projection call draining forever.
        for _ in 0..16 {
            match self.inotify.read_events() {
                Ok(batch) => {
                    for event in batch {
                        if event.mask.intersects(
                            Mask::IN_Q_OVERFLOW
                                | Mask::IN_IGNORED
                                | Mask::IN_UNMOUNT
                                | Mask::IN_DELETE_SELF
                                | Mask::IN_MOVE_SELF,
                        ) {
                            return Err(changed("publication namespace watch lost continuity"));
                        }
                        events.push(event);
                    }
                }
                Err(Errno::EAGAIN) => return Ok(events),
                Err(error) => return Err(map_error("publication_watch", error)),
            }
        }
        Err(changed(
            "publication namespace change batch exceeded its bound",
        ))
    }

    /// Return whether a census was needed. A quiet namespace costs three
    /// directory metadata reads and a nonblocking event read, not a scan.
    pub(super) fn refresh(&mut self) -> Result<bool> {
        self.verify_directories()?;
        let events = self.events()?;
        if self.valid && events.is_empty() {
            return Ok(false);
        }
        self.valid = false;
        let objects = count_regular_store_entries(
            &self.root.join("objects"),
            self.maximum,
            "publication object store",
        )?;
        let temporary = count_regular_store_entries(
            &self.root.join("tmp"),
            self.maximum,
            "publication temporary store",
        )?;
        self.verify_directories()?;
        if !self.events()?.is_empty() {
            return Err(changed(
                "publication directories changed during their census",
            ));
        }
        self.entries = objects.saturating_add(temporary);
        self.valid = true;
        Ok(true)
    }

    pub(super) fn admit(&mut self) -> Result<()> {
        self.refresh()?;
        if self.entries >= self.maximum {
            return Err(HostPostureError::new(
                "publication_capacity",
                "configured aggregate publication capacity is exhausted",
            ));
        }
        Ok(())
    }

    fn reconcile_publication(&mut self, hex: &str, existed: bool) -> Result<()> {
        self.verify_directories()?;
        let events = self.events()?;
        let prefix = format!("{hex}.{}.", std::process::id());
        let candidate = events
            .iter()
            .filter_map(|event| event.name.as_ref()?.to_str())
            .find(|name| name.starts_with(&prefix) && name.ends_with(".candidate"))
            .ok_or_else(|| changed("publication candidate namespace events are missing"))?;
        let sequence = candidate
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(".candidate"))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| changed("publication candidate sequence is not recognized"))?;
        let pointer = format!("CURRENT.{}.{sequence}.candidate", std::process::id());
        let mut expected: BTreeMap<EventKey, usize> = BTreeMap::new();
        for (watch, name, mask) in [
            (self.watches[2], candidate, Mask::IN_CREATE),
            (self.watches[2], candidate, Mask::IN_DELETE),
            (self.watches[2], pointer.as_str(), Mask::IN_CREATE),
            (self.watches[2], pointer.as_str(), Mask::IN_MOVED_FROM),
            (self.watches[0], "CURRENT", Mask::IN_MOVED_TO),
        ] {
            expected.insert((watch, name.to_owned(), mask.bits()), 1);
        }
        if !existed {
            expected.insert(
                (
                    self.watches[1],
                    format!("{hex}.json"),
                    Mask::IN_CREATE.bits(),
                ),
                1,
            );
        }
        let mut observed = BTreeMap::new();
        for event in events {
            let name = event
                .name
                .and_then(|name| name.into_string().ok())
                .ok_or_else(|| changed("publication namespace event has no recognized name"))?;
            *observed
                .entry((event.wd, name, event.mask.bits()))
                .or_insert(0) += 1;
        }
        if observed != expected {
            return Err(changed(
                "publication namespace changed outside this exact commit",
            ));
        }
        Ok(())
    }

    pub(super) fn publish(&mut self, artifact: &StatusArtifactV1) -> Result<String> {
        self.admit()?;
        let hex = artifact
            .artifact_id
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                HostPostureError::new("publication", "artifact has no sha256 identity")
            })?;
        let object = self.root.join("objects").join(format!("{hex}.json"));
        let exists = match fs::symlink_metadata(object) {
            Ok(_) => true, // Staging still checks the exact type and bytes.
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => return Err(map_error("publication", error)),
        };
        // Failed staging can retain an object. Reconstruct before any final
        // withdrawal; a restarted process always performs a new exact census.
        self.valid = false;
        let id = stage_publication(&self.root, artifact)
            .map_err(|error| map_error("publication", error))?
            .commit()
            .map_err(|error| map_error("publication", error))?;
        self.reconcile_publication(hex, exists)?;
        if !exists {
            self.entries = self.entries.saturating_add(1);
        }
        self.valid = true;
        Ok(id)
    }
}
