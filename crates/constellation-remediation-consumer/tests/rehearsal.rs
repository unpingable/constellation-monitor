//! Generation-transition rehearsal against a copy of a real consumer state
//! directory. Ignored unless run explicitly with `CONSUMER_REHEARSAL_STATE_DIR`
//! naming that directory; the source is only ever read.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use common::*;
use constellation_remediation_consumer::run_pass;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn digest(path: &Path) -> (u64, String) {
    let bytes = fs::read(path).unwrap();
    let hex: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (u64::try_from(bytes.len()).unwrap(), hex)
}

fn copy_tree(source: &Path, target: &Path) -> usize {
    fs::create_dir(target).unwrap();
    fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
    let mut files = 0;
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            files += copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), &destination).unwrap();
            files += 1;
        }
    }
    files
}

#[test]
#[ignore = "needs CONSUMER_REHEARSAL_STATE_DIR"]
fn rehearsal_seals_a_copied_state_dir_and_resumes() {
    let Some(source) = std::env::var_os("CONSUMER_REHEARSAL_STATE_DIR") else {
        println!("CONSUMER_REHEARSAL_STATE_DIR unset; nothing rehearsed");
        return;
    };
    let source = Path::new(&source);
    let (journal_bytes, journal_sha) = digest(&source.join("journal.jsonl"));
    let (state_bytes, state_sha) = digest(&source.join("state.json"));
    let source_state = fs::read(source.join("state.json")).unwrap();
    println!("source journal.jsonl bytes={journal_bytes} sha256={journal_sha}");
    println!("source state.json bytes={state_bytes} sha256={state_sha}");

    // The fakes stand in for every external; a clear observation (the
    // evaluator's own word, page not held) makes the pass an idle one, as
    // most of production's passes are.
    let harness = Harness::new();
    harness.write_report(&Report {
        observation: "clear",
        page_deferred: false,
        ..Report::default()
    });
    let state_dir = harness.path("state");
    fs::create_dir(&state_dir).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(
        source.join("journal.jsonl"),
        state_dir.join("journal.jsonl"),
    )
    .unwrap();
    fs::copy(source.join("state.json"), state_dir.join("state.json")).unwrap();
    let episode_files = copy_tree(&source.join("episodes"), &state_dir.join("episodes"));
    let episodes_before = fs::read_dir(state_dir.join("episodes")).unwrap().count();
    println!(
        "copied into fresh 0700 dir: episodes entries={episodes_before} files={episode_files}"
    );

    let clock = || {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    };
    let started = Instant::now();
    let summary = run_pass(&harness.config(), &clock).unwrap();
    let pass_ms = started.elapsed().as_millis();

    let journal = harness.journal();
    println!("whole pass wall ms (includes seal)={pass_ms}");
    let sealed = state_dir.join("journal.sealed.0001.jsonl");
    let (sealed_bytes, sealed_sha) = digest(&sealed);
    println!("sealed segment=journal.sealed.0001.jsonl bytes={sealed_bytes} sha256={sealed_sha}");
    println!(
        "sealed sha256 equals source journal sha256={}",
        sealed_sha == journal_sha
    );
    let sidecar = fs::read_to_string(state_dir.join("journal.sealed.0001.json")).unwrap();
    println!("sidecar journal.sealed.0001.json:\n{sidecar}");
    println!("new journal first record: {}", journal[0]);
    println!(
        "new journal events: {:?}",
        journal
            .iter()
            .map(|record| record["event"].as_str().unwrap_or_default())
            .collect::<Vec<_>>()
    );
    println!("pass summary: {}", summary.to_json());
    let last_pass = fs::read_to_string(state_dir.join("last-pass.json")).unwrap();
    println!("last-pass.json:\n{last_pass}");
    let state_after = fs::read(state_dir.join("state.json")).unwrap();
    println!(
        "state.json identical to source={}",
        state_after == source_state
    );
    println!("external calls reached={}", harness.calls().len());

    assert!(harness.calls().is_empty(), "{:?}", harness.calls());
    assert_eq!(summary.result, "abstained");
    assert_eq!(sealed_bytes, journal_bytes);
    assert_eq!(sealed_sha, journal_sha);
    let sidecar: Value = serde_json::from_str(&sidecar).unwrap();
    assert_eq!(sidecar["sha256"], format!("sha256:{journal_sha}"));
    assert_eq!(sidecar["bytes"], journal_bytes);
    assert_eq!(journal[0]["event"], "journal_sealed");
    assert_eq!(
        journal[0]["detail"]["predecessor"],
        "journal.sealed.0001.jsonl"
    );
    assert_eq!(journal[0]["detail"]["sha256"], sidecar["sha256"]);
    let events: Vec<&str> = journal
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    // An idle pass journals nothing of its own; the first idle pass of a
    // streak never summarizes (the hourly window starts with it).
    assert_eq!(events, ["journal_sealed"]);
    let last_pass: Value = serde_json::from_str(&last_pass).unwrap();
    assert_eq!(last_pass["idle"], true);
    assert_eq!(last_pass["abstain_reason"], "observation_not_present");
    assert_eq!(last_pass["consecutive_idle_passes"], 1);
    assert_eq!(last_pass["sealed_segments"], 1);
    assert_eq!(
        last_pass["journal_bytes"],
        fs::metadata(state_dir.join("journal.jsonl")).unwrap().len()
    );
    assert_eq!(state_after, source_state);
    assert_eq!(
        fs::read_dir(state_dir.join("episodes")).unwrap().count(),
        episodes_before
    );
    // The source was only read.
    assert_eq!(
        digest(&source.join("journal.jsonl")),
        (journal_bytes, journal_sha)
    );
    assert_eq!(digest(&source.join("state.json")), (state_bytes, state_sha));
    println!("source journal.jsonl and state.json sha256 unchanged=true");
}
