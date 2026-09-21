#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use pulse_project_predicate_support::{
    NqArtifacts, QualifiedSupportReceiptV1, SignedSupportEvidenceV1, SupportPolicyV1, qualify,
    qualify_support_failure, read_json, replay, write_json,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let rest: Vec<String> = args.collect();
    let values = parse_options(&rest)?;
    let policy: SupportPolicyV1 = read_json(required_path(&values, "--policy")?)?;
    let nq = NqArtifacts {
        executable: required_path(&values, "--nq-executable")?,
        receipt: required_path(&values, "--nq-receipt")?,
        inventory: required_path(&values, "--inventory")?,
        catalog: required_path(&values, "--catalog")?,
    };
    let evidence: Option<SignedSupportEvidenceV1> = values
        .get("--support-evidence")
        .map(|path| read_json(Path::new(path)))
        .transpose()?;
    match command.as_str() {
        "qualify" => {
            let at = required(&values, "--at")?;
            let output = required_path(&values, "--output")?;
            let receipt = if let Some(detail) = values.get("--support-failure") {
                if evidence.is_some() {
                    return Err(
                        "support evidence and support failure are mutually exclusive".into(),
                    );
                }
                qualify_support_failure(&policy, nq.receipt, at, detail)?
            } else {
                qualify(&policy, &nq, evidence.as_ref(), at)?
            };
            write_json(output, &receipt)
        }
        "replay" => {
            let prior: QualifiedSupportReceiptV1 = read_json(required_path(&values, "--receipt")?)?;
            let output = required_path(&values, "--output")?;
            let result = replay(&prior, &policy, &nq, evidence.as_ref())?;
            write_json(output, &result)?;
            if !result.matches {
                return Err("Pulse support replay did not reproduce the exact receipt".into());
            }
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn parse_options(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    if args.len() % 2 != 0 {
        return Err(usage());
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !pair[0].starts_with("--") || values.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err("options must be unique --name value pairs".into());
        }
    }
    Ok(values)
}

fn required<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("{name} is required"))
}

fn required_path<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Result<&'a Path, String> {
    Ok(Path::new(required(values, name)?))
}

fn usage() -> String {
    "usage: pulse-project-predicate-support qualify|replay --policy PATH --nq-executable PATH --nq-receipt PATH --inventory PATH --catalog PATH [--support-evidence PATH | --support-failure DETAIL] [--at RFC3339] [--receipt PATH] --output PATH".into()
}
