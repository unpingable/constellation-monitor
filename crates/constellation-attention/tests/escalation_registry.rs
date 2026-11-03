use std::collections::BTreeSet;
use std::process::{Command, Output, Stdio};

use constellation_attention::registry::{RULES, ResponseClass};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema: String,
    anchors: Vec<Anchor>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    rule: String,
    components: Vec<String>,
    response_classes: Vec<String>,
}

fn cli(arguments: &[&str]) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_constellation-attention"))
        .args(arguments)
        .env_clear()
        .env("PATH", "/no/external/programs")
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    output
}

fn exported() -> Registry {
    let output = cli(&["escalation-registry"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn export_covers_every_compiled_rule_and_its_notification_classes() {
    let export = exported();
    assert_eq!(export.schema, "nq.escalation_registry.v1");
    assert_eq!(export.anchors.len(), RULES.len());
    let ids: BTreeSet<_> = export
        .anchors
        .iter()
        .map(|anchor| anchor.rule.as_str())
        .collect();
    assert_eq!(ids, RULES.iter().map(|rule| rule.id).collect());
    for rule in RULES {
        let anchor = export
            .anchors
            .iter()
            .find(|anchor| anchor.rule == rule.id)
            .unwrap();
        if let Some(component) = rule.component {
            assert_eq!(anchor.components, [component], "{}", rule.id);
        } else {
            assert_eq!(
                anchor.components,
                ["estate", "host_posture", "nightshift", "nq"],
                "input faults must cover the actual runtime input components"
            );
        }
        let expected = if rule.response_class == ResponseClass::Page {
            vec!["attention", "page"]
        } else {
            vec!["attention"]
        };
        assert_eq!(anchor.response_classes, expected, "{}", rule.id);
    }
}

#[test]
fn disabled_pages_and_remediation_are_present_without_promoting_notice_rules() {
    let export = exported();
    for rule in RULES.iter().filter(|rule| rule.disabled.is_some()) {
        let anchor = export
            .anchors
            .iter()
            .find(|anchor| anchor.rule == rule.id)
            .unwrap();
        assert!(anchor.response_classes.iter().any(|class| class == "page"));
    }
    let remediation = export
        .anchors
        .iter()
        .find(|anchor| anchor.rule == "remediation-journal-critical")
        .unwrap();
    assert_eq!(remediation.components, ["service"]);
    assert_eq!(remediation.response_classes, ["attention", "page"]);
    // This legacy NQ anchor allows v2 identities, but its actual rule cannot page.
    let disk = export
        .anchors
        .iter()
        .find(|anchor| anchor.rule == "host-disk")
        .unwrap();
    assert_eq!(disk.response_classes, ["attention"]);
    assert!(
        !export
            .anchors
            .iter()
            .any(|anchor| anchor.rule == "build-identity")
    );
}

#[test]
fn export_is_deterministic_without_configuration_environment_or_side_effects() {
    let first = cli(&["escalation-registry"]);
    let second = cli(&["escalation-registry"]);
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
}

#[test]
fn export_refuses_configuration_extra_arguments_and_unknown_commands() {
    for arguments in [
        vec!["escalation-registry", "--config", "/absent/attention.toml"],
        vec!["escalation-registry", "--now", "2026-11-03T12:00:00Z"],
        vec!["escalation-registry", "--dry-run"],
        vec!["escalation-registry", "unexpected"],
        vec!["escalation-registry", "--unknown"],
        vec!["unknown-command"],
    ] {
        let output = cli(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}: {output:?}");
        assert!(!output.stderr.is_empty(), "{arguments:?}: {output:?}");
    }
}
