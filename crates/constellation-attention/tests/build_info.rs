use std::process::{Command, Stdio};

fn build_info() -> serde_json::Value {
    let binary = env!("CARGO_BIN_EXE_constellation-attention");
    let output = Command::new(binary)
        .arg("--build-info")
        .env_clear()
        .env("MONITOR_SOURCE_COMMIT", "not-a-runtime-override")
        .current_dir("/")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn identity_is_available_without_runtime_environment_or_configuration() {
    let info = build_info();
    assert_eq!(info["schema"], "constellation.attention_build_info.v1");
    assert_eq!(info["name"], "constellation-attention");
    assert_eq!(info["minimum_nq"], "0.2.2");
    assert_eq!(info["debug_assertions"], cfg!(debug_assertions));
    assert_eq!(
        info["source_commit"],
        option_env!("MONITOR_SOURCE_COMMIT").unwrap_or("unavailable")
    );
    assert_eq!(
        info["build_id"].as_str(),
        option_env!("MONITOR_BUILD_IDENTITY")
    );
    assert!(info["target"].as_str().is_some());
    assert_eq!(
        info["capabilities"],
        serde_json::json!(constellation_attention::build_info::CAPABILITIES)
    );
}

#[test]
fn build_info_matches_v1_golden() {
    let mut info = build_info();
    // Normalize build-specific metadata; keep presence and the rest of the
    // shape, including the complete capability list, under golden comparison.
    for (field, value) in [
        ("source_commit", serde_json::json!("unavailable")),
        ("rustc", serde_json::json!("rustc <toolchain>")),
        ("build_id", serde_json::Value::Null),
        ("target", serde_json::json!("<target>")),
        ("debug_assertions", serde_json::json!(false)),
    ] {
        *info.get_mut(field).unwrap() = value;
    }
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden/build-info-v1.json")).unwrap();
    assert_eq!(info, expected);
}
