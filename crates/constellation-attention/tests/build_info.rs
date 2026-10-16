use std::process::{Command, Stdio};

#[test]
fn identity_is_available_without_runtime_environment_or_configuration() {
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
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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
}
