#![forbid(unsafe_code)]
//! Deterministic JSONL replay for hostile present-confidence traces.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use pulse_evaluator::{
    ContradictionResolutionV1, EscalationPolicyV1, EvaluationOutput, Evaluator,
    MonitorCapabilityV1, ReceiverTracker, ReliancePolicyV1,
};
use pulse_l3_bridge::{StubL3Bridge, stub_profile_identity};
use pulse_types::{
    AuthenticationFieldV1, AuthenticationResultV1, BoundedSignalValueV1, BridgeId, ClockId,
    ConsumerId, CoverageDescriptorV1, DiagnosticBoundsV1, EscalationDispositionV1,
    EscalationTriggerClassV1, ExperimentalMetricsV1, IncarnationId, JudgmentCategoryV1,
    JudgmentTransitionV1, MockDiagnosticReceiptV1, ObservationPolicyGenerationId,
    ObservationProfileIdV1, ObserverId, PolicyGenerationId, PulseFrameV1, ReceivedPulseV1,
    ReceiverId, SCHEMA_VERSION_V1, SignalAssessmentV1, SparseDurableEventV1, SubjectId,
    digest_parts,
};
use serde::{Deserialize, Serialize};

pub const DEMO_TRACE: &str = include_str!("../../../traces/demo.jsonl");

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TraceRecordV1 {
    Config {
        #[serde(default)]
        normal_trace: bool,
        #[serde(default = "default_minimum_observers")]
        minimum_observers: u32,
        #[serde(default = "default_required_coverage")]
        required_coverage: Vec<String>,
        #[serde(default)]
        require_verified_authentication: bool,
        #[serde(default)]
        failure_domains: BTreeMap<String, String>,
        #[serde(default = "default_true")]
        auto_bridge: bool,
        #[serde(default = "default_subject_incarnation")]
        initial_subject_incarnation: String,
    },
    Pulse {
        at_ms: u64,
        observer: String,
        observer_incarnation: String,
        #[serde(default = "default_subject_incarnation")]
        subject_incarnation: String,
        sequence: u64,
        #[serde(default = "default_validity_ms")]
        validity_ms: u64,
        #[serde(default = "default_required_coverage")]
        observed_coverage: Vec<String>,
        #[serde(default = "default_assessment")]
        load: TraceAssessmentV1,
        #[serde(default = "default_load_value")]
        load_value: f64,
        #[serde(default = "default_assessment")]
        memory: TraceAssessmentV1,
        #[serde(default = "default_memory_value")]
        memory_value: f64,
        #[serde(default = "default_authentication")]
        authentication: TraceAuthenticationV1,
        #[serde(default = "default_transport")]
        transport: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport_delay_ms: Option<u64>,
    },
    Tick {
        at_ms: u64,
    },
    Fault {
        at_ms: u64,
        #[serde(default)]
        label: String,
    },
    Monitor {
        at_ms: u64,
        state: TraceMonitorStateV1,
        detail: String,
        #[serde(default)]
        dropped_inputs: u64,
    },
    ResolveAll {
        at_ms: u64,
        resolver: String,
        rule: String,
        explanation: String,
    },
    BridgeAvailable {
        at_ms: u64,
        available: bool,
    },
    Note {
        at_ms: u64,
        text: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TraceAssessmentV1 {
    Observed,
    Within,
    Outside,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TraceAuthenticationV1 {
    Verified,
    Unauthenticated,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TraceMonitorStateV1 {
    Operational,
    Degraded,
    Blind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayTransitionV1 {
    pub transition: JudgmentTransitionV1,
    pub category: JudgmentCategoryV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub positive_support_expires_at_monotonic_ms: Option<u64>,
    pub summary: String,
    pub reason_codes: Vec<String>,
    pub active_coverage: Vec<String>,
    pub missing_coverage: Vec<String>,
    pub dimensions: pulse_types::ConfidenceDimensionsV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayReportV1 {
    pub schema_version: u16,
    pub transitions: Vec<ReplayTransitionV1>,
    pub escalation_dispositions: Vec<EscalationDispositionV1>,
    pub diagnostic_receipts: Vec<MockDiagnosticReceiptV1>,
    pub final_judgment: pulse_types::PresentStateJudgmentV1,
    pub metrics: ExperimentalMetricsV1,
    pub sparse_events: Vec<SparseDurableEventV1>,
    pub terminal_lines: Vec<String>,
}

#[derive(Clone, Debug)]
struct ReplayConfig {
    normal_trace: bool,
    minimum_observers: u32,
    required_coverage: Vec<String>,
    require_verified_authentication: bool,
    failure_domains: BTreeMap<String, String>,
    auto_bridge: bool,
    initial_subject_incarnation: String,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            normal_trace: false,
            minimum_observers: default_minimum_observers(),
            required_coverage: default_required_coverage(),
            require_verified_authentication: false,
            failure_domains: BTreeMap::new(),
            auto_bridge: true,
            initial_subject_incarnation: default_subject_incarnation(),
        }
    }
}

pub fn parse_jsonl(input: &str) -> Result<Vec<TraceRecordV1>, ReplayError> {
    let mut records = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let record = serde_json::from_str(line).map_err(|error| {
            ReplayError::new(format!("line {} is invalid JSONL: {error}", index + 1))
        })?;
        records.push(record);
    }
    if records.is_empty() {
        return Err(ReplayError::new("trace contains no records"));
    }
    Ok(records)
}

pub fn run_jsonl(input: &str) -> Result<ReplayReportV1, ReplayError> {
    run_records(parse_jsonl(input)?)
}

pub fn run_records(records: Vec<TraceRecordV1>) -> Result<ReplayReportV1, ReplayError> {
    let (config, records) = extract_config(records)?;
    let profile = trace_profile_identity();
    let escalation_triggers = [
        EscalationTriggerClassV1::FreshnessLost,
        EscalationTriggerClassV1::CoverageCollapse,
        EscalationTriggerClassV1::ObserverDisagreement,
        EscalationTriggerClassV1::ContradictionRetained,
        EscalationTriggerClassV1::SubjectBoundViolated,
        EscalationTriggerClassV1::ProvenanceFailed,
        EscalationTriggerClassV1::TransportBlind,
        EscalationTriggerClassV1::SequenceDiscontinuity,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let policy = ReliancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new("subject:demo-host"),
        scope: "host".to_owned(),
        consumer: ConsumerId::new("consumer:capacity-display/v1"),
        generation: PolicyGenerationId::new("policy:demo-v1"),
        observation_policy_generation: ObservationPolicyGenerationId::new("policy:demo-v1"),
        observation_profile: profile.clone(),
        required_coverage: config.required_coverage.clone(),
        minimum_observers: config.minimum_observers,
        maximum_validity_ms: 10_000,
        require_verified_authentication: config.require_verified_authentication,
        coherence_tolerances: BTreeMap::from([("load_ratio".to_owned(), 0.20)]),
        observer_failure_domains: config.failure_domains,
        escalation: Some(EscalationPolicyV1 {
            triggers: escalation_triggers,
            diagnostic_profile: stub_profile_identity(),
            bounds: DiagnosticBoundsV1 {
                maximum_runtime_ms: 25,
                maximum_output_bytes: 1_024,
                maximum_observations: 4,
            },
            request_ttl_ms: 200,
        }),
    };
    let receiver_id = ReceiverId::new("receiver:replay-v1");
    let receiver_incarnation = IncarnationId::new("receiver-incarnation:replay-v1");
    let clock_id = ClockId::new("clock:replay-v1");
    let mut receiver = ReceiverTracker::new(
        receiver_id.clone(),
        receiver_incarnation.clone(),
        clock_id.clone(),
    );
    let mut evaluator = Evaluator::new(
        policy,
        receiver_id,
        receiver_incarnation,
        clock_id.clone(),
        IncarnationId::new(config.initial_subject_incarnation),
    )
    .map_err(|error| ReplayError::new(error.to_string()))?;
    evaluator.set_normal_trace(config.normal_trace);
    let mut bridge = StubL3Bridge::new(BridgeId::new("bridge:replay-stub-v1"), clock_id);
    let mut collector = ReplayCollector::default();
    let mut last_at = 0_u64;

    for record in records {
        match record {
            TraceRecordV1::Config { .. } => {
                return Err(ReplayError::new(
                    "config must appear at most once and before every trace event",
                ));
            }
            TraceRecordV1::Pulse {
                at_ms,
                observer,
                observer_incarnation,
                subject_incarnation,
                sequence,
                validity_ms,
                mut observed_coverage,
                load,
                load_value,
                memory,
                memory_value,
                authentication,
                transport,
                transport_delay_ms,
            } => {
                require_nondecreasing_time(last_at, at_ms)?;
                last_at = at_ms;
                observed_coverage.sort();
                observed_coverage.dedup();
                let frame = trace_frame(
                    &profile,
                    at_ms,
                    observer,
                    observer_incarnation,
                    subject_incarnation,
                    sequence,
                    validity_ms,
                    &observed_coverage,
                    load,
                    load_value,
                    memory,
                    memory_value,
                    authentication,
                );
                let annotation = receiver
                    .annotate(
                        &frame,
                        at_ms,
                        transport,
                        transport_delay_ms,
                        authentication_result(authentication),
                    )
                    .map_err(|error| ReplayError::new(error.to_string()))?;
                let output = evaluator
                    .ingest(
                        ReceivedPulseV1 {
                            frame,
                            receiver: annotation,
                        },
                        at_ms,
                    )
                    .map_err(|error| ReplayError::new(error.to_string()))?;
                collect_with_bridge(
                    output,
                    at_ms,
                    config.auto_bridge,
                    &mut evaluator,
                    &mut bridge,
                    &mut collector,
                )?;
            }
            TraceRecordV1::Tick { at_ms } => {
                require_nondecreasing_time(last_at, at_ms)?;
                last_at = at_ms;
                let output = evaluator
                    .tick(at_ms)
                    .map_err(|error| ReplayError::new(error.to_string()))?;
                collect_with_bridge(
                    output,
                    at_ms,
                    config.auto_bridge,
                    &mut evaluator,
                    &mut bridge,
                    &mut collector,
                )?;
            }
            TraceRecordV1::Fault { at_ms, label } => {
                require_nondecreasing_time(last_at, at_ms)?;
                last_at = at_ms;
                evaluator.mark_failure_start(at_ms);
                collector.terminal_lines.push(format!(
                    "[{at_ms:06}ms] FAULT marker={} (experiment timing basis only)",
                    if label.is_empty() { "unnamed" } else { &label }
                ));
            }
            TraceRecordV1::Monitor {
                at_ms,
                state,
                detail,
                dropped_inputs,
            } => {
                require_nondecreasing_time(last_at, at_ms)?;
                last_at = at_ms;
                let output = if dropped_inputs > 0 {
                    evaluator.record_monitor_input_drop(dropped_inputs, at_ms, detail)
                } else {
                    evaluator.set_monitor_capability(
                        match state {
                            TraceMonitorStateV1::Operational => MonitorCapabilityV1::Operational,
                            TraceMonitorStateV1::Degraded => {
                                MonitorCapabilityV1::Degraded { detail }
                            }
                            TraceMonitorStateV1::Blind => MonitorCapabilityV1::Blind { detail },
                        },
                        at_ms,
                    )
                }
                .map_err(|error| ReplayError::new(error.to_string()))?;
                collect_with_bridge(
                    output,
                    at_ms,
                    config.auto_bridge,
                    &mut evaluator,
                    &mut bridge,
                    &mut collector,
                )?;
            }
            TraceRecordV1::ResolveAll {
                at_ms,
                resolver,
                rule,
                explanation,
            } => {
                require_nondecreasing_time(last_at, at_ms)?;
                last_at = at_ms;
                let ids: Vec<_> = evaluator
                    .contradictions()
                    .into_iter()
                    .filter(|record| record.is_active())
                    .map(|record| record.contradiction_id.clone())
                    .collect();
                for id in ids {
                    let output = evaluator
                        .resolve_contradiction(
                            &id,
                            ContradictionResolutionV1 {
                                resolver: resolver.clone(),
                                rule: rule.clone(),
                                explanation: explanation.clone(),
                            },
                            at_ms,
                        )
                        .map_err(|error| ReplayError::new(error.to_string()))?;
                    collect_with_bridge(
                        output,
                        at_ms,
                        config.auto_bridge,
                        &mut evaluator,
                        &mut bridge,
                        &mut collector,
                    )?;
                }
            }
            TraceRecordV1::BridgeAvailable { at_ms, available } => {
                require_nondecreasing_time(last_at, at_ms)?;
                last_at = at_ms;
                bridge.set_available(available);
                collector
                    .terminal_lines
                    .push(format!("[{at_ms:06}ms] BRIDGE availability={available}"));
            }
            TraceRecordV1::Note { at_ms, text } => {
                require_nondecreasing_time(last_at, at_ms)?;
                last_at = at_ms;
                collector
                    .terminal_lines
                    .push(format!("[{at_ms:06}ms] NOTE {text}"));
            }
        }
    }
    let final_output = evaluator
        .tick(last_at)
        .map_err(|error| ReplayError::new(error.to_string()))?;
    collector.collect_output(&final_output);
    let final_judgment = final_output.judgment;
    if !collector.diagnostic_receipts.is_empty()
        && final_judgment.category != JudgmentCategoryV1::Current
    {
        collector.terminal_lines.push(format!(
            "[{last_at:06}ms] CAUTION diagnostic receipt correlated; judgment remains {}",
            final_judgment.category,
        ));
    }
    collector.terminal_lines.push(format!(
        "[{last_at:06}ms] METRICS max_stale_positive={}ms pulse_to_eval={}ms failure_to_unknown={} failure_to_contradicted={} failure_to_escalation={} false_escalation={} active_coverage={} expired_coverage={} stale_drop={} duplicate={} gap={} escalation_dedup={}",
        evaluator.metrics().maximum_stale_positive_duration_ms,
        evaluator.metrics().pulse_to_evaluation_latency_ms,
        metric_duration(evaluator.metrics().failure_to_unknown_latency_ms),
        metric_duration(evaluator.metrics().failure_to_contradicted_latency_ms),
        metric_duration(evaluator.metrics().failure_to_escalation_latency_ms),
        evaluator.metrics().false_escalation_count,
        evaluator.metrics().active_coverage,
        evaluator.metrics().expired_coverage,
        evaluator.metrics().dropped_stale_pulse_count,
        evaluator.metrics().duplicate_count,
        evaluator.metrics().sequence_gap_count,
        evaluator.metrics().escalation_deduplication_count,
    ));
    Ok(ReplayReportV1 {
        schema_version: SCHEMA_VERSION_V1,
        transitions: collector.transitions,
        escalation_dispositions: collector.escalation_dispositions,
        diagnostic_receipts: collector.diagnostic_receipts,
        final_judgment,
        metrics: evaluator.metrics().clone(),
        sparse_events: evaluator.event_log().to_vec(),
        terminal_lines: collector.terminal_lines,
    })
}

#[derive(Default)]
struct ReplayCollector {
    transitions: Vec<ReplayTransitionV1>,
    escalation_dispositions: Vec<EscalationDispositionV1>,
    diagnostic_receipts: Vec<MockDiagnosticReceiptV1>,
    terminal_lines: Vec<String>,
}

impl ReplayCollector {
    fn collect_output(&mut self, output: &EvaluationOutput) {
        if let Some(transition) = &output.transition {
            let reason_codes = output
                .judgment
                .explanation
                .reasons
                .iter()
                .map(|reason| reason.code.clone())
                .collect::<Vec<_>>();
            self.terminal_lines.push(format!(
                "[{:06}ms] JUDGMENT {} -> {} coverage={}/{} missing=[{}] support_expires={} freshness={:?} continuity={:?} availability={:?} coherence={:?} coverage_state={:?} provenance={:?} transport={:?} signals={:?} reasons=[{}]",
                transition.at_monotonic_ms,
                transition
                    .from
                    .map_or("NONE", pulse_types::JudgmentCategoryV1::as_str),
                transition.to,
                output.judgment.coverage.active.len(),
                output.judgment.coverage.required.len(),
                output.judgment.coverage.missing.join(","),
                support_deadline(output.judgment.positive_support_expires_at_monotonic_ms),
                output.judgment.dimensions.freshness,
                output.judgment.dimensions.sequence_continuity,
                output.judgment.dimensions.observer_availability,
                output.judgment.dimensions.cross_observer_coherence,
                output.judgment.dimensions.coverage,
                output.judgment.dimensions.provenance,
                output.judgment.dimensions.transport,
                output.judgment.dimensions.subject_signal_consistency,
                reason_codes.join(","),
            ));
            self.transitions.push(ReplayTransitionV1 {
                transition: transition.clone(),
                category: output.judgment.category,
                positive_support_expires_at_monotonic_ms: output
                    .judgment
                    .positive_support_expires_at_monotonic_ms,
                summary: output.judgment.explanation.summary.clone(),
                reason_codes,
                active_coverage: output.judgment.coverage.active.clone(),
                missing_coverage: output.judgment.coverage.missing.clone(),
                dimensions: output.judgment.dimensions.clone(),
            });
        }
    }
}

fn collect_with_bridge(
    output: EvaluationOutput,
    at_ms: u64,
    auto_bridge: bool,
    evaluator: &mut Evaluator,
    bridge: &mut StubL3Bridge,
    collector: &mut ReplayCollector,
) -> Result<(), ReplayError> {
    collector.collect_output(&output);
    let Some(request) = output.escalation_request else {
        return Ok(());
    };
    collector.terminal_lines.push(format!(
        "[{at_ms:06}ms] ESCALATION request={} trigger={} profile={}/{} expires={}ms bounds={:?}",
        request.request_id,
        request.trigger_class.as_str(),
        request.diagnostic_profile.name,
        request.diagnostic_profile.version,
        request.expires_at_monotonic_ms,
        request.bounds,
    ));
    if !auto_bridge {
        return Ok(());
    }
    let bridge_at = at_ms.saturating_add(1);
    let outcome = bridge.handle(&request, bridge_at);
    collector.terminal_lines.push(format!(
        "[{bridge_at:06}ms] BRIDGE request={} decision={}",
        request.request_id,
        disposition_name(&outcome.disposition)
    ));
    collector
        .escalation_dispositions
        .push(outcome.disposition.clone());
    let disposition_output = evaluator
        .record_escalation_disposition(outcome.disposition, bridge_at)
        .map_err(|error| ReplayError::new(error.to_string()))?;
    collector.collect_output(&disposition_output);
    if let Some(receipt) = outcome.receipt {
        let receipt_at = receipt.completed_at_monotonic_ms;
        collector.terminal_lines.push(format!(
            "[{receipt_at:06}ms] DIAGNOSTIC receipt={} run={} status={:?} result={} nonclaim=does-not-establish-health",
            receipt.receipt_id, receipt.run_id, receipt.status, receipt.result_digest
        ));
        collector.diagnostic_receipts.push(receipt.clone());
        let receipt_output = evaluator
            .record_diagnostic_receipt(receipt, receipt_at)
            .map_err(|error| ReplayError::new(error.to_string()))?;
        collector.collect_output(&receipt_output);
    }
    Ok(())
}

fn extract_config(
    mut records: Vec<TraceRecordV1>,
) -> Result<(ReplayConfig, Vec<TraceRecordV1>), ReplayError> {
    if !matches!(records.first(), Some(TraceRecordV1::Config { .. })) {
        return Ok((ReplayConfig::default(), records));
    }
    let record = records.remove(0);
    let TraceRecordV1::Config {
        normal_trace,
        minimum_observers,
        mut required_coverage,
        require_verified_authentication,
        failure_domains,
        auto_bridge,
        initial_subject_incarnation,
    } = record
    else {
        unreachable!("first record was checked as config")
    };
    required_coverage.sort();
    required_coverage.dedup();
    if minimum_observers == 0 || required_coverage.is_empty() {
        return Err(ReplayError::new(
            "config requires nonzero observers and nonempty coverage",
        ));
    }
    Ok((
        ReplayConfig {
            normal_trace,
            minimum_observers,
            required_coverage,
            require_verified_authentication,
            failure_domains,
            auto_bridge,
            initial_subject_incarnation,
        },
        records,
    ))
}

#[allow(clippy::too_many_arguments)]
fn trace_frame(
    profile: &ObservationProfileIdV1,
    at_ms: u64,
    observer: String,
    observer_incarnation: String,
    subject_incarnation: String,
    sequence: u64,
    validity_ms: u64,
    observed_coverage: &[String],
    load: TraceAssessmentV1,
    load_value: f64,
    memory: TraceAssessmentV1,
    memory_value: f64,
    authentication: TraceAuthenticationV1,
) -> PulseFrameV1 {
    let mut signals = Vec::new();
    if observed_coverage
        .binary_search_by(|tag| tag.as_str().cmp("load"))
        .is_ok()
    {
        signals.push(BoundedSignalValueV1 {
            name: "load_ratio".to_owned(),
            value: load_value,
            unit: "ratio".to_owned(),
            assessment: assessment(load),
        });
    }
    if observed_coverage
        .binary_search_by(|tag| tag.as_str().cmp("memory"))
        .is_ok()
    {
        signals.push(BoundedSignalValueV1 {
            name: "memory_available_ratio".to_owned(),
            value: memory_value,
            unit: "ratio".to_owned(),
            assessment: assessment(memory),
        });
    }
    PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new("subject:demo-host"),
        subject_incarnation: IncarnationId::new(subject_incarnation),
        observer: ObserverId::new(observer),
        observer_incarnation: IncarnationId::new(observer_incarnation),
        sequence,
        observer_monotonic_ns: at_ms.saturating_mul(1_000_000),
        validity_ms,
        profile: profile.clone(),
        observation_policy_generation: ObservationPolicyGenerationId::new("policy:demo-v1"),
        coverage: CoverageDescriptorV1 {
            expected: default_required_coverage(),
            observed: observed_coverage.to_vec(),
        },
        signals,
        observation_digest: digest_parts("unsealed", &[]),
        authentication: match authentication {
            TraceAuthenticationV1::Verified => AuthenticationFieldV1::Mac {
                scheme: "trace-fixture".to_owned(),
                key_id: "fixture-key".to_owned(),
                tag: "fixture-tag-not-cryptographic".to_owned(),
            },
            TraceAuthenticationV1::Unauthenticated | TraceAuthenticationV1::Failed => {
                AuthenticationFieldV1::Placeholder {
                    disclosure: "trace fixture has no authentication".to_owned(),
                }
            }
        },
    }
    .seal()
}

fn assessment(value: TraceAssessmentV1) -> SignalAssessmentV1 {
    match value {
        TraceAssessmentV1::Observed => SignalAssessmentV1::Observed,
        TraceAssessmentV1::Within => SignalAssessmentV1::WithinDeclaredBound,
        TraceAssessmentV1::Outside => SignalAssessmentV1::OutsideDeclaredBound,
        TraceAssessmentV1::Unavailable => SignalAssessmentV1::Unavailable,
    }
}

fn authentication_result(value: TraceAuthenticationV1) -> AuthenticationResultV1 {
    match value {
        TraceAuthenticationV1::Verified => AuthenticationResultV1::Verified {
            method: "trace-fixture".to_owned(),
            principal: "fixture-observer".to_owned(),
        },
        TraceAuthenticationV1::Unauthenticated => AuthenticationResultV1::Unauthenticated {
            disclosure: "trace fixture is unauthenticated".to_owned(),
        },
        TraceAuthenticationV1::Failed => AuthenticationResultV1::Failed {
            reason: "trace fixture requested authentication failure".to_owned(),
        },
    }
}

fn trace_profile_identity() -> ObservationProfileIdV1 {
    ObservationProfileIdV1 {
        name: "synthetic.present".to_owned(),
        version: 1,
        semantic_digest: digest_parts("observation.profile.v1", &[b"synthetic.present", b"1"]),
    }
}

fn disposition_name(disposition: &EscalationDispositionV1) -> &'static str {
    match disposition.kind {
        pulse_types::EscalationDispositionKindV1::Accept { .. } => "accept",
        pulse_types::EscalationDispositionKindV1::Refuse { .. } => "refuse",
        pulse_types::EscalationDispositionKindV1::Narrow { .. } => "narrow",
        pulse_types::EscalationDispositionKindV1::Defer { .. } => "defer",
    }
}

fn metric_duration(value: Option<u64>) -> String {
    value.map_or_else(|| "not-measured".to_owned(), |value| format!("{value}ms"))
}

fn support_deadline(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| format!("{value}ms"))
}

fn require_nondecreasing_time(prior: u64, current: u64) -> Result<(), ReplayError> {
    if current < prior {
        return Err(ReplayError::new(format!(
            "trace time regressed from {prior} to {current}"
        )));
    }
    Ok(())
}

const fn default_minimum_observers() -> u32 {
    2
}

fn default_required_coverage() -> Vec<String> {
    vec!["load".to_owned(), "memory".to_owned()]
}

const fn default_true() -> bool {
    true
}

fn default_subject_incarnation() -> String {
    "subject-incarnation:1".to_owned()
}

const fn default_validity_ms() -> u64 {
    100
}

const fn default_assessment() -> TraceAssessmentV1 {
    TraceAssessmentV1::Within
}

const fn default_load_value() -> f64 {
    0.25
}

const fn default_memory_value() -> f64 {
    0.70
}

const fn default_authentication() -> TraceAuthenticationV1 {
    TraceAuthenticationV1::Verified
}

fn default_transport() -> String {
    "replay:local".to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayError {
    detail: String,
}

impl ReplayError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for ReplayError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_is_deterministic_and_remains_cautious_after_receipt() {
        let first = run_jsonl(DEMO_TRACE).expect("first replay");
        let second = run_jsonl(DEMO_TRACE).expect("second replay");
        assert_eq!(first, second);
        assert_eq!(
            first.final_judgment.category,
            JudgmentCategoryV1::Contradicted
        );
        assert_eq!(first.diagnostic_receipts.len(), 1);
        assert!(!first.final_judgment.grants_mutation_authority());
    }

    #[test]
    fn malformed_and_time_regressing_traces_are_refused() {
        assert!(run_jsonl("not-json").is_err());
        let trace = r#"
{"event":"tick","at_ms":10}
{"event":"tick","at_ms":9}
"#;
        assert!(run_jsonl(trace).is_err());
    }
}
