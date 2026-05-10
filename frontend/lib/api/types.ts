export type ApiResult<T> =
  | { data: T; error: null; status: number }
  | { data: null; error: string; status: number };

export type CountSummary = {
  name: string;
  count: number;
  percentage: number;
};

export type SourceMetric = {
  source: string;
  total_events: number;
  high_or_critical_events: number;
  last_event_time: string | null;
};

export type OperationalKpis = {
  mtta_minutes: number | null;
  mttr_minutes: number | null;
  true_positive_rate: number | null;
  false_positive_rate: number | null;
  alert_volume: number | null;
  high_severity_ratio: number;
  authentication_failure_ratio: number;
  events_per_source: number;
};

export type ExecutiveOperationalKpis = {
  high_severity_ratio: number;
  authentication_failure_ratio: number;
  alert_closure_ratio: number;
  open_alerts: number;
  unassigned_open_alerts: number;
  mtta_minutes: number | null;
  mttr_minutes: number | null;
  true_positive_rate: number | null;
  detection_coverage_ratio: number | null;
  silent_active_rules: number | null;
  high_or_critical_threat_insights: number;
  high_confidence_ai_anomalies: number;
};

export type AlertWorkflowKpis = {
  alert_volume: number;
  open_alerts: number;
  acknowledged_alerts: number;
  closed_alerts: number;
  high_or_critical_alerts: number;
  unassigned_open_alerts: number;
  oldest_open_alert_minutes: number | null;
  mtta_minutes: number | null;
  mttr_minutes: number | null;
  true_positive_rate: number | null;
  false_positive_rate: number | null;
};

export type ExecutiveSecuritySummary = {
  posture: "nominal" | "guarded" | "elevated" | string;
  risk_score: number;
  summary: string;
  primary_driver: string | null;
  total_events: number;
  high_or_critical_events: number;
  alert_volume: number;
  open_alerts: number;
  high_or_critical_alerts: number;
  threat_insights: number;
  high_or_critical_threat_insights: number;
  ai_anomalies: number;
  high_confidence_ai_anomalies: number;
  active_sources: number;
};

export type ReportingFinding = {
  name: string;
  severity: "low" | "medium" | "high" | "critical" | string;
  count: number;
  reason: string;
};

export type AuditActionMetric = {
  action: string;
  outcome: string;
  count: number;
  last_seen: string | null;
};

export type AuditActorMetric = {
  actor_id: string | null;
  actor_email_hash: string | null;
  count: number;
  failure_count: number;
  last_seen: string | null;
};

export type RecentAuditActivity = {
  action: string;
  outcome: string;
  resource: string | null;
  correlation_id: string | null;
  created_at: string | null;
};

export type SecurityActivityFinding = {
  name: string;
  severity: "low" | "medium" | "high" | "critical" | string;
  count: number;
  reason: string;
};

export type AuthenticationActivitySummary = {
  successes: number;
  failures: number;
  token_refreshes: number;
  logouts: number;
  user_state_rejections: number;
  failure_ratio: number;
};

export type AuthorizationActivitySummary = {
  permission_denials: number;
  tenant_scope_denials: number;
};

export type InvestigationActivitySummary = {
  workflow_updates: number;
  acknowledgements: number;
  closures: number;
};

export type SecurityActivitySummary = {
  period_start: string;
  period_end: string;
  total_audit_events: number;
  successful_authentications: number;
  failed_authentications: number;
  permission_denials: number;
  tenant_scope_denials: number;
  investigation_updates: number;
  detection_rule_activity: number;
  event_ingestion_rejections: number;
  active_actor_count: number;
  authentication: AuthenticationActivitySummary;
  authorization: AuthorizationActivitySummary;
  investigations: InvestigationActivitySummary;
  actions: AuditActionMetric[];
  top_actors: AuditActorMetric[];
  recent_activity: RecentAuditActivity[];
  findings: SecurityActivityFinding[];
};

export type ThreatSummary = {
  total_insights: number;
  high_or_critical: number;
  ioc_related: number;
  repeated_auth_failures: number;
  suspicious_ip_reuse: number;
  endpoint_repetition: number;
  event_bursts: number;
  max_risk_score: number;
};

export type AIAnalyticsSummary = {
  total_anomalies: number;
  high_confidence: number;
  max_score: number;
  suspicious_classifications: number;
  enriched_events: number;
};

export type SocReport = {
  period_start: string;
  period_end: string;
  executive_summary: ExecutiveSecuritySummary;
  operational_kpis: OperationalKpis;
  alert_workflow: AlertWorkflowKpis;
  executive_kpis: ExecutiveOperationalKpis;
  severity_distribution: CountSummary[];
  category_distribution: CountSummary[];
  top_sources: SourceMetric[];
  threat_summary: ThreatSummary;
  ai_summary: AIAnalyticsSummary;
  findings: ReportingFinding[];
};

export type DetectionAlert = {
  id: string;
  tenant_id: string;
  rule_id: string;
  event_id: string;
  status: "open" | "acknowledged" | "closed" | string;
  severity: "informational" | "low" | "medium" | "high" | "critical" | string;
  category: string;
  title: string;
  source_name: string;
  event_time: string;
  matched_selections: string[];
  assigned_to: string | null;
  acknowledged_at: string | null;
  closed_at: string | null;
  disposition: string | null;
  investigation_note: string | null;
  created_at: string;
  updated_at: string;
};

export type AttackTechniqueCoverage = {
  technique_id: string;
  name: string | null;
  tactic: string | null;
  rule_count: number;
  active_rule_count: number;
  alert_count: number;
  high_or_critical_alerts: number;
};

export type AttackTacticCoverage = {
  tactic: string;
  technique_count: number;
  rule_count: number;
  alert_count: number;
};

export type DetectionRuleEfficacy = {
  rule_id: string;
  title: string;
  status: string;
  severity: string;
  category: string;
  attack_techniques: string[];
  alert_count: number;
  high_or_critical_alerts: number;
  open_alerts: number;
  true_positive_alerts: number;
  false_positive_alerts: number;
  last_alert_time: string | null;
};

export type DetectionCoverageSummary = {
  period_start: string;
  period_end: string;
  total_rules: number;
  active_rules: number;
  mapped_rules: number;
  unmapped_rules: number;
  active_mapped_rules: number;
  techniques_covered: number;
  tactics_covered: number;
  coverage_ratio: number;
  alerting_rules: number;
  silent_active_rules: number;
  total_alerts: number;
  true_positive_rate: number | null;
  false_positive_rate: number | null;
  top_techniques: AttackTechniqueCoverage[];
  tactic_coverage: AttackTacticCoverage[];
  noisy_rules: DetectionRuleEfficacy[];
  silent_rules: DetectionRuleEfficacy[];
};

export type NormalizedActor = {
  user_id?: string | null;
  username?: string | null;
  email?: string | null;
  ip_address?: string | null;
};

export type NormalizedAsset = {
  asset_id?: string | null;
  hostname?: string | null;
  ip_address?: string | null;
};

export type NormalizedEvent = {
  id: string;
  raw_event_id: string;
  tenant_id: string;
  source_name: string;
  source_product: string | null;
  source_vendor: string | null;
  category: string;
  severity: "info" | "low" | "medium" | "high" | "critical" | string;
  event_time: string;
  ingested_at: string;
  title: string;
  actor: NormalizedActor;
  asset: NormalizedAsset;
  network: Record<string, unknown>;
  ioc: Record<string, unknown>;
  enrichment: Record<string, unknown>;
  normalization_version: string;
};

export type EventSearchResponse = {
  items: NormalizedEvent[];
  limit: number;
  offset: number;
};

export type DetectionAlertListResponse = {
  items: DetectionAlert[];
  total: number;
  limit: number;
  offset: number;
};

export type AlertWorkflowUpdate = {
  status: "acknowledged" | "closed";
  disposition?: string;
  investigation_note?: string;
};
