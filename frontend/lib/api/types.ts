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
