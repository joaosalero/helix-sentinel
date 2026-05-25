import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Crosshair,
  FileText,
  GitBranch,
  KeyRound,
  LockKeyhole,
  RadioTower,
  type LucideIcon,
  ShieldAlert,
  Siren,
  UserRound,
} from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { acknowledgeAlert, closeAlert } from "@/app/actions";
import type {
  ApiResult,
  DetectionAlert,
  DetectionAlertListResponse,
  DetectionCoverageSummary,
  DetectionRuleEfficacy,
  EventSearchResponse,
  NormalizedEvent,
  ReportingFinding,
  SecurityActivitySummary,
  SocReport,
} from "@/lib/api/types";
import { cn } from "@/lib/utils";

type SocDashboardProps = {
  report: ApiResult<SocReport>;
  alerts: ApiResult<DetectionAlertListResponse>;
  coverage: ApiResult<DetectionCoverageSummary>;
  securityActivity: ApiResult<SecurityActivitySummary>;
  selectedAlert: ApiResult<DetectionAlert> | null;
  investigationEvents: ApiResult<EventSearchResponse> | null;
  tenantId?: string;
};

export function SocDashboard({
  report,
  alerts,
  coverage,
  securityActivity,
  selectedAlert,
  investigationEvents,
  tenantId,
}: SocDashboardProps) {
  if (!report.data) {
    return (
      <UnavailableState
        message={report.error ?? "SOC report data was not returned."}
        status={report.status}
      />
    );
  }

  const data = report.data;
  const openAlerts = alerts.data?.items ?? [];

  return (
    <main className="min-h-screen bg-background">
      <AppShellHeader
        periodEnd={data.period_end}
        periodStart={data.period_start}
        posture={data.executive_summary.posture}
        tenantId={tenantId}
      />
      <section className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-5 py-5">
        <ExecutiveStrip report={data} />
        <OperationsBrief
          coverage={coverage}
          report={data}
          securityActivity={securityActivity}
        />
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1.25fr)_minmax(360px,0.75fr)]">
          <section className="flex min-w-0 flex-col gap-5">
            <KpiGrid report={data} />
            <DetectionCoveragePanel coverage={coverage} />
            <SecurityActivityPanel activity={securityActivity} />
            <OperationalTables report={data} />
          </section>
          <aside className="flex min-w-0 flex-col gap-5">
            <FindingsPanel findings={data.findings} />
            <AlertQueuePanel
              alerts={openAlerts}
              error={alerts.error}
              total={alerts.data?.total}
              selectedAlertId={selectedAlert?.data?.id}
              tenantId={tenantId}
            />
            <InvestigationPanel
              alert={selectedAlert}
              investigationEvents={investigationEvents}
              tenantId={tenantId}
            />
          </aside>
        </div>
      </section>
    </main>
  );
}

function OperationsBrief({
  report,
  coverage,
  securityActivity,
}: {
  report: SocReport;
  coverage: ApiResult<DetectionCoverageSummary>;
  securityActivity: ApiResult<SecurityActivitySummary>;
}) {
  const kpis = report.executive_kpis;
  const oldestOpen = report.alert_workflow.oldest_open_alert_minutes;
  const staleQueue = oldestOpen !== null && oldestOpen >= 60 * 24;
  const tenantDenials = securityActivity.data?.authorization.tenant_scope_denials ?? 0;
  const coverageRatio = coverage.data?.coverage_ratio ?? kpis.detection_coverage_ratio;

  return (
    <section className="grid gap-3 lg:grid-cols-4">
      <OperationalBriefItem
        icon={Siren}
        label="Triage pressure"
        tone={kpis.open_alerts > 0 ? "warning" : "good"}
        value={`${formatNumber(kpis.open_alerts)} open`}
        detail={`${formatNumber(kpis.unassigned_open_alerts)} unassigned`}
      />
      <OperationalBriefItem
        icon={Clock3}
        label="Oldest open alert"
        tone={staleQueue ? "danger" : oldestOpen !== null ? "warning" : "neutral"}
        value={formatDuration(oldestOpen)}
        detail={staleQueue ? "stale queue item" : "workflow age"}
      />
      <OperationalBriefItem
        icon={Crosshair}
        label="Coverage posture"
        tone={coverageRatio !== null && coverageRatio < 0.5 ? "warning" : "neutral"}
        value={formatPercent(coverageRatio)}
        detail={`${formatNumber(kpis.silent_active_rules ?? 0)} silent active rules`}
      />
      <OperationalBriefItem
        icon={LockKeyhole}
        label="Access guardrails"
        tone={tenantDenials > 0 ? "warning" : "good"}
        value={`${formatNumber(tenantDenials)} tenant denials`}
        detail="audit-backed oversight"
      />
    </section>
  );
}

function OperationalBriefItem({
  icon: Icon,
  label,
  value,
  detail,
  tone,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  detail: string;
  tone: "neutral" | "good" | "warning" | "danger";
}) {
  return (
    <article
      className={cn(
        "rounded-md border bg-white p-3 shadow-sm",
        tone === "good" && "border-emerald-200",
        tone === "warning" && "border-amber-300",
        tone === "danger" && "border-red-300",
        tone === "neutral" && "border-border",
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </p>
        <Icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
      </div>
      <p className="mt-2 text-lg font-semibold">{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
    </article>
  );
}

function AppShellHeader({
  posture,
  periodStart,
  periodEnd,
  tenantId,
}: {
  posture: string;
  periodStart: string;
  periodEnd: string;
  tenantId?: string;
}) {
  return (
    <header className="border-b border-border bg-white/95">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-4 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Helix Sentinel
          </p>
          <h1 className="truncate text-xl font-semibold text-foreground">
            SOC Operations
          </h1>
          <p className="mt-1 truncate text-xs text-muted-foreground">
            {formatDate(periodStart)} - {formatDate(periodEnd)}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <HeaderPill
            label="Scope"
            value={tenantId ? "Tenant filtered" : "Aggregate demo"}
          />
          <HeaderPill label="Window" value="7 days" />
          <div
            className={cn(
              "flex items-center gap-2 rounded-md border px-3 py-2",
              postureTone(posture) === "danger" && "border-red-300 bg-red-50 text-red-900",
              postureTone(posture) === "warning" && "border-amber-300 bg-amber-50 text-amber-900",
              postureTone(posture) === "good" && "border-emerald-200 bg-emerald-50 text-emerald-900",
            )}
          >
            <ShieldAlert className="h-4 w-4" aria-hidden="true" />
            <span className="text-sm font-medium capitalize">{posture}</span>
          </div>
        </div>
      </div>
    </header>
  );
}

function HeaderPill({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/40 px-3 py-2">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="ml-2 text-sm font-medium">{value}</span>
    </div>
  );
}

function ExecutiveStrip({ report }: { report: SocReport }) {
  const summary = report.executive_summary;
  const kpis = report.executive_kpis;
  return (
    <section className="grid gap-3 xl:grid-cols-[minmax(0,1.25fr)_repeat(3,minmax(0,1fr))]">
      <article className="rounded-md border border-border bg-white p-4 shadow-sm">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm text-muted-foreground">Executive posture</p>
            <p className="mt-2 text-2xl font-semibold capitalize">{summary.posture}</p>
          </div>
          <div className="rounded-md border border-border px-3 py-2 text-right">
            <p className="text-xs text-muted-foreground">Risk</p>
            <p className="text-lg font-semibold">{summary.risk_score}</p>
          </div>
        </div>
        <p className="mt-3 text-sm text-muted-foreground">{summary.summary}</p>
        <div className="mt-4 h-2 rounded-sm bg-muted">
          <div
            className={cn(
              "h-2 rounded-sm",
              summary.risk_score >= 45 && "bg-red-600",
              summary.risk_score >= 15 && summary.risk_score < 45 && "bg-amber-500",
              summary.risk_score < 15 && "bg-emerald-600",
            )}
            style={{ width: `${Math.min(summary.risk_score, 100)}%` }}
          />
        </div>
        {summary.primary_driver ? (
          <p className="mt-2 truncate text-xs text-muted-foreground">
            Driver: {humanize(summary.primary_driver)}
          </p>
        ) : null}
      </article>
      <MetricCard
        icon={Siren}
        label="Open alerts"
        value={formatNumber(kpis.open_alerts)}
        subvalue={`${formatPercent(kpis.alert_closure_ratio)} closed`}
        tone={kpis.open_alerts > 0 ? "warning" : "good"}
      />
      <MetricCard
        icon={Crosshair}
        label="Detection coverage"
        value={formatPercent(kpis.detection_coverage_ratio)}
        subvalue={`${formatNumber(kpis.silent_active_rules ?? 0)} silent active`}
        tone={
          kpis.detection_coverage_ratio !== null && kpis.detection_coverage_ratio < 0.5
            ? "warning"
            : "neutral"
        }
      />
      <MetricCard
        icon={AlertTriangle}
        label="High-risk signals"
        value={formatNumber(
          kpis.high_or_critical_threat_insights + kpis.high_confidence_ai_anomalies,
        )}
        subvalue={`${formatNumber(kpis.high_or_critical_threat_insights)} threat / ${formatNumber(
          kpis.high_confidence_ai_anomalies,
        )} AI`}
        tone={
          kpis.high_or_critical_threat_insights > 0 ||
          kpis.high_confidence_ai_anomalies > 0
            ? "danger"
            : "neutral"
        }
      />
    </section>
  );
}

function KpiGrid({ report }: { report: SocReport }) {
  const kpis = report.executive_kpis;
  return (
    <section className="grid gap-3 md:grid-cols-3">
      <KpiBlock
        label="High severity ratio"
        value={formatPercent(kpis.high_severity_ratio)}
      />
      <KpiBlock
        label="Auth failure ratio"
        value={formatPercent(kpis.authentication_failure_ratio)}
      />
      <KpiBlock
        label="Alert closure"
        value={formatPercent(kpis.alert_closure_ratio)}
      />
      <KpiBlock
        label="MTTA"
        value={formatMinutes(kpis.mtta_minutes)}
      />
      <KpiBlock
        label="MTTR"
        value={formatMinutes(kpis.mttr_minutes)}
      />
      <KpiBlock
        label="Unassigned open"
        value={formatNumber(kpis.unassigned_open_alerts)}
      />
    </section>
  );
}

function OperationalTables({ report }: { report: SocReport }) {
  return (
    <section className="grid gap-5 xl:grid-cols-2">
      <Panel
        title="Source Coverage"
        subtitle={`${formatNumber(report.executive_summary.active_sources)} active sources`}
      >
        <div className="space-y-3">
          {report.top_sources.length === 0 ? (
            <EmptyLine text="No event sources reported in this window." />
          ) : (
            report.top_sources.map((source) => (
              <div key={source.source} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="truncate text-sm font-medium">{source.source}</span>
                  <span className="text-sm text-muted-foreground">
                    {formatNumber(source.total_events)}
                  </span>
                </div>
                <div className="mt-2 h-2 rounded-sm bg-muted">
                  <div
                    className="h-2 rounded-sm bg-primary"
                    style={{
                      width: `${sourceSeverityWidth(source)}%`,
                    }}
                  />
                </div>
                <p className="mt-2 text-xs text-muted-foreground">
                  {formatNumber(source.high_or_critical_events)} high or critical
                </p>
              </div>
            ))
          )}
        </div>
      </Panel>
      <Panel title="Severity Distribution" subtitle="Normalized event severity">
        <div className="space-y-3">
          {report.severity_distribution.length === 0 ? (
            <EmptyLine text="No severity distribution returned." />
          ) : (
            report.severity_distribution.map((item) => (
              <DistributionRow
                key={item.name}
                label={item.name}
                count={item.count}
                percentage={item.percentage}
              />
            ))
          )}
        </div>
      </Panel>
    </section>
  );
}

function DetectionCoveragePanel({
  coverage,
}: {
  coverage: ApiResult<DetectionCoverageSummary>;
}) {
  if (!coverage.data) {
    return (
      <Panel title="Detection Coverage">
        <EmptyLine text={coverage.error ?? "Detection coverage data was not returned."} />
      </Panel>
    );
  }

  const data = coverage.data;
  const topTechnique = data.top_techniques[0];

  return (
    <Panel title="Detection Coverage" subtitle="Rule efficacy and ATT&CK mapping">
      <div className="grid gap-3 md:grid-cols-4">
        <KpiBlock label="Mapped rules" value={formatPercent(data.coverage_ratio)} />
        <KpiBlock label="Techniques" value={formatNumber(data.techniques_covered)} />
        <KpiBlock label="Alerting rules" value={formatNumber(data.alerting_rules)} />
        <KpiBlock label="Silent active" value={formatNumber(data.silent_active_rules)} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Crosshair className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            <p className="text-sm font-medium">ATT&CK activity</p>
          </div>
          {data.top_techniques.length === 0 ? (
            <EmptyLine text="No ATT&CK mappings are available for coverage analysis." />
          ) : (
            data.top_techniques.map((technique) => (
              <div key={technique.technique_id} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-medium">{technique.technique_id}</span>
                  <span className="text-sm text-muted-foreground">
                    {formatNumber(technique.alert_count)} alerts
                  </span>
                </div>
                <p className="mt-1 truncate text-xs text-muted-foreground">
                  {technique.name ?? humanize(technique.tactic ?? "unknown tactic")}
                </p>
              </div>
            ))
          )}
        </div>

        <div className="space-y-3">
          <p className="text-sm font-medium">Detection efficacy</p>
          <div className="rounded-md border border-border p-3">
            <KeyValue
              label="Top technique"
              value={topTechnique ? topTechnique.technique_id : "None"}
            />
            <KeyValue
              label="TP rate"
              value={formatPercent(data.true_positive_rate)}
            />
            <KeyValue
              label="FP rate"
              value={formatPercent(data.false_positive_rate)}
            />
          </div>
          {data.noisy_rules.length === 0 ? (
            <EmptyLine text="No alerting rules in this reporting window." />
          ) : (
            data.noisy_rules.slice(0, 3).map((rule) => (
              <RuleEfficacyRow key={rule.rule_id} rule={rule} />
            ))
          )}
        </div>
      </div>
    </Panel>
  );
}

function SecurityActivityPanel({
  activity,
}: {
  activity: ApiResult<SecurityActivitySummary>;
}) {
  if (!activity.data) {
    return (
      <Panel title="Security Activity">
        <EmptyLine text={activity.error ?? "Security activity data was not returned."} />
      </Panel>
    );
  }

  const data = activity.data;
  return (
    <Panel title="Security Activity" subtitle="Audit-backed operational oversight">
      <div className="grid gap-3 md:grid-cols-4">
        <KpiBlock label="Audit events" value={formatNumber(data.total_audit_events)} />
        <KpiBlock
          label="Auth failure ratio"
          value={formatPercent(data.authentication.failure_ratio)}
        />
        <KpiBlock
          label="Tenant denials"
          value={formatNumber(data.authorization.tenant_scope_denials)}
        />
        <KpiBlock
          label="Active actors"
          value={formatNumber(data.active_actor_count)}
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <LockKeyhole className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            <p className="text-sm font-medium">Activity mix</p>
          </div>
          {data.actions.length === 0 ? (
            <EmptyLine text="No audit actions returned for this window." />
          ) : (
            data.actions.slice(0, 5).map((item) => (
              <div
                key={`${item.action}-${item.outcome}`}
                className="rounded-md border border-border p-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="truncate text-sm font-medium">{humanize(item.action)}</span>
                  <span className="text-sm text-muted-foreground">
                    {formatNumber(item.count)}
                  </span>
                </div>
                <p className="mt-1 text-xs text-muted-foreground capitalize">
                  {item.outcome}
                  {item.last_seen ? ` · ${formatDateTime(item.last_seen)}` : ""}
                </p>
              </div>
            ))
          )}
        </div>

        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            <p className="text-sm font-medium">Actor concentration</p>
          </div>
          {data.top_actors.length === 0 ? (
            <EmptyLine text="No attributed actor activity returned." />
          ) : (
            data.top_actors.slice(0, 5).map((item, index) => (
              <div
                key={`${item.actor_id ?? item.actor_email_hash ?? index}`}
                className="rounded-md border border-border p-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="truncate text-sm font-medium">{actorLabel(item)}</span>
                  <span className="text-sm text-muted-foreground">
                    {formatNumber(item.count)}
                  </span>
                </div>
                <p className="mt-1 truncate text-xs text-muted-foreground">
                  {formatNumber(item.failure_count)} failures
                  {item.last_seen ? ` · ${formatDateTime(item.last_seen)}` : ""}
                </p>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <div className="space-y-3">
          <p className="text-sm font-medium">Recent audit trail</p>
          {data.recent_activity.length === 0 ? (
            <EmptyLine text="No recent audit activity returned." />
          ) : (
            data.recent_activity.slice(0, 5).map((item, index) => (
              <div
                key={`${item.action}-${item.correlation_id ?? index}`}
                className="rounded-md border border-border p-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="truncate text-sm font-medium">{humanize(item.action)}</span>
                  <span className="text-xs text-muted-foreground capitalize">
                    {item.outcome}
                  </span>
                </div>
                <p className="mt-1 truncate text-xs text-muted-foreground">
                  {item.resource ?? "No resource"}
                  {item.created_at ? ` · ${formatDateTime(item.created_at)}` : ""}
                </p>
              </div>
            ))
          )}
        </div>

        <div className="space-y-3">
          <p className="text-sm font-medium">Security oversight</p>
          <div className="rounded-md border border-border p-3">
            <KeyValue
              label="Auth outcomes"
              value={`${formatNumber(data.authentication.successes)} success / ${formatNumber(
                data.authentication.failures,
              )} fail`}
            />
            <KeyValue
              label="Investigation flow"
              value={`${formatNumber(data.investigations.acknowledgements)} ack / ${formatNumber(
                data.investigations.closures,
              )} closed`}
            />
            <KeyValue
              label="Ingestion rejects"
              value={formatNumber(data.event_ingestion_rejections)}
            />
          </div>
          {data.findings.length === 0 ? (
            <EmptyLine text="No audit findings in this window." />
          ) : (
            data.findings.slice(0, 3).map((finding) => (
              <div key={finding.name} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-medium">{humanize(finding.name)}</span>
                  <SeverityBadge severity={finding.severity} />
                </div>
                <p className="mt-2 text-sm text-muted-foreground">{finding.reason}</p>
              </div>
            ))
          )}
        </div>
      </div>
    </Panel>
  );
}

function RuleEfficacyRow({ rule }: { rule: DetectionRuleEfficacy }) {
  return (
    <div className="rounded-md border border-border p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{rule.title}</p>
          <p className="mt-1 text-xs text-muted-foreground">
            {humanize(rule.category)} · {rule.attack_techniques.join(", ") || "Unmapped"}
          </p>
        </div>
        <SeverityBadge severity={rule.severity} />
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        {formatNumber(rule.alert_count)} alerts · {formatNumber(rule.open_alerts)} open
      </p>
    </div>
  );
}

function FindingsPanel({ findings }: { findings: ReportingFinding[] }) {
  return (
    <Panel title="Priority Findings" subtitle="Deterministic report drivers">
      <div className="space-y-3">
        {findings.length === 0 ? (
          <EmptyLine text="No prioritized findings in this reporting window." />
        ) : (
          findings.map((finding) => (
            <div key={finding.name} className="rounded-md border border-border p-3">
              <div className="flex items-center justify-between gap-3">
                <span className="text-sm font-medium">
                  {humanize(finding.name)}
                </span>
                <SeverityBadge severity={finding.severity} />
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{finding.reason}</p>
            </div>
          ))
        )}
      </div>
    </Panel>
  );
}

function AlertQueuePanel({
  alerts,
  error,
  total,
  selectedAlertId,
  tenantId,
}: {
  alerts: DetectionAlertListResponse["items"];
  error: string | null;
  total?: number;
  selectedAlertId?: string;
  tenantId?: string;
}) {
  return (
    <Panel
      title="Open Alert Queue"
      subtitle={`${formatNumber(total ?? alerts.length)} persisted alerts awaiting triage`}
    >
      {error ? (
        <EmptyLine text={error} />
      ) : (
        <div className="space-y-3">
          {alerts.length === 0 ? (
            <EmptyLine text="No open alerts awaiting triage." />
          ) : (
            alerts.map((alert) => (
              <Link
                key={alert.id}
                href={alertHref(alert.id, tenantId)}
                aria-current={selectedAlertId === alert.id ? "true" : undefined}
                className={cn(
                  "block rounded-md border border-border p-3 transition-colors hover:border-primary",
                  selectedAlertId === alert.id && "border-primary bg-muted/70",
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{alert.title}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {alert.source_name} · {humanize(alert.category)}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                      <span>{formatAge(alert.event_time)} old</span>
                      <span>{alert.assigned_to ?? "Unassigned"}</span>
                      <span>{shortId(alert.id)}</span>
                    </div>
                  </div>
                  <SeverityBadge severity={alert.severity} />
                </div>
              </Link>
            ))
          )}
        </div>
      )}
    </Panel>
  );
}

function InvestigationPanel({
  alert,
  investigationEvents,
  tenantId,
}: {
  alert: ApiResult<DetectionAlert> | null;
  investigationEvents: ApiResult<EventSearchResponse> | null;
  tenantId?: string;
}) {
  if (alert === null) {
    return (
      <Panel title="Investigation Detail" subtitle="Selected alert context">
        <EmptyLine text="Select an alert from the queue to review investigation context." />
      </Panel>
    );
  }
  if (!alert.data) {
    return (
      <Panel title="Investigation Detail" subtitle="Selected alert context">
        <EmptyLine text={alert.error ?? "Alert detail was not returned."} />
      </Panel>
    );
  }

  const item = alert.data;
  const canAcknowledge = item.status === "open";
  const canClose = item.status === "open" || item.status === "acknowledged";
  const workflowLocked = !canAcknowledge && !canClose;

  return (
    <Panel title="Investigation Detail" subtitle="Selected alert context">
      <div className="space-y-4">
        <div className="rounded-md border border-border p-3">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-sm font-semibold">{item.title}</p>
              <p className="mt-1 text-xs text-muted-foreground">
                {item.source_name} · {humanize(item.category)} · {formatDateTime(item.event_time)}
              </p>
            </div>
            <SeverityBadge severity={item.severity} />
          </div>
          <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
            <KeyValue label="Status" value={humanize(item.status)} />
            <KeyValue label="Disposition" value={item.disposition ?? "Not set"} />
            <KeyValue label="Assigned" value={item.assigned_to ?? "Unassigned"} />
            <KeyValue label="Selections" value={item.matched_selections.join(", ") || "None"} />
          </div>
        </div>

        <InvestigationReadiness
          alert={item}
          events={investigationEvents}
        />

        <TimelinePanel
          alert={item}
          events={investigationEvents}
        />

        {item.investigation_note ? (
          <div className="rounded-md border border-border p-3">
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              <p className="text-sm font-medium">Investigation note</p>
            </div>
            <p className="mt-2 text-sm text-muted-foreground">{item.investigation_note}</p>
          </div>
        ) : null}

        <div className="grid gap-3">
          <WorkflowForm
            action={acknowledgeAlert}
            alertId={item.id}
            disabled={!canAcknowledge}
            disabledReason={
              canAcknowledge ? undefined : "Alert is no longer open for acknowledgement."
            }
            noteLabel="Acknowledge note"
            submitLabel="Acknowledge"
            tenantId={tenantId}
          />
          <CloseForm
            alertId={item.id}
            disabled={!canClose}
            disabledReason={
              workflowLocked ? "Closed alerts keep their recorded disposition." : undefined
            }
            tenantId={tenantId}
          />
        </div>
      </div>
    </Panel>
  );
}

function InvestigationReadiness({
  alert,
  events,
}: {
  alert: DetectionAlert;
  events: ApiResult<EventSearchResponse> | null;
}) {
  const contextEvents = events?.data?.items ?? [];
  const relatedEvents = contextEvents.filter((event) => event.id !== alert.event_id);
  const highContext = relatedEvents.filter((event) =>
    ["high", "critical"].includes(event.severity),
  ).length;

  return (
    <div className="rounded-md border border-border p-3">
      <div className="flex items-center gap-2">
        <CheckCircle2 className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        <p className="text-sm font-medium">Triage readiness</p>
      </div>
      <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
        <ReadinessItem
          complete={alert.assigned_to !== null}
          label={alert.assigned_to ? `Assigned to ${alert.assigned_to}` : "Unassigned"}
        />
        <ReadinessItem
          complete={alert.investigation_note !== null}
          label={alert.investigation_note ? "Analyst note recorded" : "No analyst note"}
        />
        <ReadinessItem
          complete={relatedEvents.length > 0}
          label={`${formatNumber(relatedEvents.length)} related context events`}
        />
        <ReadinessItem
          complete={highContext > 0 || !["high", "critical"].includes(alert.severity)}
          label={`${formatNumber(highContext)} high+ context events`}
        />
      </div>
    </div>
  );
}

function ReadinessItem({ complete, label }: { complete: boolean; label: string }) {
  return (
    <div className="flex min-w-0 items-center gap-2">
      <span
        className={cn(
          "h-2 w-2 shrink-0 rounded-full",
          complete ? "bg-emerald-500" : "bg-amber-500",
        )}
      />
      <span className="truncate">{label}</span>
    </div>
  );
}

function TimelinePanel({
  alert,
  events,
}: {
  alert: DetectionAlert;
  events: ApiResult<EventSearchResponse> | null;
}) {
  if (events === null) {
    return null;
  }
  if (!events.data) {
    return (
      <div className="rounded-md border border-border p-3">
        <div className="flex items-center gap-2">
          <GitBranch className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm font-medium">Context timeline</p>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">
          {events.error ?? "No contextual events were returned."}
        </p>
      </div>
    );
  }

  const timeline = timelineEvents(alert, events.data.items);
  const highCount = timeline.filter((event) =>
    ["high", "critical"].includes(event.severity),
  ).length;

  return (
    <div className="rounded-md border border-border p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <GitBranch className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm font-medium">Context timeline</p>
        </div>
        <span className="text-xs text-muted-foreground">
          {timeline.length} events · {highCount} high+
        </span>
      </div>
      <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-3">
        <KeyValue label="Pivot" value={`${alert.source_name} / ${humanize(alert.category)}`} />
        <KeyValue label="Window" value="±12h" />
        <KeyValue label="Matched event" value={shortId(alert.event_id)} />
      </div>
      <EvidencePivots alert={alert} events={timeline} />
      <div className="mt-4 space-y-0">
        {timeline.length === 0 ? (
          <EmptyLine text="No source/category context events found around this alert." />
        ) : (
          timeline.map((event) => (
            <TimelineEventRow
              key={event.id}
              alertEventId={alert.event_id}
              event={event}
            />
          ))
        )}
      </div>
    </div>
  );
}

function EvidencePivots({
  alert,
  events,
}: {
  alert: DetectionAlert;
  events: NormalizedEvent[];
}) {
  const entities = Array.from(new Set(events.map(entityLabel).filter(Boolean))).slice(0, 4);
  const sources = Array.from(new Set(events.map((event) => event.source_name))).slice(0, 3);
  return (
    <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
      <div className="rounded-md border border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <UserRound className="h-3.5 w-3.5" aria-hidden="true" />
          <span className="font-medium text-foreground">Entities</span>
        </div>
        <p className="mt-1 truncate">{entities.join(", ") || "No actor or asset pivot"}</p>
      </div>
      <div className="rounded-md border border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <RadioTower className="h-3.5 w-3.5" aria-hidden="true" />
          <span className="font-medium text-foreground">Sources</span>
        </div>
        <p className="mt-1 truncate">{sources.join(", ") || alert.source_name}</p>
      </div>
    </div>
  );
}

function TimelineEventRow({
  alertEventId,
  event,
}: {
  alertEventId: string;
  event: NormalizedEvent;
}) {
  const isMatchedEvent = event.id === alertEventId;
  return (
    <div className="grid grid-cols-[72px_16px_minmax(0,1fr)] gap-3 border-l-0 py-2">
      <time className="pt-0.5 text-xs text-muted-foreground">
        {formatTime(event.event_time)}
      </time>
      <div className="flex justify-center">
        <span
          className={cn(
            "mt-1 h-2.5 w-2.5 rounded-full",
            isMatchedEvent ? "bg-primary" : "bg-slate-300",
          )}
        />
      </div>
      <div className={cn("min-w-0", isMatchedEvent && "rounded-sm bg-muted px-2 py-1")}>
        <div className="flex items-start justify-between gap-2">
          <p className="truncate text-sm font-medium">{event.title}</p>
          <SeverityBadge severity={event.severity} />
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          {event.source_name} · {humanize(event.category)}
          {entityLabel(event) ? ` · ${entityLabel(event)}` : ""}
        </p>
      </div>
    </div>
  );
}

function WorkflowForm({
  action,
  alertId,
  disabled,
  disabledReason,
  noteLabel,
  submitLabel,
  tenantId,
}: {
  action: (formData: FormData) => Promise<void>;
  alertId: string;
  disabled: boolean;
  disabledReason?: string;
  noteLabel: string;
  submitLabel: string;
  tenantId?: string;
}) {
  return (
    <form action={action} className="rounded-md border border-border p-3">
      <input name="alert_id" type="hidden" value={alertId} />
      <input name="tenant_id" type="hidden" value={tenantId ?? ""} />
      <label className="text-sm font-medium" htmlFor={`${alertId}-${submitLabel}`}>
        {noteLabel}
      </label>
      <textarea
        className="mt-2 min-h-20 w-full resize-y rounded-md border border-border bg-white p-2 text-sm outline-none focus:border-primary"
        disabled={disabled}
        id={`${alertId}-${submitLabel}`}
        name="investigation_note"
        placeholder="Record concise analyst context."
      />
      <button
        className="mt-3 inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50"
        disabled={disabled}
        type="submit"
      >
        {submitLabel}
        <ArrowRight className="h-4 w-4" aria-hidden="true" />
      </button>
      {disabled && disabledReason ? (
        <p className="mt-2 text-xs text-muted-foreground">{disabledReason}</p>
      ) : null}
    </form>
  );
}

function CloseForm({
  alertId,
  disabled,
  disabledReason,
  tenantId,
}: {
  alertId: string;
  disabled: boolean;
  disabledReason?: string;
  tenantId?: string;
}) {
  return (
    <form action={closeAlert} className="rounded-md border border-border p-3">
      <input name="alert_id" type="hidden" value={alertId} />
      <input name="tenant_id" type="hidden" value={tenantId ?? ""} />
      <label className="text-sm font-medium" htmlFor={`${alertId}-disposition`}>
        Close disposition
      </label>
      <select
        className="mt-2 w-full rounded-md border border-border bg-white p-2 text-sm outline-none focus:border-primary"
        disabled={disabled}
        id={`${alertId}-disposition`}
        name="disposition"
      >
        <option value="true_positive">True positive</option>
        <option value="false_positive">False positive</option>
        <option value="benign_activity">Benign activity</option>
        <option value="duplicate">Duplicate</option>
      </select>
      <textarea
        className="mt-2 min-h-20 w-full resize-y rounded-md border border-border bg-white p-2 text-sm outline-none focus:border-primary"
        disabled={disabled}
        name="investigation_note"
        placeholder="Summarize evidence and closure rationale."
      />
      <button
        className="mt-3 inline-flex items-center gap-2 rounded-md bg-slate-800 px-3 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
        disabled={disabled}
        type="submit"
      >
        Close alert
        <ArrowRight className="h-4 w-4" aria-hidden="true" />
      </button>
      {disabled && disabledReason ? (
        <p className="mt-2 text-xs text-muted-foreground">{disabledReason}</p>
      ) : null}
    </form>
  );
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <span className="font-medium text-foreground">{label}: </span>
      <span className="break-words">{value}</span>
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  subvalue,
  tone,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  subvalue?: string;
  tone: "neutral" | "good" | "warning" | "danger";
}) {
  return (
    <article
      className={cn(
        "rounded-md border bg-white p-4 shadow-sm",
        tone === "good" && "border-emerald-200",
        tone === "warning" && "border-amber-300",
        tone === "danger" && "border-red-300",
        tone === "neutral" && "border-border",
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm text-muted-foreground">{label}</span>
        <Icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
      </div>
      <p className="mt-3 text-2xl font-semibold">{value}</p>
      {subvalue ? <p className="mt-1 text-xs text-muted-foreground">{subvalue}</p> : null}
    </article>
  );
}

function KpiBlock({ label, value }: { label: string; value: string }) {
  return (
    <article className="rounded-md border border-border bg-white p-4 shadow-sm">
      <p className="text-sm text-muted-foreground">{label}</p>
      <p className="mt-2 text-xl font-semibold">{value}</p>
    </article>
  );
}

function Panel({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  return (
    <section className="rounded-md border border-border bg-white p-4 shadow-sm">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between sm:gap-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        {subtitle ? (
          <span className="text-xs text-muted-foreground sm:max-w-[55%] sm:text-right">
            {subtitle}
          </span>
        ) : null}
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function DistributionRow({
  label,
  count,
  percentage,
}: {
  label: string;
  count: number;
  percentage: number;
}) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="capitalize">{label}</span>
        <span className="text-muted-foreground">{formatNumber(count)}</span>
      </div>
      <div className="mt-2 h-2 rounded-sm bg-muted">
        <div
          className={cn("h-2 rounded-sm", severityBarClass(label))}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={cn(
        "rounded-sm px-2 py-1 text-xs font-medium capitalize",
        severity === "critical" && "bg-red-100 text-red-800",
        severity === "high" && "bg-amber-100 text-amber-800",
        severity === "medium" && "bg-sky-100 text-sky-800",
        !["critical", "high", "medium"].includes(severity) &&
          "bg-muted text-muted-foreground",
      )}
    >
      {severity}
    </span>
  );
}

function EmptyLine({ text }: { text: string }) {
  return (
    <div className="rounded-md border border-dashed border-border bg-muted/50 px-3 py-2">
      <p className="text-sm text-muted-foreground">{text}</p>
    </div>
  );
}

function UnavailableState({ message, status }: { message: string; status: number }) {
  return (
    <main className="min-h-screen bg-background px-5 py-10">
      <section className="mx-auto max-w-2xl rounded-md border border-border bg-white p-6">
        <div className="flex items-center gap-3">
          <Clock3 className="h-5 w-5 text-amber-600" aria-hidden="true" />
          <h1 className="text-lg font-semibold">SOC data unavailable</h1>
        </div>
        <p className="mt-3 text-sm text-muted-foreground">{message}</p>
        <p className="mt-2 text-xs text-muted-foreground">Status: {status}</p>
      </section>
    </main>
  );
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(value);
}

function formatPercent(value: number | null): string {
  if (value === null) {
    return "n/a";
  }
  return `${Math.round(value * 100)}%`;
}

function formatMinutes(value: number | null): string {
  if (value === null) {
    return "n/a";
  }
  return `${formatNumber(value)}m`;
}

function formatDuration(minutes: number | null): string {
  if (minutes === null) {
    return "n/a";
  }
  if (minutes >= 60 * 24) {
    return `${formatNumber(Math.round(minutes / (60 * 24)))}d`;
  }
  if (minutes >= 60) {
    return `${formatNumber(Math.round(minutes / 60))}h`;
  }
  return `${formatNumber(Math.round(minutes))}m`;
}

function formatAge(value: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60000));
  return formatDuration(minutes);
}

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
  }).format(new Date(value));
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function postureTone(posture: string): "danger" | "warning" | "good" {
  if (posture === "elevated") {
    return "danger";
  }
  if (posture === "guarded") {
    return "warning";
  }
  return "good";
}

function sourceSeverityWidth(source: { total_events: number; high_or_critical_events: number }) {
  if (source.total_events <= 0) {
    return 0;
  }
  return Math.min((source.high_or_critical_events / source.total_events) * 100, 100);
}

function severityBarClass(severity: string): string {
  if (severity === "critical") {
    return "bg-red-600";
  }
  if (severity === "high") {
    return "bg-amber-500";
  }
  if (severity === "medium") {
    return "bg-sky-500";
  }
  return "bg-slate-600";
}

function humanize(value: string): string {
  return value.replaceAll("_", " ");
}

function timelineEvents(
  alert: DetectionAlert,
  events: NormalizedEvent[],
): NormalizedEvent[] {
  const matched = events.some((event) => event.id === alert.event_id);
  const syntheticEvent: NormalizedEvent = {
    id: alert.event_id,
    raw_event_id: alert.event_id,
    tenant_id: alert.tenant_id,
    source_name: alert.source_name,
    source_product: null,
    source_vendor: null,
    category: alert.category,
    severity: alertSeverity(alert.severity),
    event_time: alert.event_time,
    ingested_at: alert.event_time,
    title: alert.title,
    actor: {},
    asset: {},
    network: {},
    ioc: {},
    enrichment: {},
    normalization_version: "alert",
  };
  return [...events, ...(matched ? [] : [syntheticEvent])].sort(
    (left, right) =>
      new Date(left.event_time).getTime() - new Date(right.event_time).getTime(),
  );
}

function alertSeverity(value: string): NormalizedEvent["severity"] {
  return value === "informational" ? "info" : value;
}

function entityLabel(event: NormalizedEvent): string | null {
  return (
    event.actor.email ??
    event.actor.username ??
    event.actor.ip_address ??
    event.asset.hostname ??
    event.asset.ip_address ??
    null
  );
}

function actorLabel(actor: { actor_id: string | null; actor_email_hash: string | null }): string {
  if (actor.actor_id) {
    return `Actor ${shortId(actor.actor_id)}`;
  }
  if (actor.actor_email_hash) {
    return `Email hash ${shortId(actor.actor_email_hash)}`;
  }
  return "Unknown actor";
}

function shortId(value: string): string {
  return value.slice(0, 8);
}

function alertHref(alertId: string, tenantId?: string): string {
  const params = new URLSearchParams({ alert_id: alertId });
  if (tenantId) {
    params.set("tenant_id", tenantId);
  }
  return `/?${params.toString()}`;
}
