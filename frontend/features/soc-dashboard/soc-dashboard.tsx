import {
  AlertTriangle,
  ArrowRight,
  Brain,
  Clock3,
  FileText,
  GitBranch,
  type LucideIcon,
  RadioTower,
  ShieldAlert,
  Siren,
} from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { acknowledgeAlert, closeAlert } from "@/app/actions";
import type {
  ApiResult,
  DetectionAlert,
  DetectionAlertListResponse,
  EventSearchResponse,
  NormalizedEvent,
  ReportingFinding,
  SocReport,
} from "@/lib/api/types";
import { cn } from "@/lib/utils";

type SocDashboardProps = {
  report: ApiResult<SocReport>;
  alerts: ApiResult<DetectionAlertListResponse>;
  selectedAlert: ApiResult<DetectionAlert> | null;
  investigationEvents: ApiResult<EventSearchResponse> | null;
  tenantId?: string;
};

export function SocDashboard({
  report,
  alerts,
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
      <AppShellHeader posture={data.executive_summary.posture} />
      <section className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-5 py-5">
        <ExecutiveStrip report={data} />
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1.25fr)_minmax(360px,0.75fr)]">
          <section className="flex min-w-0 flex-col gap-5">
            <KpiGrid report={data} />
            <OperationalTables report={data} />
          </section>
          <aside className="flex min-w-0 flex-col gap-5">
            <FindingsPanel findings={data.findings} />
            <AlertQueuePanel
              alerts={openAlerts}
              error={alerts.error}
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

function AppShellHeader({ posture }: { posture: string }) {
  return (
    <header className="border-b border-border bg-white">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-5 py-4">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Helix Sentinel
          </p>
          <h1 className="truncate text-xl font-semibold text-foreground">
            SOC Operations
          </h1>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-border px-3 py-2">
          <ShieldAlert className="h-4 w-4 text-primary" aria-hidden="true" />
          <span className="text-sm font-medium capitalize">{posture}</span>
        </div>
      </div>
    </header>
  );
}

function ExecutiveStrip({ report }: { report: SocReport }) {
  const summary = report.executive_summary;
  return (
    <section className="grid gap-3 md:grid-cols-4">
      <MetricCard
        icon={RadioTower}
        label="Events"
        value={formatNumber(summary.total_events)}
        tone="neutral"
      />
      <MetricCard
        icon={Siren}
        label="Open alerts"
        value={formatNumber(summary.open_alerts)}
        tone={summary.open_alerts > 0 ? "warning" : "good"}
      />
      <MetricCard
        icon={AlertTriangle}
        label="Threat insights"
        value={formatNumber(summary.threat_insights)}
        tone={summary.high_or_critical_threat_insights > 0 ? "danger" : "neutral"}
      />
      <MetricCard
        icon={Brain}
        label="AI anomalies"
        value={formatNumber(summary.ai_anomalies)}
        tone={summary.high_confidence_ai_anomalies > 0 ? "warning" : "neutral"}
      />
    </section>
  );
}

function KpiGrid({ report }: { report: SocReport }) {
  return (
    <section className="grid gap-3 md:grid-cols-3">
      <KpiBlock
        label="High severity ratio"
        value={formatPercent(report.operational_kpis.high_severity_ratio)}
      />
      <KpiBlock
        label="Auth failure ratio"
        value={formatPercent(report.operational_kpis.authentication_failure_ratio)}
      />
      <KpiBlock
        label="Events per source"
        value={formatNumber(report.operational_kpis.events_per_source)}
      />
      <KpiBlock
        label="MTTA"
        value={formatMinutes(report.alert_workflow.mtta_minutes)}
      />
      <KpiBlock
        label="MTTR"
        value={formatMinutes(report.alert_workflow.mttr_minutes)}
      />
      <KpiBlock
        label="Unassigned open"
        value={formatNumber(report.alert_workflow.unassigned_open_alerts)}
      />
    </section>
  );
}

function OperationalTables({ report }: { report: SocReport }) {
  return (
    <section className="grid gap-5 xl:grid-cols-2">
      <Panel title="Source Coverage">
        <div className="space-y-3">
          {report.top_sources.map((source) => (
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
                    width: `${Math.min(source.high_or_critical_events * 18, 100)}%`,
                  }}
                />
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                {formatNumber(source.high_or_critical_events)} high or critical
              </p>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Severity Distribution">
        <div className="space-y-3">
          {report.severity_distribution.map((item) => (
            <DistributionRow
              key={item.name}
              label={item.name}
              count={item.count}
              percentage={item.percentage}
            />
          ))}
        </div>
      </Panel>
    </section>
  );
}

function FindingsPanel({ findings }: { findings: ReportingFinding[] }) {
  return (
    <Panel title="Priority Findings">
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
  selectedAlertId,
  tenantId,
}: {
  alerts: DetectionAlertListResponse["items"];
  error: string | null;
  selectedAlertId?: string;
  tenantId?: string;
}) {
  return (
    <Panel title="Open Alert Queue">
      {error ? (
        <EmptyLine text={error} />
      ) : (
        <div className="space-y-3">
          {alerts.length === 0 ? (
            <EmptyLine text="No open alerts returned." />
          ) : (
            alerts.map((alert) => (
              <Link
                key={alert.id}
                href={alertHref(alert.id, tenantId)}
                className={cn(
                  "block rounded-md border border-border p-3 transition-colors hover:border-primary",
                  selectedAlertId === alert.id && "border-primary bg-muted",
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{alert.title}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {alert.source_name} · {humanize(alert.category)}
                    </p>
                    <p className="mt-2 text-xs text-muted-foreground">
                      {formatDateTime(alert.event_time)}
                    </p>
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
      <Panel title="Investigation Detail">
        <EmptyLine text="Select an alert from the queue to review investigation context." />
      </Panel>
    );
  }
  if (!alert.data) {
    return (
      <Panel title="Investigation Detail">
        <EmptyLine text={alert.error ?? "Alert detail was not returned."} />
      </Panel>
    );
  }

  const item = alert.data;
  const canAcknowledge = item.status === "open";
  const canClose = item.status === "open" || item.status === "acknowledged";

  return (
    <Panel title="Investigation Detail">
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
            noteLabel="Acknowledge note"
            submitLabel="Acknowledge"
            tenantId={tenantId}
          />
          <CloseForm
            alertId={item.id}
            disabled={!canClose}
            tenantId={tenantId}
          />
        </div>
      </div>
    </Panel>
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
  noteLabel,
  submitLabel,
  tenantId,
}: {
  action: (formData: FormData) => Promise<void>;
  alertId: string;
  disabled: boolean;
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
    </form>
  );
}

function CloseForm({
  alertId,
  disabled,
  tenantId,
}: {
  alertId: string;
  disabled: boolean;
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
    </form>
  );
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="font-medium text-foreground">{label}: </span>
      <span>{value}</span>
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  tone: "neutral" | "good" | "warning" | "danger";
}) {
  return (
    <article
      className={cn(
        "rounded-md border bg-white p-4",
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
    </article>
  );
}

function KpiBlock({ label, value }: { label: string; value: string }) {
  return (
    <article className="rounded-md border border-border bg-white p-4">
      <p className="text-sm text-muted-foreground">{label}</p>
      <p className="mt-2 text-xl font-semibold">{value}</p>
    </article>
  );
}

function Panel({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="rounded-md border border-border bg-white p-4">
      <h2 className="text-sm font-semibold">{title}</h2>
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
          className="h-2 rounded-sm bg-slate-700"
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
  return <p className="text-sm text-muted-foreground">{text}</p>;
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

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
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
