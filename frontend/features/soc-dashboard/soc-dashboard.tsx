import {
  AlertTriangle,
  Brain,
  Clock3,
  type LucideIcon,
  RadioTower,
  ShieldAlert,
  Siren,
} from "lucide-react";
import type { ReactNode } from "react";

import type {
  ApiResult,
  DetectionAlertListResponse,
  ReportingFinding,
  SocReport,
} from "@/lib/api/types";
import { cn } from "@/lib/utils";

type SocDashboardProps = {
  report: ApiResult<SocReport>;
  alerts: ApiResult<DetectionAlertListResponse>;
};

export function SocDashboard({ report, alerts }: SocDashboardProps) {
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
            <AlertQueuePanel alerts={openAlerts} error={alerts.error} />
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
}: {
  alerts: DetectionAlertListResponse["items"];
  error: string | null;
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
              <div key={alert.id} className="rounded-md border border-border p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{alert.title}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {alert.source_name} · {humanize(alert.category)}
                    </p>
                  </div>
                  <SeverityBadge severity={alert.severity} />
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </Panel>
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

function humanize(value: string): string {
  return value.replaceAll("_", " ");
}
