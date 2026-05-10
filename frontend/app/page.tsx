import { SocDashboard } from "@/features/soc-dashboard/soc-dashboard";
import {
  getAlert,
  getDetectionCoverage,
  getInvestigationEvents,
  getOpenAlerts,
  getSecurityActivity,
  getSocReport,
} from "@/lib/api/client";
import type { DetectionAlert } from "@/lib/api/types";

export const dynamic = "force-dynamic";

type HomeProps = {
  searchParams?: {
    alert_id?: string;
    tenant_id?: string;
  };
};

export default async function Home({ searchParams }: HomeProps) {
  const endTime = new Date();
  const startTime = new Date(endTime.getTime() - 7 * 24 * 60 * 60 * 1000);
  const params = {
    start_time: startTime.toISOString(),
    end_time: endTime.toISOString(),
    tenant_id: searchParams?.tenant_id,
  };

  const [report, alerts, coverage, securityActivity, selectedAlert] = await Promise.all([
    getSocReport(params),
    getOpenAlerts({ tenant_id: searchParams?.tenant_id, limit: 8 }),
    getDetectionCoverage({ ...params, limit: 6 }),
    getSecurityActivity({ ...params, limit: 8 }),
    searchParams?.alert_id
      ? getAlert(searchParams.alert_id, { tenant_id: searchParams.tenant_id })
      : Promise.resolve(null),
  ]);
  const investigationEvents = selectedAlert?.data
    ? await getInvestigationEvents(contextQuery(selectedAlert.data, searchParams?.tenant_id))
    : null;

  return (
    <SocDashboard
      alerts={alerts}
      coverage={coverage}
      investigationEvents={investigationEvents}
      report={report}
      securityActivity={securityActivity}
      selectedAlert={selectedAlert}
      tenantId={searchParams?.tenant_id}
    />
  );
}

function contextQuery(alert: DetectionAlert, tenantId?: string) {
  const eventTime = new Date(alert.event_time);
  const startTime = new Date(eventTime.getTime() - 12 * 60 * 60 * 1000);
  const endTime = new Date(eventTime.getTime() + 12 * 60 * 60 * 1000);
  const category = eventCategory(alert.category);
  return {
    start_time: startTime.toISOString(),
    end_time: endTime.toISOString(),
    tenant_id: tenantId,
    source: alert.source_name,
    category,
    limit: 25,
  };
}

function eventCategory(value: string): string | undefined {
  return [
    "authentication",
    "authorization",
    "network",
    "endpoint",
    "ioc",
    "audit",
    "system",
    "generic",
  ].includes(value)
    ? value
    : undefined;
}
