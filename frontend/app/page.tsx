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
  searchParams: Promise<{
    alert_id?: string | string[];
    tenant_id?: string | string[];
  }>;
};

export default async function Home({ searchParams }: HomeProps) {
  const query = await searchParams;
  const alertId = Array.isArray(query.alert_id) ? query.alert_id[0] : query.alert_id;
  const tenantId = Array.isArray(query.tenant_id) ? query.tenant_id[0] : query.tenant_id;
  const endTime = new Date();
  const startTime = new Date(endTime.getTime() - 7 * 24 * 60 * 60 * 1000);
  const params = {
    start_time: startTime.toISOString(),
    end_time: endTime.toISOString(),
    tenant_id: tenantId,
  };

  const [report, alerts, coverage, securityActivity, selectedAlert] = await Promise.all([
    getSocReport(params),
    getOpenAlerts({ tenant_id: tenantId, limit: 8 }),
    getDetectionCoverage({ ...params, limit: 6 }),
    getSecurityActivity({ ...params, limit: 8 }),
    alertId ? getAlert(alertId, { tenant_id: tenantId }) : Promise.resolve(null),
  ]);
  const investigationEvents = selectedAlert?.data
    ? await getInvestigationEvents(contextQuery(selectedAlert.data, tenantId))
    : null;

  return (
    <SocDashboard
      alerts={alerts}
      coverage={coverage}
      investigationEvents={investigationEvents}
      report={report}
      securityActivity={securityActivity}
      selectedAlert={selectedAlert}
      tenantId={tenantId}
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
