import { SocDashboard } from "@/features/soc-dashboard/soc-dashboard";
import { getOpenAlerts, getSocReport } from "@/lib/api/client";

export const dynamic = "force-dynamic";

type HomeProps = {
  searchParams?: {
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

  const [report, alerts] = await Promise.all([
    getSocReport(params),
    getOpenAlerts({ tenant_id: searchParams?.tenant_id, limit: 8 }),
  ]);

  return <SocDashboard alerts={alerts} report={report} />;
}
