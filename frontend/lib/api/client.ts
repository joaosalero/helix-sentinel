import type {
  AlertWorkflowUpdate,
  ApiResult,
  DetectionAlert,
  DetectionAlertListResponse,
  DetectionCoverageSummary,
  EventSearchResponse,
  SecurityActivitySummary,
  SocReport,
} from "@/lib/api/types";

const DEFAULT_API_BASE_URL = "http://localhost:8000/api/v1";

type QueryValue = string | number | boolean | null | undefined;

function apiBaseUrl(): string {
  return (process.env.HELIX_API_BASE_URL ?? DEFAULT_API_BASE_URL).replace(/\/$/, "");
}

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const url = new URL(`${apiBaseUrl()}${path}`);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function requestJson<T>(
  path: string,
  query?: Record<string, QueryValue>,
  init?: RequestInit,
): Promise<ApiResult<T>> {
  const headers = new Headers({ Accept: "application/json" });
  for (const [key, value] of new Headers(init?.headers).entries()) {
    headers.set(key, value);
  }
  const token = process.env.HELIX_API_TOKEN;
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  try {
    const response = await fetch(buildUrl(path, query), {
      ...init,
      headers,
      cache: "no-store",
    });
    if (!response.ok) {
      return {
        data: null,
        error: await responseError(response),
        status: response.status,
      };
    }
    return {
      data: (await response.json()) as T,
      error: null,
      status: response.status,
    };
  } catch (error) {
    return {
      data: null,
      error: error instanceof Error ? error.message : "API request failed",
      status: 0,
    };
  }
}

async function responseError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    return typeof body.detail === "string"
      ? body.detail
      : `API request failed with status ${response.status}`;
  } catch {
    return `API request failed with status ${response.status}`;
  }
}

export function getSocReport(query: {
  start_time: string;
  end_time: string;
  tenant_id?: string;
}): Promise<ApiResult<SocReport>> {
  return requestJson<SocReport>("/analytics/report", query);
}

export function getSecurityActivity(query: {
  start_time: string;
  end_time: string;
  tenant_id?: string;
  limit?: number;
}): Promise<ApiResult<SecurityActivitySummary>> {
  return requestJson<SecurityActivitySummary>("/analytics/security-activity", query);
}

export function getOpenAlerts(query: {
  tenant_id?: string;
  limit?: number;
}): Promise<ApiResult<DetectionAlertListResponse>> {
  return requestJson<DetectionAlertListResponse>("/detections/alerts", {
    ...query,
    status: "open",
  });
}

export function getDetectionCoverage(query: {
  start_time: string;
  end_time: string;
  tenant_id?: string;
  limit?: number;
}): Promise<ApiResult<DetectionCoverageSummary>> {
  return requestJson<DetectionCoverageSummary>("/detections/coverage", query);
}

export function getAlert(
  alertId: string,
  query?: { tenant_id?: string },
): Promise<ApiResult<DetectionAlert>> {
  return requestJson<DetectionAlert>(`/detections/alerts/${alertId}`, query);
}

export function updateAlertWorkflow(
  alertId: string,
  payload: AlertWorkflowUpdate,
  query?: { tenant_id?: string },
): Promise<ApiResult<DetectionAlert>> {
  return requestJson<DetectionAlert>(`/detections/alerts/${alertId}`, query, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function getInvestigationEvents(query: {
  start_time: string;
  end_time: string;
  tenant_id?: string;
  source?: string;
  category?: string;
  limit?: number;
}): Promise<ApiResult<EventSearchResponse>> {
  return requestJson<EventSearchResponse>("/analytics/events", query);
}
