"use server";

import { revalidatePath } from "next/cache";

import { updateAlertWorkflow } from "@/lib/api/client";

export async function acknowledgeAlert(formData: FormData): Promise<void> {
  const alertId = requiredString(formData, "alert_id");
  const tenantId = optionalString(formData, "tenant_id");
  const note = optionalString(formData, "investigation_note");

  const result = await updateAlertWorkflow(
    alertId,
    {
      status: "acknowledged",
      investigation_note: note || "Investigation acknowledged from SOC console.",
    },
    { tenant_id: tenantId },
  );
  if (result.error) {
    throw new Error(result.error);
  }
  revalidatePath("/");
}

export async function closeAlert(formData: FormData): Promise<void> {
  const alertId = requiredString(formData, "alert_id");
  const tenantId = optionalString(formData, "tenant_id");
  const disposition = optionalString(formData, "disposition") || "true_positive";
  const note = optionalString(formData, "investigation_note");

  const result = await updateAlertWorkflow(
    alertId,
    {
      status: "closed",
      disposition,
      investigation_note: note || "Investigation closed from SOC console.",
    },
    { tenant_id: tenantId },
  );
  if (result.error) {
    throw new Error(result.error);
  }
  revalidatePath("/");
}

function requiredString(formData: FormData, name: string): string {
  const value = formData.get(name);
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function optionalString(formData: FormData, name: string): string | undefined {
  const value = formData.get(name);
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
