import type {
  Finding,
  HealthResponse,
  ReportFormat,
  ScanRead,
  ScanStart,
} from "../types";

const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      ...(options?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...options?.headers,
    },
  });
  if (!response.ok) {
    const body = await response.text();
    let message = body || response.statusText;
    try {
      const parsed = JSON.parse(body) as { detail?: string };
      message = parsed.detail ?? message;
    } catch {
      // Keep the response body as the error message when it is not JSON.
    }
    throw new Error(`API ${response.status}: ${message}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export function listScans(limit = 100): Promise<ScanRead[]> {
  return request<ScanRead[]>(`/scans/?limit=${limit}`);
}

export function getScan(id: string): Promise<ScanRead> {
  return request<ScanRead>(`/scans/${encodeURIComponent(id)}`);
}

export function deleteScan(id: string): Promise<{ detail: string }> {
  return request<{ detail: string }>(`/scans/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function cancelScan(id: string): Promise<{ detail: string }> {
  return request<{ detail: string }>(`/scans/${encodeURIComponent(id)}/cancel`, {
    method: "POST",
  });
}

export async function uploadFile(
  file: File,
  projectName: string,
  enableBandit: boolean
): Promise<ScanStart> {
  const form = new FormData();
  form.append("file", file);
  form.append("project_name", projectName);
  form.append("enable_bandit", String(enableBandit));
  return request<ScanStart>("/scans/upload/file", { method: "POST", body: form });
}

export async function uploadZip(
  file: File,
  projectName: string,
  enableBandit: boolean
): Promise<ScanStart> {
  const form = new FormData();
  form.append("file", file);
  form.append("project_name", projectName);
  form.append("enable_bandit", String(enableBandit));
  return request<ScanStart>("/scans/upload/zip", { method: "POST", body: form });
}

export function scanSamples(
  set: "vulnerable" | "safe" | "all",
  enableBandit: boolean
): Promise<ScanStart> {
  return request<ScanStart>(
    `/scans/samples/${set}?enable_bandit=${enableBandit}`,
    { method: "POST" }
  );
}

export async function listFindings(): Promise<Finding[]> {
  return request<Finding[]>("/scans/findings/?limit=1000");
}

export async function downloadReport(
  id: string,
  format: ReportFormat
): Promise<void> {
  const response = await fetch(
    `${BASE}/scans/${encodeURIComponent(id)}/report?format=${format}`
  );
  if (!response.ok) {
    const body = await response.text();
    let message = body || response.statusText;
    try {
      const parsed = JSON.parse(body) as { detail?: string };
      message = parsed.detail ?? message;
    } catch {
      // Keep the response body as the error message when it is not JSON.
    }
    throw new Error(`API ${response.status}: ${message}`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `vulnpath_${id}.${format === "sarif" ? "sarif" : format === "markdown" ? "md" : "json"}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
