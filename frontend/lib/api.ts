export const API_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080"
).replace(/\/$/, "");

export const CONTACT_EMAIL =
  process.env.NEXT_PUBLIC_CONTACT_EMAIL ?? "jutenoh@gmail.com";

export type JobState ="queued" | "running" | "done" | "failed";

export type JobStatus = {
  id: string;
  status: JobState;
  bundle_sha256: string;
  invariant_spec: string;
  executions: number | null;
  failure_count: number | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  report_available: boolean;
};

export type SubmitResponse = {
  id: string;
  token: string;
  status: JobState;
  notice: string;
};

export function tokenKey(id: string): string {
  return `fuzzforge.token.${id}`;
}

export function storeToken(id: string, token: string): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(tokenKey(id), token);
  } catch {
    // Private browsing and full storage are not worth failing a submission.
  }
}

export function getToken(id: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(tokenKey(id));
  } catch {
    return null;
  }
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: string };
    if (body.error) return body.error;
  } catch {
    // fall through
  }
  return `${response.status} ${response.statusText}`;
}

export async function fetchJob(id: string, token: string): Promise<JobStatus> {
  const response = await fetch(`${API_URL}/jobs/${id}`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(await errorMessage(response));
  return (await response.json()) as JobStatus;
}

export async function fetchReportText(
  id: string,
  token: string,
): Promise<string> {
  const response = await fetch(`${API_URL}/jobs/${id}/report`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(await errorMessage(response));
  return response.text();
}

export async function downloadReport(
  id: string,
  token: string,
  kind: "md" | "json",
): Promise<void> {
  const suffix = kind === "json" ? "/report.json" : "/report";
  const response = await fetch(`${API_URL}/jobs/${id}${suffix}`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(await errorMessage(response));

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `fuzzforge-${id}.${kind}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
