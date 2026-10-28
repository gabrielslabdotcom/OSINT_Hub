import type {
  Analysis,
  Bundle,
  CompareResult,
  Correlation,
  HubStatus,
  JobEvent,
  JobSnapshot,
  Phase2Dossier,
  RunSummary,
  TargetRow,
} from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export const api = {
  status: () => request<HubStatus>("/api/status"),
  runs: () => request<{ runs: RunSummary[] }>("/api/runs"),
  run: (id: string) => request<RunSummary>(`/api/runs/${id}`),
  bundle: (id: string) => request<Bundle>(`/api/runs/${id}/bundle`),
  correlations: (id: string) => request<Correlation[]>(`/api/runs/${id}/correlations`),
  report: (id: string) => request<{ markdown: string }>(`/api/runs/${id}/report`),
  analysis: (id: string, provider: "local" | "claude") =>
    request<Analysis>(`/api/runs/${id}/analysis/${provider}`),
  targets: (id: string) => request<TargetRow[]>(`/api/runs/${id}/targets`),
  compare: (id: string) => request<CompareResult>(`/api/runs/${id}/compare`),
  investigate: (domain: string, analyze: "none" | "local" | "claude") =>
    request<JobSnapshot>("/api/runs", {
      method: "POST",
      body: JSON.stringify({ domain, analyze }),
    }),
  deleteRun: (id: string) =>
    request<{ ok: boolean; run_id: string }>(`/api/runs/${id}`, { method: "DELETE" }),
  deleteAllRuns: () =>
    request<{ ok: boolean; deleted: number }>("/api/runs", { method: "DELETE" }),
  generateReport: (id: string) =>
    request<{ ok: boolean; correlations: number }>(`/api/runs/${id}/report`, { method: "POST" }),
  analyze: (id: string, provider: "local" | "claude") =>
    request<JobSnapshot>(`/api/runs/${id}/analyze`, {
      method: "POST",
      body: JSON.stringify({ provider }),
    }),
  buildTargets: (id: string) =>
    request<{ ok: boolean; targets: TargetRow[] }>(`/api/runs/${id}/targets`, { method: "POST" }),
  phase2: (id: string) => request<Phase2Dossier>(`/api/runs/${id}/phase2`),
  buildPhase2: (id: string) =>
    request<{ ok: boolean; phase2: Phase2Dossier }>(`/api/runs/${id}/phase2`, { method: "POST" }),
  patchPhase2Task: (id: string, taskId: string, status: "open" | "done") =>
    request<Phase2Dossier>(`/api/runs/${id}/phase2`, {
      method: "PATCH",
      body: JSON.stringify({ task_id: taskId, status }),
    }),
  job: (id: string) => request<JobSnapshot>(`/api/jobs/${id}`),
};

export function subscribeJob(jobId: string, onEvent: (event: JobEvent) => void): () => void {
  const source = new EventSource(`/api/jobs/${jobId}/events`);
  source.onmessage = (message) => {
    try {
      onEvent(JSON.parse(message.data) as JobEvent);
    } catch {
      /* ignore malformed frames */
    }
  };
  source.addEventListener("end", () => source.close());
  source.onerror = () => {
    /* EventSource retries; close on terminal page hide via returned disposer */
  };
  return () => source.close();
}
