"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useRef, useState } from "react";

import {
  downloadReport,
  fetchJob,
  fetchReportText,
  getToken,
  storeToken,
  type JobState,
  type JobStatus,
} from "@/lib/api";

export default function JobPage() {
  return (
    <Suspense fallback={<Loading />}>
      <JobView />
    </Suspense>
  );
}

function Loading() {
  return (
    <main className="page">
      <div className="wrap">
        <p className="muted">Loading campaign…</p>
      </div>
    </main>
  );
}

const STAGES: { key: "queued" | "running" | "report"; label: string }[] = [
  { key: "queued", label: "Queued" },
  { key: "running", label: "Running" },
  { key: "report", label: "Report ready" },
];

function stageClass(stage: (typeof STAGES)[number]["key"], status: JobState | undefined): string {
  if (!status) return "";
  const order = { queued: 0, running: 1, report: 2 } as const;
  const current = status === "queued" ? 0 : status === "running" ? 1 : 2;
  const idx = order[stage];
  if (status === "failed" && stage === "report") return "failed";
  if (idx < current) return "complete";
  if (idx === current) {
    if (status === "done") return "complete";
    return "current live";
  }
  return "";
}

function stageNote(stage: (typeof STAGES)[number]["key"], job: JobStatus | null): string {
  if (!job) return "";
  const time = (iso: string | null) => (iso ? new Date(iso).toLocaleTimeString() : "");
  if (stage === "queued") return time(job.created_at);
  if (stage === "running") return job.started_at ? time(job.started_at) : "Waiting for a worker";
  if (job.status === "failed") return "The run failed";
  return job.finished_at ? time(job.finished_at) : "Up to 30 minutes";
}

function JobView() {
  const params = useParams<{ id: string }>();
  const search = useSearchParams();
  const id = params.id;
  const urlToken = search.get("token");
  const [token, setToken] = useState<string | null>(urlToken ?? null);
  const [tokenReady, setTokenReady] = useState(Boolean(urlToken));

  const [job, setJob] = useState<JobStatus | null>(null);
  const [report, setReport] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<"md" | "json" | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const resolved = urlToken ?? getToken(id);
    setToken(resolved);
    setTokenReady(true);
    if (urlToken) storeToken(id, urlToken);
  }, [id, urlToken]);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const next = await fetchJob(id, token);
      setJob(next);
      setError(null);

      if (next.status === "done" && next.report_available) {
        setReport(await fetchReportText(id, token));
        return;
      }
      if (next.status === "queued" || next.status === "running") {
        timer.current = setTimeout(load, 5_000);
      }
    } catch (cause) {
      const reason =
        cause instanceof TypeError
          ? "the Fuzzforge API isn't reachable"
          : cause instanceof Error
            ? cause.message
            : String(cause);
      setError(`Couldn't load this campaign: ${reason}. Retrying in 10 seconds.`);
      timer.current = setTimeout(load, 10_000);
    }
  }, [id, token]);

  useEffect(() => {
    load();
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [load]);

  async function download(kind: "md" | "json") {
    if (!token) return;
    setDownloading(kind);
    try {
      await downloadReport(id, token, kind);
    } catch (cause) {
      setError(`Download failed: ${cause instanceof Error ? cause.message : String(cause)}`);
    } finally {
      setDownloading(null);
    }
  }

  if (!tokenReady) return <Loading />;

  if (!token) {
    return (
      <main className="page">
        <div className="wrap empty-state">
          <h1>This link is missing its access token</h1>
          <p className="muted">
            The link you received after uploading is the only key to this
            campaign. Open that full link, including everything after the
            question mark, or upload the bundle again.
          </p>
          <div className="actions">
            <Link href="/submit" className="btn btn-primary">
              Upload a bundle
            </Link>
            <Link href="/" className="btn btn-quiet">
              Go to the home page
            </Link>
          </div>
        </div>
      </main>
    );
  }

  const status = job?.status;

  return (
    <main className="page">
      <div className="wrap">
        <div className="page-head">
          <h1>Fuzzing campaign</h1>
          <p className="job-id">Campaign {id}</p>
        </div>

        <ol className="track" aria-label="Campaign progress">
          {STAGES.map((s) => (
            <li
              key={s.key}
              className={stageClass(s.key, status)}
              aria-current={stageClass(s.key, status).includes("current") ? "step" : undefined}
            >
              {s.key === "report" && status === "failed" ? "Failed" : s.label}
              <span>{stageNote(s.key, job)}</span>
            </li>
          ))}
        </ol>

        <p className="keep-link">
          Bookmark this page. Its link is the only way back to this campaign and
          its report.
        </p>

        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}

        {job ? (
          <>
            <dl className="facts">
              <div>
                <dt>Executions</dt>
                <dd>{job.executions === null ? "Not yet" : job.executions.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Failing cases</dt>
                <dd>{job.failure_count === null ? "Not yet" : job.failure_count}</dd>
              </div>
              <div>
                <dt>Uploaded</dt>
                <dd className="small">{new Date(job.created_at).toLocaleString()}</dd>
              </div>
              <div>
                <dt>Finished</dt>
                <dd className="small">
                  {job.finished_at ? new Date(job.finished_at).toLocaleString() : "Not yet"}
                </dd>
              </div>
            </dl>

            {status === "failed" ? (
              <div className="run-failed" role="status">
                <h2>The campaign didn&apos;t finish</h2>
                <pre>{job.error ?? "No error detail was recorded."}</pre>
                <p>Fix the bundle and upload it again, or reply to your engagement email with this page&apos;s link.</p>
              </div>
            ) : null}

            <div className="detail-block">
              <h2>Invariants</h2>
              <p className="spec">{job.invariant_spec || "None given. The campaign ran the harness's own assertions."}</p>
            </div>

            <div className="detail-block">
              <h2>Bundle SHA-256</h2>
              <p className="mono">{job.bundle_sha256}</p>
            </div>
          </>
        ) : !error ? (
          <p className="muted">Loading campaign…</p>
        ) : null}

        {status === "done" ? (
          <section aria-labelledby="report-heading">
            <div className="job-title">
              <h2 id="report-heading">Report</h2>
              <div className="actions">
                <button className="btn btn-primary" onClick={() => download("md")} disabled={downloading !== null}>
                  {downloading === "md" ? "Downloading…" : "Download report"}
                </button>
                <button className="btn btn-quiet" onClick={() => download("json")} disabled={downloading !== null}>
                  {downloading === "json" ? "Downloading…" : "Download JSON data"}
                </button>
              </div>
            </div>
            <div className="report-doc">
              {report ? <pre>{report}</pre> : <p className="muted" style={{ padding: "1.5rem" }}>Loading report…</p>}
            </div>
          </section>
        ) : null}
      </div>
    </main>
  );
}
