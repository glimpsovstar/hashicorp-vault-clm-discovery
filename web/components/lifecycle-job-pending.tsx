"use client";

import { useEffect, useState } from "react";
import { getLifecycleJob, type LifecycleJob } from "@/lib/api";

function formatWhen(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function LifecycleJobPending({
  jobId,
  initial,
}: {
  jobId: string;
  initial?: LifecycleJob | null;
}) {
  const [job, setJob] = useState<LifecycleJob | null>(initial ?? null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const next = await getLifecycleJob(jobId);
        if (!cancelled) {
          setJob(next);
          setError("");
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load job");
        }
      }
    }
    void load();
    const pending = !job || job.user_status === "Pending";
    if (!pending) {
      return () => {
        cancelled = true;
      };
    }
    const t = setInterval(() => void load(), 10_000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [jobId, job?.user_status]);

  if (error) {
    return <p className="help-text">{error}</p>;
  }
  if (!job) {
    return <p className="help-text">Loading migrate status…</p>;
  }

  const badge =
    job.user_status === "Verified"
      ? "badge badge-ok"
      : job.user_status === "Timed out" || job.user_status === "Failed"
        ? "badge badge-danger"
        : "badge badge-warn";

  return (
    <div className="panel" style={{ marginTop: 12 }} data-testid="lifecycle-job-pending">
      <div className="panel-body">
        <p>
          <span className={badge}>{job.user_status || "Pending"}</span>
        </p>
        <p className="help-text">
          Attempt {job.verify_attempt}
          {job.next_verify_at ? ` · Next check ${formatWhen(job.next_verify_at)}` : ""}
          {job.timeout_at ? ` · Times out ${formatWhen(job.timeout_at)}` : ""}
        </p>
      </div>
    </div>
  );
}
