import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import LifecycleJobPending from "@/components/lifecycle-job-pending";
import { getLifecycleJob, type LifecycleJob } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  getLifecycleJob: vi.fn(),
}));

const mockedGet = vi.mocked(getLifecycleJob);

beforeEach(() => {
  mockedGet.mockReset();
});

describe("LifecycleJobPending", () => {
  it("shows Pending badge with attempt and next-check / timeout", async () => {
    const job: LifecycleJob = {
      id: "j1",
      status: "pending_verify",
      user_status: "Pending",
      verify_attempt: 3,
      next_verify_at: "2026-08-13T12:30:00Z",
      timeout_at: "2026-08-14T12:00:00Z",
    };
    mockedGet.mockResolvedValue(job);
    render(<LifecycleJobPending jobId="j1" initial={job} />);
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(screen.getByText(/Attempt 3/)).toBeInTheDocument();
    expect(screen.getByText(/Next check/i)).toBeInTheDocument();
    expect(screen.getByText(/Times out/i)).toBeInTheDocument();
  });
});
