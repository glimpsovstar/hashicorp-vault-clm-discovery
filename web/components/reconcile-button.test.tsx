import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ReconcileButton from "@/components/reconcile-button";
import { triggerReconcile } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

vi.mock("@/lib/api", () => ({
  triggerReconcile: vi.fn(),
}));

const mockedTriggerReconcile = vi.mocked(triggerReconcile);

beforeEach(() => {
  mockedTriggerReconcile.mockReset();
});

describe("ReconcileButton", () => {
  it("shows a failure message (not success) when the reconcile fully fails", async () => {
    mockedTriggerReconcile.mockResolvedValue({
      mounts_scanned: 1,
      vault_certs_read: 0,
      matched: 0,
      unmatched_clm: 0,
      status: "failed",
      errors: ["pki/: status 403"],
    });

    render(<ReconcileButton />);
    await userEvent.click(screen.getByRole("button", { name: /reconcile with vault/i }));

    expect(await screen.findByText(/Reconcile failed/i)).toBeInTheDocument();
    expect(screen.queryByText(/Reconcile complete/i)).not.toBeInTheDocument();
  });

  it("shows a success message when the reconcile succeeds", async () => {
    mockedTriggerReconcile.mockResolvedValue({
      mounts_scanned: 2,
      vault_certs_read: 15,
      matched: 12,
      unmatched_clm: 3,
      status: "ok",
      errors: [],
    });

    render(<ReconcileButton />);
    await userEvent.click(screen.getByRole("button", { name: /reconcile with vault/i }));

    expect(await screen.findByText(/Reconcile complete: 12 matched/i)).toBeInTheDocument();
  });
});
