import { describe, expect, it } from "vitest";
import { reconcileStatusMessage } from "@/lib/reconcile";
import type { ReconcileSummary } from "@/lib/api";

function summary(overrides: Partial<ReconcileSummary>): ReconcileSummary {
  return {
    mounts_scanned: 1,
    vault_certs_read: 0,
    matched: 0,
    unmatched_clm: 0,
    status: "ok",
    errors: [],
    ...overrides,
  };
}

describe("reconcileStatusMessage", () => {
  it("returns the success base unchanged when status is ok", () => {
    const msg = reconcileStatusMessage(summary({ status: "ok" }), "Reconcile complete: 3 matched");
    expect(msg).toBe("Reconcile complete: 3 matched");
  });

  it("reports a failure (not success) when nothing could be read", () => {
    const msg = reconcileStatusMessage(
      summary({ status: "failed", mounts_scanned: 2, errors: ["pki/: 403"] }),
      "Reconcile complete: 0 matched"
    );
    expect(msg).not.toContain("complete");
    expect(msg).toContain("Reconcile failed");
    expect(msg).toContain("2 PKI mount(s)");
    expect(msg).toContain("pki/: 403");
  });

  it("does not append a trailing space when a failed run has no error detail", () => {
    const msg = reconcileStatusMessage(summary({ status: "failed", errors: [] }), "base");
    expect(msg).toBe(msg.trim());
  });

  it("appends an error count to the success base on a partial run", () => {
    const msg = reconcileStatusMessage(
      summary({ status: "partial", vault_certs_read: 5, errors: ["a", "b"] }),
      "Reconcile complete: 4 matched"
    );
    expect(msg).toContain("Reconcile complete: 4 matched");
    expect(msg).toContain("2 error(s)");
  });
});
