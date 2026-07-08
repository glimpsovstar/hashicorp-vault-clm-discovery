import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

// fetchBlindSpot runs in an effect on mount; stub the API module so the card
// renders in isolation. triggerReconcile is unused by these assertions.
vi.mock("@/lib/api", () => ({
  fetchBlindSpot: vi.fn().mockResolvedValue({
    vault_managed: 34, discovered: 50, shadow: 16, sc081_violations: 4,
  }),
  triggerReconcile: vi.fn(),
}));

import BlindSpotCard from "./blind-spot-card";

function renderCard() {
  return render(<BlindSpotCard scanId="s1" scanStatus="completed" />);
}

describe("BlindSpotCard help popovers", () => {
  it("puts a help popover on On wire, Shadow certs, and SC-081 violations", async () => {
    renderCard();
    // Flush the mount effect so any state settle happens inside act().
    expect(await screen.findByRole("button", { name: /What is .*On wire/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /What is .*Shadow certs/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /What is .*SC-081 violations/ })).toBeInTheDocument();
  });

  it("does not put a help popover on Vault managed", async () => {
    renderCard();
    await screen.findByRole("button", { name: /What is .*On wire/ });
    expect(screen.queryByRole("button", { name: /What is .*Vault managed/ })).toBeNull();
  });

  it("leaves Show shadow certs and View report as plain controls (no help popover)", async () => {
    renderCard();
    await screen.findByRole("button", { name: /What is .*On wire/ });
    expect(screen.getByRole("button", { name: /Show shadow certs/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View report/ })).toBeInTheDocument();
    // The old popovers were labelled "What does Show shadow certs do?" / "What is the report?".
    expect(screen.queryByRole("button", { name: /What does Show shadow certs/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /What is the report/ })).toBeNull();
  });
});
