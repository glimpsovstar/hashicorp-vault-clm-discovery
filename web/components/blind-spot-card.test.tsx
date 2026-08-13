import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { fetchBlindSpot, triggerReconcile } from "@/lib/api";

// fetchBlindSpot runs in an effect on mount; stub the API module so the card
// renders in isolation.
vi.mock("@/lib/api", () => ({
  fetchBlindSpot: vi.fn(),
  triggerReconcile: vi.fn(),
}));

import BlindSpotCard from "./blind-spot-card";

const mockedFetchBlindSpot = vi.mocked(fetchBlindSpot);
const mockedTriggerReconcile = vi.mocked(triggerReconcile);

beforeEach(() => {
  mockedFetchBlindSpot.mockReset();
  mockedTriggerReconcile.mockReset();
  mockedFetchBlindSpot.mockResolvedValue({
    vault_managed: 34,
    discovered: 50,
    shadow: 16,
    sc081_violations: 4,
  });
});

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

describe("BlindSpotCard Vault not configured", () => {
  it("points operators to Settings instead of README-only env setup", async () => {
    mockedTriggerReconcile.mockRejectedValue(new Error("vault not configured"));

    renderCard();
    await userEvent.click(await screen.findByRole("button", { name: /Show shadow certs/ }));

    const link = await screen.findByRole("link", { name: /settings/i });
    expect(link).toHaveAttribute("href", "/settings/connections");
    expect(screen.queryByRole("link", { name: /readme/i })).not.toBeInTheDocument();
  });
});
