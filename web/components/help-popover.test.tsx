import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import HelpPopover from "./help-popover";

describe("HelpPopover", () => {
  it("is closed initially and opens on click", async () => {
    render(<HelpPopover label="Explain">Hello help</HelpPopover>);
    const trigger = screen.getByRole("button", { name: "Explain" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("tooltip")).toBeNull();

    await userEvent.click(trigger);

    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("tooltip")).toHaveTextContent("Hello help");
  });

  it("closes on Escape", async () => {
    render(<HelpPopover label="Explain">Hello help</HelpPopover>);
    const trigger = screen.getByRole("button", { name: "Explain" });

    await userEvent.click(trigger);
    await userEvent.keyboard("{Escape}");

    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("closes on outside click", async () => {
    render(
      <div>
        <HelpPopover label="Explain">Hello help</HelpPopover>
        <button>outside</button>
      </div>
    );

    await userEvent.click(screen.getByRole("button", { name: "Explain" }));
    expect(screen.getByRole("tooltip")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "outside" }));
    expect(screen.queryByRole("tooltip")).toBeNull();
  });
});
