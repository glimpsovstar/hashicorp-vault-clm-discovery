import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api", () => ({
  downloadReport: vi.fn(),
}));

import { downloadReport } from "@/lib/api";
import ReportDownloadMenu from "./report-download-menu";

const mockDownload = vi.mocked(downloadReport);

describe("ReportDownloadMenu", () => {
  beforeEach(() => {
    mockDownload.mockReset();
  });

  it("opens the menu and downloads the chosen format", async () => {
    mockDownload.mockResolvedValue(undefined);
    render(<ReportDownloadMenu scanId="scan-1" />);

    await userEvent.click(screen.getByRole("button", { name: /download/i }));
    await userEvent.click(screen.getByRole("menuitem", { name: /CSV/ }));

    expect(mockDownload).toHaveBeenCalledWith("scan-1", "csv");
  });

  it("shows an error message when the download fails", async () => {
    mockDownload.mockRejectedValue(new Error("boom"));
    render(<ReportDownloadMenu scanId="scan-1" />);

    await userEvent.click(screen.getByRole("button", { name: /download/i }));
    await userEvent.click(screen.getByRole("menuitem", { name: /JSON/ }));

    expect(await screen.findByText("boom")).toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    render(<ReportDownloadMenu scanId="scan-1" />);

    await userEvent.click(screen.getByRole("button", { name: /download/i }));
    expect(screen.getByRole("menu")).toBeInTheDocument();

    await userEvent.keyboard("{Escape}");

    expect(screen.queryByRole("menu")).toBeNull();
  });
});
