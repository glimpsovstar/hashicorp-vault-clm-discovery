"use client";

import { useEffect, useRef, useState } from "react";
import { downloadReport } from "@/lib/api";

const FORMATS: { format: "markdown" | "csv" | "json"; label: string }[] = [
  { format: "markdown", label: "Markdown (.md)" },
  { format: "csv", label: "CSV (.csv)" },
  { format: "json", label: "JSON (.json)" },
];

// ReportDownloadMenu offers the report in each supported format. It reuses the
// existing /report?format= endpoints via downloadReport(); the report page is the
// view-first entry point, and download lives here rather than on the scan card.
export default function ReportDownloadMenu({ scanId }: { scanId: string }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onClick(e: MouseEvent) {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  async function onDownload(format: "markdown" | "csv" | "json") {
    setBusy(true);
    setMessage("");
    try {
      await downloadReport(scanId, format);
      setOpen(false);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Download failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="download-menu" ref={wrapRef}>
      <button
        type="button"
        className="button button-secondary"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        disabled={busy}
      >
        {busy ? "Downloading…" : "Download ▾"}
      </button>
      {open && (
        <div className="download-menu-panel" role="menu">
          {FORMATS.map(({ format, label }) => (
            <button
              key={format}
              type="button"
              role="menuitem"
              className="download-menu-item"
              onClick={() => void onDownload(format)}
              disabled={busy}
            >
              {label}
            </button>
          ))}
        </div>
      )}
      {message && <p className="error-text">{message}</p>}
    </div>
  );
}
