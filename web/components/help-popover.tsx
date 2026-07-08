"use client";

import { useEffect, useId, useRef, useState, type ReactNode } from "react";

// HelpPopover renders a small "?" affordance next to a control. Clicking it opens
// a short explanation panel. It closes on Escape or an outside click and returns
// focus to the trigger. Purely presentational — no data dependencies.
export default function HelpPopover({
  label = "What does this do?",
  children,
}: {
  label?: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelId = useId();

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    function onClick(e: MouseEvent) {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
    };
  }, [open]);

  return (
    <span className="help-popover" ref={wrapRef}>
      <button
        type="button"
        ref={triggerRef}
        className="help-popover-trigger"
        aria-label={label}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
      >
        ?
      </button>
      {open && (
        <span className="help-popover-panel" id={panelId} role="tooltip">
          {children}
        </span>
      )}
    </span>
  );
}
