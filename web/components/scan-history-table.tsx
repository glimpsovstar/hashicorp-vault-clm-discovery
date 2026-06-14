"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { listScans, scanStatusBadgeClass, type Scan } from "@/lib/api";

function hasActiveScans(items: Scan[]) {
  return items.some((s) => s.status === "pending" || s.status === "running");
}

export default function ScanHistoryTable({ initialItems }: { initialItems: Scan[] }) {
  const router = useRouter();
  const [items, setItems] = useState(initialItems);

  useEffect(() => {
    setItems(initialItems);
  }, [initialItems]);

  const active = hasActiveScans(items);

  useEffect(() => {
    if (!active) {
      return;
    }

    const id = window.setInterval(async () => {
      try {
        const { items: next } = await listScans();
        setItems(next ?? []);
        if (!hasActiveScans(next ?? [])) {
          router.refresh();
        }
      } catch {
        // keep showing last known state
      }
    }, 2000);

    return () => window.clearInterval(id);
  }, [active, router]);

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Status</th>
          <th>Targets</th>
          <th>Progress</th>
          <th>Certs</th>
          <th>Started</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {items.map((scan) => (
          <tr key={scan.id}>
            <td>
              <code>{scan.id.slice(0, 8)}…</code>
            </td>
            <td>
              <span className={scanStatusBadgeClass(scan.status)}>{scan.status}</span>
            </td>
            <td>
              {scan.hostnames?.length
                ? scan.hostnames.join(", ")
                : scan.cidrs.join(", ") || "—"}
            </td>
            <td>
              {scan.targets_scanned}/{scan.targets_total}
            </td>
            <td>{scan.certs_found}</td>
            <td>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}</td>
            <td className="muted" style={{ maxWidth: 280 }}>
              {scan.error || "—"}
            </td>
          </tr>
        ))}
        {items.length === 0 && (
          <tr>
            <td colSpan={7} className="muted">
              No scans yet.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}
