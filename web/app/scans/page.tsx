import { listScans } from "@/lib/api";
import ScanForm from "./scan-form";

export default async function ScansPage() {
  const { items: rawItems } = await listScans();
  const items = rawItems ?? [];

  return (
    <section>
      <div className="card">
        <h2>Start scan</h2>
        <ScanForm />
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <h3 style={{ padding: "16px 16px 0" }}>Scan history</h3>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Status</th>
              <th>CIDRs</th>
              <th>Progress</th>
              <th>Certs</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {items.map((scan) => (
              <tr key={scan.id}>
                <td>{scan.id.slice(0, 8)}…</td>
                <td>{scan.status}</td>
                <td>{scan.hostnames?.length ? scan.hostnames.join(", ") : scan.cidrs.join(", ") || "—"}</td>
                <td>{scan.targets_scanned}/{scan.targets_total}</td>
                <td>{scan.certs_found}</td>
                <td>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">No scans yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
