import PageHeader from "@/components/page-header";
import { listScans } from "@/lib/api";
import ScanForm from "./scan-form";

export default async function ScansPage() {
  const { items: rawItems } = await listScans();
  const items = rawItems ?? [];

  return (
    <>
      <PageHeader
        title="Scans"
        description="Start authorized TLS discovery scans and review scan history."
      />

      <section className="panel">
        <div className="panel-header">
          <h2>Start scan</h2>
        </div>
        <div className="panel-body">
          <ScanForm />
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Scan history</h2>
        </div>
        <div className="panel-body panel-body-flush data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Status</th>
                <th>Targets</th>
                <th>Progress</th>
                <th>Certs</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {items.map((scan) => (
                <tr key={scan.id}>
                  <td>
                    <code>{scan.id.slice(0, 8)}…</code>
                  </td>
                  <td>
                    <span className="badge badge-neutral">{scan.status}</span>
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
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No scans yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
