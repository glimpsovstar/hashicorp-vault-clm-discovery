import Link from "next/link";
import PageHeader from "@/components/page-header";
import InventoryTable from "@/components/inventory-table";
import { getScan, listScanCertificates, scanStatusBadgeClass } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = await getScan(id);
  const { items: certs, total } = await listScanCertificates(id);

  const targets = scan.hostnames?.length
    ? scan.hostnames.join(", ")
    : scan.cidrs.join(", ") || "—";

  return (
    <>
      <PageHeader
        title={`Scan ${scan.id.slice(0, 8)}…`}
        subtitle="Scans"
        description={`Targets: ${targets} · Progress ${scan.targets_scanned}/${scan.targets_total} · ${scan.certs_found} certificate(s) persisted`}
        breadcrumbs={<Link href="/scans">← Back to scans</Link>}
        actions={
          <Link className="button button-secondary" href={`/?scan_id=${scan.id}`}>
            Filter inventory
          </Link>
        }
      />

      <section className="panel">
        <div className="panel-body">
          <p>
            <span className={scanStatusBadgeClass(scan.status)}>{scan.status}</span>
          </p>
          <div className="detail-list">
            <p>
              <strong>Started:</strong>{" "}
              {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
            </p>
            <p>
              <strong>Finished:</strong>{" "}
              {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "—"}
            </p>
            <p>
              <strong>Ports:</strong> {scan.ports.join(", ")}
            </p>
            {scan.error && (
              <p>
                <strong>Notes:</strong> {scan.error}
              </p>
            )}
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Discovered certificates ({total})</h2>
        </div>
        <div className="panel-body panel-body-flush data-table-wrap">
          <InventoryTable items={certs ?? []} />
        </div>
      </section>
    </>
  );
}
