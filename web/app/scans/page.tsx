import PageHeader from "@/components/page-header";
import ScanHistoryTable from "@/components/scan-history-table";
import { listScans } from "@/lib/api";
import ScanForm from "./scan-form";

export const dynamic = "force-dynamic";

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
          <ScanHistoryTable initialItems={items} />
        </div>
      </section>
    </>
  );
}
