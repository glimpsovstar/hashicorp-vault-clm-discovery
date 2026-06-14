import PageHeader from "@/components/page-header";
import InventoryTable from "@/components/inventory-table";
import { listCertificates } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function InventoryPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string; search?: string; scan_id?: string }>;
}) {
  const params = await searchParams;
  const query: Record<string, string> = {};
  if (params.status) query.status = params.status;
  if (params.search) query.search = params.search;
  if (params.scan_id) query.scan_id = params.scan_id;

  const { items: rawItems, total } = await listCertificates(query);
  const items = rawItems ?? [];

  return (
    <>
      <PageHeader
        title="Certificate inventory"
        description={
          params.scan_id
            ? `Certificates discovered in scan ${params.scan_id.slice(0, 8)}…`
            : "Discovered TLS certificates across scanned network targets. Filter by status or search by common name, SAN, or fingerprint."
        }
      />

      <section className="panel">
        <div className="panel-toolbar">
          <form method="get" className="form-row">
            <div className="form-field">
              <label htmlFor="status">Status</label>
              <select id="status" name="status" defaultValue={params.status || ""}>
                <option value="">All</option>
                <option value="valid">Valid</option>
                <option value="expiring_soon">Expiring soon</option>
                <option value="expired">Expired</option>
              </select>
            </div>
            <div className="form-field form-field-wide">
              <label htmlFor="search">Search</label>
              <input
                id="search"
                name="search"
                placeholder="CN, SAN, fingerprint"
                defaultValue={params.search || ""}
              />
            </div>
            {params.scan_id && (
              <input type="hidden" name="scan_id" value={params.scan_id} />
            )}
            <button type="submit" className="button button-primary">
              Apply filters
            </button>
          </form>
          <p className="count-text">{total} certificate(s)</p>
        </div>

        <div className="panel-body panel-body-flush data-table-wrap">
          <InventoryTable items={items} />
        </div>
      </section>
    </>
  );
}
