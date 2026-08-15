import PageHeader from "@/components/page-header";
import InventoryTable from "@/components/inventory-table";
import ReconcileButton from "@/components/reconcile-button";
import { listCertificates } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function InventoryPage({
  searchParams,
}: {
  searchParams: Promise<{
    status?: string;
    search?: string;
    scan_id?: string;
    sort?: string;
    min_risk?: string;
    pqc_tag?: string;
  }>;
}) {
  const params = await searchParams;
  const query: Record<string, string> = {};
  if (params.status) query.status = params.status;
  if (params.search) query.search = params.search;
  if (params.scan_id) query.scan_id = params.scan_id;
  if (params.sort) query.sort = params.sort;
  if (params.min_risk) query.min_risk = params.min_risk;
  if (params.pqc_tag) query.pqc_tag = params.pqc_tag;

  const { items: rawItems, total } = await listCertificates(query);
  const items = rawItems ?? [];

  return (
    <>
      <PageHeader
        title="Certificate inventory"
        description={
          params.scan_id
            ? `Certificates discovered in scan ${params.scan_id.slice(0, 8)}…`
            : "Discovered TLS certificates across scanned network targets. Filter by status, risk, or PQC tag."
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
            <div className="form-field">
              <label htmlFor="sort">Sort</label>
              <select id="sort" name="sort" defaultValue={params.sort || ""}>
                <option value="">Last seen</option>
                <option value="risk_score">Risk score</option>
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="min_risk">Min risk</label>
              <select id="min_risk" name="min_risk" defaultValue={params.min_risk || ""}>
                <option value="">Any</option>
                <option value="70">High+</option>
                <option value="90">Critical</option>
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="pqc_tag">PQC</label>
              <select id="pqc_tag" name="pqc_tag" defaultValue={params.pqc_tag || ""}>
                <option value="">All</option>
                <option value="classic">Classic</option>
                <option value="hybrid">Hybrid</option>
                <option value="pqc">PQC</option>
                <option value="unknown">Unknown</option>
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
          <ReconcileButton />
        </div>

        <div className="panel-body panel-body-flush data-table-wrap">
          <InventoryTable items={items} />
        </div>
      </section>
    </>
  );
}
