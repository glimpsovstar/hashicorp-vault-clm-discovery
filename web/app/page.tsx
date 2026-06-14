import Link from "next/link";
import PageHeader from "@/components/page-header";
import { listCertificates, statusBadgeClass } from "@/lib/api";

export default async function InventoryPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string; search?: string }>;
}) {
  const params = await searchParams;
  const query: Record<string, string> = {};
  if (params.status) query.status = params.status;
  if (params.search) query.search = params.search;

  const { items: rawItems, total } = await listCertificates(query);
  const items = rawItems ?? [];

  return (
    <>
      <PageHeader
        title="Certificate inventory"
        description="Discovered TLS certificates across scanned network targets. Filter by status or search by common name, SAN, or fingerprint."
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
            <button type="submit" className="button button-primary">
              Apply filters
            </button>
          </form>
          <p className="count-text">{total} certificate(s)</p>
        </div>

        <div className="panel-body panel-body-flush data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Subject CN</th>
                <th>Status</th>
                <th>Days left</th>
                <th>Chain</th>
                <th>Observations</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((cert) => (
                <tr key={cert.id}>
                  <td>
                    <Link href={`/certificates/${cert.id}`}>
                      {cert.subject_cn || cert.fingerprint_sha256.slice(0, 12)}
                    </Link>
                    {!cert.hostname_matches_san && (
                      <span className="muted" title="Hostname mismatch">
                        {" "}
                        ⚠
                      </span>
                    )}
                  </td>
                  <td>
                    <span className={statusBadgeClass(cert.status)}>{cert.status}</span>
                  </td>
                  <td>{cert.days_until_expiry}</td>
                  <td>{cert.chain_status}</td>
                  <td>{cert.observation_count ?? 0}</td>
                  <td>{new Date(cert.last_seen).toLocaleString()}</td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No certificates discovered yet. Run a scan from the Scans page.
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
