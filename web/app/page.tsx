import Link from "next/link";
import { listCertificates, statusColor } from "@/lib/api";

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
    <section>
      <div className="card">
        <form method="get" className="form-row">
          <label>
            Status
            <select name="status" defaultValue={params.status || ""}>
              <option value="">All</option>
              <option value="valid">Valid</option>
              <option value="expiring_soon">Expiring soon</option>
              <option value="expired">Expired</option>
            </select>
          </label>
          <label>
            Search
            <input name="search" placeholder="CN, SAN, fingerprint" defaultValue={params.search || ""} />
          </label>
          <button type="submit">Filter</button>
        </form>
        <p className="muted">{total} certificate(s)</p>
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <table>
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
                  <Link href={`/certificates/${cert.id}`}>{cert.subject_cn || cert.fingerprint_sha256.slice(0, 12)}</Link>
                  {!cert.hostname_matches_san && (
                    <span className="muted" title="Hostname mismatch"> ⚠</span>
                  )}
                </td>
                <td>
                  <span className="badge" style={{ background: statusColor(cert.status) }}>
                    {cert.status}
                  </span>
                </td>
                <td>{cert.days_until_expiry}</td>
                <td>{cert.chain_status}</td>
                <td>{cert.observation_count ?? 0}</td>
                <td>{new Date(cert.last_seen).toLocaleString()}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">No certificates discovered yet. Run a scan.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
