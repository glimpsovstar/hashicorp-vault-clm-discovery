import { listIssuers, statusColor } from "@/lib/api";

export default async function IssuersPage() {
  const { items } = await listIssuers();

  return (
    <section>
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <h2 style={{ padding: "16px 16px 0" }}>Issuers &amp; CAs</h2>
        <table>
          <thead>
            <tr>
              <th>Subject CN</th>
              <th>Status</th>
              <th>Days left</th>
              <th>Issuer DN</th>
              <th>CA</th>
            </tr>
          </thead>
          <tbody>
            {items.map((issuer) => (
              <tr key={issuer.id}>
                <td>{issuer.subject_cn || issuer.fingerprint_sha256.slice(0, 12)}</td>
                <td>
                  <span className="badge" style={{ background: statusColor(issuer.status) }}>
                    {issuer.status}
                  </span>
                </td>
                <td>{issuer.days_until_expiry}</td>
                <td>{issuer.issuer_dn}</td>
                <td>{issuer.is_ca ? "Yes" : "No"}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">No issuers discovered yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
