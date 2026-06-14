import PageHeader from "@/components/page-header";
import { listIssuers, statusBadgeClass } from "@/lib/api";

export default async function IssuersPage() {
  const { items: rawItems } = await listIssuers();
  const items = rawItems ?? [];

  return (
    <>
      <PageHeader
        title="Issuers"
        description="Certificate authorities and issuing entities discovered during scans."
      />

      <section className="panel">
        <div className="panel-body panel-body-flush data-table-wrap">
          <table className="data-table">
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
                    <span className={statusBadgeClass(issuer.status)}>{issuer.status}</span>
                  </td>
                  <td>{issuer.days_until_expiry}</td>
                  <td>{issuer.issuer_dn}</td>
                  <td>{issuer.is_ca ? "Yes" : "No"}</td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    No issuers discovered yet.
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
