import Link from "next/link";
import PageHeader from "@/components/page-header";
import { getCertificate, statusBadgeClass } from "@/lib/api";
import EnrichmentForm from "./enrichment-form";

export default async function CertificateDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const { certificate: cert, observations: rawObservations } = await getCertificate(id);
  const observations = rawObservations ?? [];

  return (
    <>
      <PageHeader
        title={cert.subject_cn || "Certificate"}
        subtitle="Certificate inventory"
        description={`Fingerprint ${cert.fingerprint_sha256}`}
        breadcrumbs={
          <Link href="/">← Back to certificate inventory</Link>
        }
        actions={
          <a
            className="button button-secondary"
            href={`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080"}/api/v1/certificates/${cert.id}/pem`}
          >
            Download PEM
          </a>
        }
      />

      <section className="panel">
        <div className="panel-body">
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
            <span className={statusBadgeClass(cert.status)}>{cert.status}</span>
            <span className="badge badge-neutral">{cert.chain_status}</span>
            <span className="badge badge-neutral">{cert.managed_status}</span>
          </div>
          <div className="grid-2">
            <div className="detail-list">
              <p>
                <strong>Issuer:</strong> {cert.issuer_dn}
              </p>
              <p>
                <strong>Valid:</strong> {new Date(cert.not_before).toLocaleDateString()} –{" "}
                {new Date(cert.not_after).toLocaleDateString()}
              </p>
              <p>
                <strong>Days until expiry:</strong> {cert.days_until_expiry}
              </p>
              <p>
                <strong>SANs:</strong> {cert.subject_alt_names.join(", ") || "—"}
              </p>
              <p>
                <strong>Hostname matches SAN:</strong> {cert.hostname_matches_san ? "Yes" : "No"}
              </p>
            </div>
            <div>
              <EnrichmentForm cert={cert} />
            </div>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>PEM</h2>
        </div>
        <div className="panel-body">
          <pre className="code-block">{cert.pem}</pre>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Observations ({observations.length})</h2>
        </div>
        <div className="panel-body panel-body-flush data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Port</th>
                <th>Hostname</th>
                <th>SNI</th>
                <th>TLS</th>
                <th>Cipher</th>
                <th>Observed</th>
              </tr>
            </thead>
            <tbody>
              {observations.map((o) => (
                <tr key={o.id}>
                  <td>{o.ip}</td>
                  <td>{o.port}</td>
                  <td>{o.hostname || "—"}</td>
                  <td>{o.sni || "—"}</td>
                  <td>{o.tls_version || "—"}</td>
                  <td>{o.cipher_suite || "—"}</td>
                  <td>{new Date(o.observed_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
