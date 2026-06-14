import Link from "next/link";
import { getCertificate, statusColor } from "@/lib/api";
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
    <section>
      <p><Link href="/">← Back to inventory</Link></p>

      <div className="card">
        <h2>{cert.subject_cn || "Certificate"}</h2>
        <p className="muted">Fingerprint: {cert.fingerprint_sha256}</p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          <span className="badge" style={{ background: statusColor(cert.status) }}>{cert.status}</span>
          <span className="badge" style={{ background: "#475569" }}>{cert.chain_status}</span>
          <span className="badge" style={{ background: "#475569" }}>{cert.managed_status}</span>
        </div>
        <div className="grid-2">
          <div>
            <p><strong>Issuer:</strong> {cert.issuer_dn}</p>
            <p><strong>Valid:</strong> {new Date(cert.not_before).toLocaleDateString()} – {new Date(cert.not_after).toLocaleDateString()}</p>
            <p><strong>Days until expiry:</strong> {cert.days_until_expiry}</p>
            <p><strong>SANs:</strong> {cert.subject_alt_names.join(", ") || "—"}</p>
            <p><strong>Hostname matches SAN:</strong> {cert.hostname_matches_san ? "Yes" : "No"}</p>
          </div>
          <div>
            <EnrichmentForm cert={cert} />
          </div>
        </div>
      </div>

      <div className="card">
        <h3>PEM</h3>
        <pre>{cert.pem}</pre>
        <p><a href={`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080"}/api/v1/certificates/${cert.id}/pem`}>Download PEM</a></p>
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <h3 style={{ padding: "16px 16px 0" }}>Observations ({observations.length})</h3>
        <table>
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
  );
}
