import Link from "next/link";
import PageHeader from "@/components/page-header";
import ReportDownloadMenu from "@/components/report-download-menu";
import CatalogImportButton from "@/components/catalog-import-button";
import ImportCAButton from "@/components/import-ca-button";
import {
  fetchReport,
  getScan,
  listScanCertificates,
  listIssuers,
  severityBadgeClass,
  statusBadgeClass,
} from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function ScanReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = await getScan(id);

  const backToScan = <Link href={`/scans/${id}`}>← Back to scan</Link>;

  if (scan.status !== "completed") {
    return (
      <>
        <PageHeader
          title="Environment report"
          subtitle="Scans"
          breadcrumbs={backToScan}
        />
        <section className="panel">
          <div className="panel-body">
            <p className="muted">
              Complete the scan to view its environment report.
            </p>
          </div>
        </section>
      </>
    );
  }

  const [report, certsResp, issuersResp] = await Promise.all([
    fetchReport(id),
    listScanCertificates(id),
    listIssuers(),
  ]);
  const certs = certsResp.items ?? [];
  const issuers = issuersResp.items ?? [];

  // Shadow certs = on the wire but not matched to Vault PKI. Already-tracked
  // (`imported`) certs stay in the list so tracking one doesn't make it vanish;
  // CatalogImportButton renders a disabled "Tracked in CLM" for those.
  const shadowCerts = certs.filter((c) => c.managed_status !== "managed_in_vault");

  // CA-import candidates: issuers observed in THIS scan (matched by DN) that are
  // CA certs. ImportCAButton itself renders "In Vault" when already imported.
  const scanIssuerDNs = new Set(certs.map((c) => c.issuer_dn));
  const scanIssuers = issuers.filter(
    (i) => i.is_ca && scanIssuerDNs.has(i.issuer_dn)
  );

  const bs = report.blind_spot;
  const generated = new Date(report.generated_at).toLocaleString();

  return (
    <>
      <PageHeader
        title="Environment report"
        subtitle="Scans"
        description={`Scan ${scan.id.slice(0, 8)}… · generated ${generated} · report v${report.report_version}`}
        breadcrumbs={backToScan}
        actions={<ReportDownloadMenu scanId={scan.id} />}
      />

      <section className="panel">
        <div className="panel-header">
          <h2>Summary</h2>
        </div>
        <div className="panel-body">
          <div className="stat-grid">
            <StatTile label="Vault managed" value={bs.vault_managed} />
            <StatTile label="On wire" value={bs.discovered} />
            <StatTile label="Shadow certs" value={bs.shadow} />
            <StatTile label="SC-081 violations" value={bs.sc081_violations} />
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Insights ({report.insights.length})</h2>
        </div>
        <div className="panel-body panel-body-flush data-table-wrap">
          {report.insights.length === 0 ? (
            <p className="muted" style={{ padding: "16px 20px" }}>
              No findings — every discovered certificate is healthy and accounted
              for.
            </p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Subject</th>
                  <th>Finding</th>
                </tr>
              </thead>
              <tbody>
                {report.insights.map((insight, i) => (
                  <tr key={`${insight.type}-${insight.fingerprint_sha256 ?? i}`}>
                    <td>
                      <span className={severityBadgeClass(insight.severity)}>
                        {insight.severity}
                      </span>
                    </td>
                    <td>{insight.subject_cn || insight.issuer_dn || "—"}</td>
                    <td>{insight.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {report.recommendations.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <h2>Recommended actions</h2>
          </div>
          <div className="panel-body">
            <ul className="detail-list">
              {report.recommendations.map((rec) => (
                <li key={rec.code}>
                  <strong>{rec.phase}:</strong> {rec.title} ({rec.count})
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}

      <section className="panel">
        <div className="panel-header">
          <h2>Take action — shadow certificates ({shadowCerts.length})</h2>
        </div>
        <div className="panel-body panel-body-flush data-table-wrap">
          {shadowCerts.length === 0 ? (
            <p className="muted" style={{ padding: "16px 20px" }}>
              No shadow certificates — everything on the wire is managed in Vault.
            </p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Certificate</th>
                  <th>Status</th>
                  <th>Expires (days)</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {shadowCerts.map((cert) => (
                  <tr key={cert.id}>
                    <td>
                      <Link href={`/certificates/${cert.id}`}>
                        {cert.subject_cn || cert.serial_number}
                      </Link>
                    </td>
                    <td>
                      <span className={statusBadgeClass(cert.status)}>
                        {cert.status}
                      </span>
                    </td>
                    <td>{cert.days_until_expiry}</td>
                    <td>
                      <CatalogImportButton cert={cert} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Take action — issuers / CAs ({scanIssuers.length})</h2>
        </div>
        <div className="panel-body panel-body-flush data-table-wrap">
          {scanIssuers.length === 0 ? (
            <p className="muted" style={{ padding: "16px 20px" }}>
              No CA issuers observed in this scan to import into Vault.
            </p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Issuer</th>
                  <th>Expires (days)</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {scanIssuers.map((issuer) => (
                  <tr key={issuer.id}>
                    <td>{issuer.subject_cn || issuer.issuer_dn}</td>
                    <td>{issuer.days_until_expiry}</td>
                    <td>
                      <ImportCAButton issuer={issuer} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </>
  );
}

function StatTile({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="stat-tile">
      <div className="stat-tile-label">{label}</div>
      <div className="stat-tile-value">{value}</div>
    </div>
  );
}
