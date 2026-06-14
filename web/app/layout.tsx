import "./globals.css";
import Link from "next/link";
import type { ReactNode } from "react";

export const metadata = {
  title: "Vault CLM Discovery",
  description: "Certificate lifecycle discovery for HashiCorp Vault environments",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="container">
          <header>
            <h1 style={{ marginTop: 0 }}>Vault CLM Discovery</h1>
            <p className="muted">Network TLS certificate inventory for HashiCorp Vault CLM</p>
            <nav>
              <Link href="/">Inventory</Link>
              <Link href="/scans">Scans</Link>
              <Link href="/issuers">Issuers</Link>
            </nav>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}
