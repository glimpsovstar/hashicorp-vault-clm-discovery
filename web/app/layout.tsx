import "./globals.css";
import type { ReactNode } from "react";
import AppShell from "@/components/app-shell";

export const metadata = {
  title: "Vault CLM Discovery",
  description: "Certificate lifecycle discovery for HashiCorp Vault environments",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
