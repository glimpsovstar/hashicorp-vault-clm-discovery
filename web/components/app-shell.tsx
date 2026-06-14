import Link from "next/link";
import type { ReactNode } from "react";
import SidebarNav from "./sidebar-nav";
import VaultLogo from "./vault-logo";

export default function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="app-frame">
      <header className="app-header">
        <div className="app-header-start">
          <Link href="/" className="app-header-brand" aria-label="Vault CLM Discovery home">
            <VaultLogo size={24} />
            <span className="app-header-brand-text">
              <span className="app-header-product">CLM Discovery</span>
            </span>
          </Link>
        </div>
        <div className="app-header-end">
          <a
            className="app-header-link"
            href="https://developer.hashicorp.com/vault/docs"
            target="_blank"
            rel="noreferrer"
          >
            Documentation
          </a>
        </div>
      </header>

      <aside className="app-sidebar">
        <SidebarNav />
      </aside>

      <main id="app-main-content" className="app-main">
        {children}
      </main>
    </div>
  );
}
