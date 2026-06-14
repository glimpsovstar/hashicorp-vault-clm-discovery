"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/", label: "Certificate inventory", exact: true },
  { href: "/scans", label: "Scans" },
  { href: "/issuers", label: "Issuers" },
];

export default function SidebarNav() {
  const pathname = usePathname();

  function isActive(href: string, exact?: boolean) {
    if (exact) return pathname === href;
    return pathname === href || pathname.startsWith(`${href}/`);
  }

  return (
    <nav className="app-sidebar-nav" aria-label="CLM Discovery">
      <p className="app-sidebar-heading">CLM Discovery</p>
      <ul className="app-sidebar-list">
        {navItems.map((item) => (
          <li key={item.href}>
            <Link
              href={item.href}
              className={`app-sidebar-link${isActive(item.href, item.exact) ? " is-active" : ""}`}
              aria-current={isActive(item.href, item.exact) ? "page" : undefined}
            >
              {item.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
