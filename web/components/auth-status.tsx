"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

type Me = { authenticated: boolean; role?: string };

export default function AuthStatus() {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/me", { cache: "no-store" })
      .then((r) => r.json())
      .then((body: Me) => {
        if (!cancelled) setMe(body);
      })
      .catch(() => {
        if (!cancelled) setMe({ authenticated: false });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    setMe({ authenticated: false });
    router.push("/login");
    router.refresh();
  }

  if (!me) {
    return <span className="app-header-link muted">…</span>;
  }
  if (!me.authenticated) {
    return (
      <Link href="/login" className="app-header-link">
        Sign in
      </Link>
    );
  }
  return (
    <button type="button" className="app-header-link" onClick={logout} style={{ background: "none", border: 0, cursor: "pointer" }}>
      Sign out ({me.role || "operator"})
    </button>
  );
}
