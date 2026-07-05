"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  { href: "/", label: "Dashboard" },
  { href: "/cases", label: "Casi" },
  { href: "/search", label: "Ricerca" },
];

export default function Sidebar() {
  const path = usePathname();
  return (
    <aside
      style={{
        borderRight: "1px solid var(--line)",
        padding: "28px 18px",
        background: "linear-gradient(180deg, var(--panel), transparent)",
      }}
    >
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontFamily: "var(--font-display)", fontSize: 26, fontWeight: 700, color: "var(--accent)" }}>
          ARGO
        </div>
        <div style={{ fontSize: 11, letterSpacing: 2, color: "var(--muted)" }}>OSINT · PRO</div>
      </div>
      <nav style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {NAV.map((item) => {
          const active = path === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              style={{
                padding: "9px 12px",
                borderRadius: 10,
                color: active ? "var(--accent-strong)" : "var(--muted-strong)",
                background: active ? "rgba(245,183,64,0.12)" : "transparent",
                fontWeight: active ? 600 : 400,
              }}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>
      <p style={{ marginTop: 32, fontSize: 11, color: "var(--muted)" }}>
        Privacy-by-design · GDPR · court-ready
      </p>
    </aside>
  );
}
