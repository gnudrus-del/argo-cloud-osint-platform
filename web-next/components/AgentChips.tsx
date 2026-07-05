const LABELS: Record<string, string> = {
  planner: "Pianificatore",
  web: "Copertura web",
  opsec: "OPSEC",
  geo: "Geolocalizzazione",
  socmint: "SOCMINT",
  media: "Media & metadati",
  crypto: "Wallet crypto",
  phone: "Telefono",
  humint: "HUMINT",
  external: "Tool esterni",
  reverse_account: "Reverse account",
  darkweb: "Deep / dark web",
  red_team: "Red team",
};
const GATED = new Set(["darkweb", "red_team"]);

export default function AgentChips({ agents }: { agents: string[] }) {
  if (!agents?.length) return <span className="muted">-</span>;
  return (
    <div>
      {agents.map((a) => (
        <span key={a} className={`chip${GATED.has(a) ? " gated" : ""}`} title={GATED.has(a) ? "Richiede autorizzazione" : "Sempre attivo"}>
          {GATED.has(a) ? "🔒 " : ""}
          {LABELS[a] || a}
        </span>
      ))}
    </div>
  );
}
