import "./SeverityBadge.css";

const COLORS = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
} as const;

export default function SeverityBadge({ severity }: { severity: keyof typeof COLORS }) {
  return <span className={`severity-badge ${COLORS[severity]}`}>{severity.toUpperCase()}</span>;
}
