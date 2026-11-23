import type { AuditEvent } from "../api/types";
import { time, short } from "../lib/format";
import { Hash, Pill, outcomeTone, severityTone } from "./ui";

export function EventTable({
  events,
  compact,
  onSelect,
  selected,
  chain,
}: {
  events: AuditEvent[];
  compact?: boolean;
  onSelect?: (e: AuditEvent) => void;
  selected?: number | null;
  /** Show prev_hash → hash swatches so continuity between adjacent rows is visible. */
  chain?: boolean;
}) {
  return (
    <div className="table-wrap">
      <table className={`table${onSelect ? " clickable" : ""}`}>
        <thead>
          <tr>
            <th className="num">Seq</th>
            <th>Time</th>
            <th>Event</th>
            <th>Outcome</th>
            {!compact && <th>Severity</th>}
            <th>Reason</th>
            <th>Actor</th>
            {!compact && <th>Resource</th>}
            {chain && <th>Chain link</th>}
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr
              key={e.seq}
              className={selected === e.seq ? "sel" : undefined}
              onClick={onSelect ? () => onSelect(e) : undefined}
              tabIndex={onSelect ? 0 : undefined}
              onKeyDown={onSelect ? (k) => (k.key === "Enter" || k.key === " ") && onSelect(e) : undefined}
            >
              <td className="num mono">{e.seq}</td>
              <td className="nowrap">{time(e.ts)}</td>
              <td>
                <code className="evt">{e.event_type}</code>
                {e.action && <div className="muted tiny">{e.action}</div>}
              </td>
              <td>
                <Pill tone={outcomeTone(e.outcome)}>{e.outcome}</Pill>
              </td>
              {!compact && (
                <td>
                  <Pill tone={severityTone(e.severity)}>{e.severity}</Pill>
                </td>
              )}
              <td className="nowrap">{e.reason ? <code>{e.reason}</code> : <span className="muted">–</span>}</td>
              <td className="mono small" title={e.actor ?? undefined}>
                {e.actor ? short(e.actor, 12) : <span className="muted">system</span>}
                {e.actor_role && <span className="muted"> {e.actor_role}</span>}
              </td>
              {!compact && (
                <td className="mono small" title={e.resource_id ?? undefined}>
                  {e.resource_type ? `${e.resource_type} ` : ""}
                  {e.resource_id ? short(e.resource_id, 8) : <span className="muted">–</span>}
                </td>
              )}
              {chain && (
                <td className="nowrap">
                  <span className="chainlink">
                    <Hash value={e.prev_hash} n={6} swatch copy={false} />
                    <span className="muted" aria-label="links to">
                      ⟶
                    </span>
                    <Hash value={e.hash} n={6} swatch copy={false} />
                  </span>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
