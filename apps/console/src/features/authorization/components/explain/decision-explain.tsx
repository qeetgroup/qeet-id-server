import {
  Badge,
  JSONTree,
  Timeline,
  TimelineContent,
  TimelineIndicator,
  TimelineItem,
  TimelineTitle,
} from "@qeetrix/ui";
import { ArrowRightIcon, ClockIcon, GaugeIcon } from "lucide-react";

import type { DecisionRecord, RbacExplainPath, RebacPathStep } from "@/lib/authz-simulate";
import { DecisionBadge, ENGINE_DESCRIPTIONS, ENGINE_LABELS } from "../shared/decision-badge";

/**
 * The full "DevTools for authorization" view of one decision: outcome, engine,
 * latency, and the engine-specific grant-path / trace, plus the raw request.
 */
export function DecisionExplain({ record }: { record: DecisionRecord }) {
  return (
    <div className="flex flex-col gap-5">
      <header className="flex flex-wrap items-center gap-3">
        <DecisionBadge allowed={record.allowed} />
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="font-mono text-[10px] uppercase">
            {ENGINE_LABELS[record.engine]}
          </Badge>
          <span className="text-xs text-muted-foreground">
            {ENGINE_DESCRIPTIONS[record.engine]}
          </span>
        </div>
        <span className="ml-auto flex items-center gap-1 text-xs text-muted-foreground">
          <GaugeIcon className="size-3.5" aria-hidden />
          {record.durationMs} ms
        </span>
        <span className="flex items-center gap-1 text-xs text-muted-foreground">
          <ClockIcon className="size-3.5" aria-hidden />
          {new Date(record.at).toLocaleTimeString()}
        </span>
      </header>

      {record.reason && (
        <p className="rounded-md border bg-muted/30 px-3 py-2 text-sm text-muted-foreground">
          {record.reason}
        </p>
      )}

      {record.engine === "rbac" && record.rbac && <RbacExplainView paths={record.rbac.paths} />}
      {record.engine === "abac" && record.abac && (
        <AbacTraceView
          trace={record.abac.trace ?? []}
          matched={record.abac.matched_policy_id}
          effect={record.abac.effect}
        />
      )}
      {record.engine === "rebac" && record.rebac && (
        <RebacPathView path={record.rebac.path ?? []} />
      )}
      {record.engine === "authzen" && record.authzen && (
        <section className="space-y-2">
          <h3 className="text-sm font-medium">Decision context</h3>
          <div className="rounded-md border bg-muted/20 p-3">
            <JSONTree
              value={record.authzen.context ?? { decision: record.authzen.decision }}
              initialOpenDepth={2}
            />
          </div>
        </section>
      )}

      <section className="space-y-2">
        <h3 className="text-sm font-medium">Request</h3>
        <div className="rounded-md border bg-muted/20 p-3">
          <JSONTree value={record.input} initialOpenDepth={2} rootLabel="input" />
        </div>
      </section>
    </div>
  );
}

function RbacExplainView({ paths }: { paths: RbacExplainPath[] }) {
  if (paths.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No grant path — access is not granted by any role.
      </p>
    );
  }
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-medium">Grant paths</h3>
      <ul className="flex flex-col gap-2">
        {paths.map((p, i) => {
          const isGroup = p.via.startsWith("group:");
          return (
            <li
              key={`${p.role_id}-${p.via}-${i}`}
              className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/20 p-3"
            >
              <Badge variant="default" className="font-mono">
                {p.permission}
              </Badge>
              <span className="text-xs text-muted-foreground">granted by</span>
              <Badge variant="secondary">{p.granted_by}</Badge>
              <Badge variant={isGroup ? "outline" : "muted"}>
                {isGroup ? `via ${p.via}` : "direct assignment"}
              </Badge>
              <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                role {p.role_id.slice(0, 8)}
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function AbacTraceView({
  trace,
  matched,
  effect,
}: {
  trace: string[];
  matched?: string | null;
  effect: string;
}) {
  return (
    <section className="space-y-2">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-medium">Evaluation trace</h3>
        {effect && <Badge variant={effect === "deny" ? "destructive" : "success"}>{effect}</Badge>}
        {matched && (
          <span className="font-mono text-[10px] text-muted-foreground">
            matched policy {matched.slice(0, 8)}
          </span>
        )}
      </div>
      {trace.length === 0 ? (
        <p className="text-sm text-muted-foreground">No policy matched — default deny.</p>
      ) : (
        <Timeline>
          {trace.map((step, i) => (
            <TimelineItem key={i}>
              <TimelineIndicator>
                <span className="flex size-5 items-center justify-center rounded-full border bg-background text-[10px] font-medium">
                  {i + 1}
                </span>
              </TimelineIndicator>
              <TimelineContent>
                <TimelineTitle className="font-mono text-xs">{step}</TimelineTitle>
              </TimelineContent>
            </TimelineItem>
          ))}
        </Timeline>
      )}
    </section>
  );
}

function RebacPathView({ path }: { path: RebacPathStep[] }) {
  if (path.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No relationship path resolves this check.</p>
    );
  }
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-medium">Relationship path</h3>
      <ol className="flex flex-col gap-1">
        {path.map((step, i) => (
          <li key={i} className="flex items-center gap-2 font-mono text-xs">
            <Badge variant="muted" className="text-[10px]">
              hop {step.depth}
            </Badge>
            <span>{step.object}</span>
            <span className="text-muted-foreground">#{step.relation}</span>
            <ArrowRightIcon className="size-3 text-muted-foreground" aria-hidden />
            <span>{step.subject}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
