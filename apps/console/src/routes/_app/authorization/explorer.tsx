import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
} from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { SearchCodeIcon, Trash2Icon } from "lucide-react";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { DecisionExplain } from "@/features/authorization/components/explain/decision-explain";
import {
  DecisionBadge,
  ENGINE_LABELS,
} from "@/features/authorization/components/shared/decision-badge";
import { clearHistory, useDecisionHistory } from "@/lib/authz-store";

export const Route = createFileRoute("/_app/authorization/explorer")({
  component: ExplorerPage,
});

function ExplorerPage() {
  const history = useDecisionHistory();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Default-select the newest decision as it arrives.
  useEffect(() => {
    if (history.length && !history.some((r) => r.id === selectedId)) {
      setSelectedId(history[0].id);
    }
  }, [history, selectedId]);

  const selected = history.find((r) => r.id === selectedId) ?? null;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Inspect authorization decisions like a network waterfall: the outcome, the engine, latency and the full grant-path or trace."
        actions={
          history.length > 0 && (
            <Button variant="outline" size="sm" onClick={() => clearHistory()}>
              <Trash2Icon /> Clear history
            </Button>
          )
        }
      />

      {history.length === 0 ? (
        <Card>
          <CardContent className="py-6">
            <EmptyState
              icon={SearchCodeIcon}
              title="No decisions captured yet"
              description="Run a check from the Simulator, the ReBAC page, or an ABAC policy test — every decision lands here for inspection."
              action={
                <Button render={<Link to="/authorization/simulator" />} size="sm">
                  Open Simulator
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
          <Card className="min-w-0">
            <CardHeader>
              <CardTitle className="text-base">Recent decisions</CardTitle>
              <CardDescription>{history.length} captured (latest first)</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <ul className="divide-y">
                {history.map((r) => (
                  <li key={r.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(r.id)}
                      className={`flex w-full items-center gap-2 p-3 text-left hover:bg-muted/40 ${r.id === selectedId ? "bg-muted/60" : ""}`}
                    >
                      <DecisionBadge allowed={r.allowed} />
                      <span className="min-w-0 flex-1">
                        <span className="block text-xs font-medium">{ENGINE_LABELS[r.engine]}</span>
                        <span className="block truncate text-[11px] text-muted-foreground">
                          {new Date(r.at).toLocaleTimeString()} · {r.durationMs} ms
                        </span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <Card className="min-w-0">
            <CardHeader>
              <CardTitle className="text-base">Decision detail</CardTitle>
              <CardDescription>Full evaluation breakdown</CardDescription>
            </CardHeader>
            <CardContent>{selected && <DecisionExplain record={selected} />}</CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
