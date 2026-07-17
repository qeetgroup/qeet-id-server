import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Field,
  FieldLabel,
  Input,
  SegmentedControl,
  SegmentedControlItem,
  Switch,
  Textarea,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, PlayIcon, PlusIcon, SlidersHorizontalIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { CodePreview } from "@/features/authorization/components/code-preview/code-preview";
import { ConditionTree } from "@/features/authorization/components/condition-builder/condition-tree";
import { DecisionExplain } from "@/features/authorization/components/explain/decision-explain";
import { MonacoPanel } from "@/features/authorization/components/shared/monaco-panel";
import type { ApiError } from "@/lib/api";
import {
  type AbacPolicy,
  type CondNode,
  type Effect,
  emptyGroup,
  fromConditionJson,
  toConditionJson,
  useAbacPolicies,
  useCreateAbacPolicy,
  useDeleteAbacPolicy,
  useUpdateAbacPolicy,
} from "@/lib/authz-abac";
import type { PolicyDoc } from "@/lib/authz-codegen";
import { type DecisionRecord, useAbacSimulate } from "@/lib/authz-simulate";
import { pushDecision } from "@/lib/authz-store";

export const Route = createFileRoute("/_app/authorization/abac")({
  component: AbacPage,
});

interface Draft {
  id?: string;
  name: string;
  description: string;
  effect: Effect;
  resourceType: string;
  action: string;
  priority: number;
  enabled: boolean;
  condition: CondNode;
}

function newDraft(): Draft {
  return {
    name: "",
    description: "",
    effect: "allow",
    resourceType: "",
    action: "",
    priority: 10,
    enabled: true,
    condition: emptyGroup("all"),
  };
}

function draftFromPolicy(p: AbacPolicy): Draft {
  return {
    id: p.id,
    name: p.name,
    description: p.description,
    effect: p.effect,
    resourceType: p.resource_type,
    action: p.action,
    priority: p.priority,
    enabled: p.enabled,
    condition: fromConditionJson(p.condition),
  };
}

function draftToDoc(d: Draft): PolicyDoc {
  return {
    name: d.name,
    description: d.description,
    effect: d.effect,
    resourceType: d.resourceType,
    action: d.action,
    requireRole: null,
    condition: d.condition,
    relation: null,
    priority: d.priority,
    enabled: d.enabled,
  };
}

function AbacPage() {
  const policiesQ = useAbacPolicies();
  const [draft, setDraft] = useState<Draft | null>(null);
  const policies = policiesQ.data?.items ?? [];
  const deleteM = useDeleteAbacPolicy();

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Author attribute-based policies with a no-code condition builder. Deny wins; policies are ordered by priority."
        actions={
          <Button size="sm" onClick={() => setDraft(newDraft())}>
            <PlusIcon /> New policy
          </Button>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle className="text-base">Policies</CardTitle>
            <CardDescription>
              {policies.length} attribute polic{policies.length === 1 ? "y" : "ies"}
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <DataState
              isLoading={policiesQ.isLoading}
              isError={policiesQ.isError}
              error={policiesQ.error}
              isEmpty={policies.length === 0}
              emptyIcon={SlidersHorizontalIcon}
              emptyTitle="No ABAC policies yet"
              emptyDescription="Create your first attribute-based policy."
              skeletonRows={4}
            >
              <ul className="divide-y">
                {policies.map((p) => (
                  <li key={p.id} className="flex items-start justify-between gap-2 p-3">
                    <button
                      type="button"
                      className="min-w-0 flex-1 text-left"
                      onClick={() => setDraft(draftFromPolicy(p))}
                    >
                      <div className="flex items-center gap-2">
                        <Badge variant={p.effect === "deny" ? "destructive" : "success"}>
                          {p.effect}
                        </Badge>
                        <span className="truncate text-sm font-medium">{p.name}</span>
                        {!p.enabled && <Badge variant="muted">disabled</Badge>}
                      </div>
                      <p className="truncate font-mono text-xs text-muted-foreground">
                        {p.resource_type}:{p.action} · priority {p.priority}
                      </p>
                    </button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Delete ${p.name}`}
                      disabled={deleteM.isPending}
                      onClick={() => deleteM.mutate(p.id)}
                    >
                      <Trash2Icon />
                    </Button>
                  </li>
                ))}
              </ul>
            </DataState>
          </CardContent>
        </Card>

        {draft ? (
          <PolicyEditor
            key={draft.id ?? "new"}
            draft={draft}
            onChange={setDraft}
            onClose={() => setDraft(null)}
          />
        ) : (
          <Card className="flex min-h-[400px] items-center justify-center">
            <CardContent className="text-center text-sm text-muted-foreground">
              Select a policy to edit, or create a new one.
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

function PolicyEditor({
  draft,
  onChange,
  onClose,
}: {
  draft: Draft;
  onChange: (d: Draft) => void;
  onClose: () => void;
}) {
  const createM = useCreateAbacPolicy();
  const updateM = useUpdateAbacPolicy(draft.id ?? "");
  const saving = createM.isPending || updateM.isPending;
  const error = (createM.error ?? updateM.error) as ApiError | null;

  function save() {
    const input = {
      name: draft.name,
      description: draft.description,
      effect: draft.effect,
      resource_type: draft.resourceType || "*",
      action: draft.action || "*",
      condition: toConditionJson(draft.condition),
      priority: draft.priority,
      enabled: draft.enabled,
    };
    if (draft.id) updateM.mutate(input, { onSuccess: onClose });
    else createM.mutate(input, { onSuccess: onClose });
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <Card>
        <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-base">{draft.id ? "Edit policy" : "New policy"}</CardTitle>
            <CardDescription>Define the effect, target and condition.</CardDescription>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={onClose}>
              Cancel
            </Button>
            <Button size="sm" onClick={save} disabled={saving || !draft.name.trim()}>
              {saving && <Loader2Icon className="animate-spin" />}
              {draft.id ? "Save changes" : "Create policy"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor="p-name">Name</FieldLabel>
              <Input
                id="p-name"
                value={draft.name}
                onChange={(e) => onChange({ ...draft, name: e.target.value })}
                placeholder="allow_eng_prod"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="p-effect">Effect</FieldLabel>
              <SegmentedControl
                value={draft.effect}
                onValueChange={(v) => onChange({ ...draft, effect: v as Effect })}
                aria-label="Effect"
              >
                <SegmentedControlItem value="allow">Allow</SegmentedControlItem>
                <SegmentedControlItem value="deny">Deny</SegmentedControlItem>
              </SegmentedControl>
            </Field>
            <Field>
              <FieldLabel htmlFor="p-resource">Resource type</FieldLabel>
              <Input
                id="p-resource"
                value={draft.resourceType}
                onChange={(e) => onChange({ ...draft, resourceType: e.target.value })}
                placeholder="* or document"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="p-action">Action</FieldLabel>
              <Input
                id="p-action"
                value={draft.action}
                onChange={(e) => onChange({ ...draft, action: e.target.value })}
                placeholder="* or read"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="p-priority">Priority</FieldLabel>
              <Input
                id="p-priority"
                type="number"
                value={draft.priority}
                onChange={(e) => onChange({ ...draft, priority: Number(e.target.value) || 0 })}
              />
            </Field>
            <Field className="justify-end">
              <div className="flex items-center gap-2 text-sm">
                <Switch
                  checked={draft.enabled}
                  onCheckedChange={(c) => onChange({ ...draft, enabled: c })}
                  aria-label="Enabled"
                />
                Enabled
              </div>
            </Field>
          </div>
          <Field>
            <FieldLabel htmlFor="p-desc">Description</FieldLabel>
            <Textarea
              id="p-desc"
              rows={2}
              value={draft.description}
              onChange={(e) => onChange({ ...draft, description: e.target.value })}
            />
          </Field>

          <div>
            <p className="mb-2 text-sm font-medium">Condition</p>
            <ConditionTree
              value={draft.condition}
              onChange={(condition) => onChange({ ...draft, condition })}
            />
          </div>
          {error && <p className="text-destructive text-sm">{error.message}</p>}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Preview</CardTitle>
            <CardDescription>Generated representations of this policy.</CardDescription>
          </CardHeader>
          <CardContent>
            <CodePreview doc={draftToDoc(draft)} height={320} />
          </CardContent>
        </Card>
        <TestPanel draft={draft} />
      </div>
    </div>
  );
}

function defaultEvalInput(draft: Draft): string {
  return JSON.stringify(
    {
      subject: { department: "Engineering", role: "member" },
      resource: {
        type: draft.resourceType || "document",
        id: "res-1",
        attrs: { environment: "production" },
      },
      action: draft.action || "read",
      context: { hour_of_day: 14, mfa: true, network: "corp" },
    },
    null,
    2,
  );
}

function TestPanel({ draft }: { draft: Draft }) {
  const [raw, setRaw] = useState(() => defaultEvalInput(draft));
  const [parseError, setParseError] = useState<string | null>(null);
  const [record, setRecord] = useState<DecisionRecord | null>(null);
  const simM = useAbacSimulate();

  function run() {
    let parsed: {
      subject?: Record<string, unknown>;
      resource?: { type: string; id: string; attrs?: Record<string, unknown> };
      action?: string;
      context?: Record<string, unknown>;
    };
    try {
      parsed = JSON.parse(raw);
    } catch {
      setParseError("Invalid JSON");
      return;
    }
    setParseError(null);
    simM.mutate(
      {
        subject: parsed.subject ?? {},
        resource: parsed.resource ?? { type: draft.resourceType || "*", id: "res-1" },
        action: parsed.action ?? (draft.action || "*"),
        context: parsed.context ?? {},
      },
      {
        onSuccess: (rec) => {
          setRecord(rec);
          pushDecision(rec);
        },
      },
    );
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
        <div>
          <CardTitle className="text-base">Test against the live engine</CardTitle>
          <CardDescription>
            Runs POST /abac/evaluate?explain=true across all enabled policies.
          </CardDescription>
        </div>
        <Button size="sm" variant="outline" onClick={run} disabled={simM.isPending}>
          {simM.isPending ? <Loader2Icon className="animate-spin" /> : <PlayIcon />}
          Test
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <MonacoPanel
          value={raw}
          language="json"
          readOnly={false}
          onChange={setRaw}
          height={200}
          ariaLabel="Evaluation input"
        />
        {parseError && <p className="text-destructive text-sm">{parseError}</p>}
        {record && (
          <div className="rounded-md border p-3">
            <DecisionExplain record={record} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
