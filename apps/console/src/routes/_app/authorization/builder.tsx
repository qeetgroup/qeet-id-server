import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldLabel,
  Input,
  SegmentedControl,
  SegmentedControlItem,
  Switch,
  toast,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CopyIcon, DownloadIcon, Loader2Icon, SaveIcon, Trash2Icon } from "lucide-react";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/page-header";
import {
  type BlockKind,
  PolicyCanvas,
} from "@/features/authorization/components/canvas/policy-canvas";
import { CodePreview } from "@/features/authorization/components/code-preview/code-preview";
import { ConditionTree } from "@/features/authorization/components/condition-builder/condition-tree";
import { ComingSoon } from "@/features/authorization/components/shared/coming-soon";
import type { ApiError } from "@/lib/api";
import { type Effect, emptyGroup, useCreateAbacPolicy } from "@/lib/authz-abac";
import {
  emptyPolicyDoc,
  isReducibleToAbac,
  type PolicyDoc,
  toAbacInput,
  toJson,
} from "@/lib/authz-codegen";
import { setBuilderDoc, useBuilderDoc } from "@/lib/authz-store";
import { downloadBlob } from "@/lib/export";

export const Route = createFileRoute("/_app/authorization/builder")({
  component: BuilderPage,
});

function BuilderPage() {
  const handoff = useBuilderDoc();
  const [doc, setDoc] = useState<PolicyDoc>(() => handoff ?? emptyPolicyDoc());
  const [selected, setSelected] = useState<BlockKind | null>("decision");

  // Consume a template hand-off from the store exactly once, on mount.
  // biome-ignore lint/correctness/useExhaustiveDependencies: intentional run-once mount effect
  useEffect(() => {
    if (handoff) {
      setDoc(handoff);
      setBuilderDoc(null);
    }
  }, []);

  const createM = useCreateAbacPolicy();
  const reducible = isReducibleToAbac(doc);

  function toggleBlock(kind: Exclude<BlockKind, "decision">) {
    setDoc((d) => {
      if (kind === "rbac") return { ...d, requireRole: d.requireRole == null ? "" : null };
      if (kind === "rebac")
        return { ...d, relation: d.relation == null ? { object: "", relation: "" } : null };
      return { ...d, condition: d.condition == null ? emptyGroup("all") : null };
    });
  }

  function saveAsAbac() {
    createM.mutate(toAbacInput(doc), {
      onSuccess: () => toast.success("Saved as ABAC policy"),
    });
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Compose RBAC, ABAC and ReBAC blocks into one policy. Wire blocks into the decision and preview the generated policy live."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                navigator.clipboard?.writeText(toJson(doc));
                toast.success("Copied JSON");
              }}
            >
              <CopyIcon /> Copy JSON
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                downloadBlob(toJson(doc), "application/json", `${doc.name || "policy"}.json`)
              }
            >
              <DownloadIcon /> Export
            </Button>
            <Button
              size="sm"
              onClick={saveAsAbac}
              disabled={!reducible || createM.isPending || !doc.name.trim()}
            >
              {createM.isPending ? <Loader2Icon className="animate-spin" /> : <SaveIcon />}
              Save as ABAC
            </Button>
          </>
        }
      />

      {createM.error && (
        <p className="text-destructive text-sm">{(createM.error as ApiError).message}</p>
      )}

      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle className="text-base">Blueprint</CardTitle>
            <CardDescription>
              Add blocks and click a node to edit it in the inspector.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <PolicyCanvas
              doc={doc}
              selected={selected}
              onSelect={setSelected}
              onToggleBlock={toggleBlock}
              height={480}
            />
          </CardContent>
        </Card>

        <Card className="min-w-0">
          <CardHeader>
            <CardTitle className="text-base">Inspector</CardTitle>
            <CardDescription>
              {selected
                ? `Editing the ${selected.toUpperCase()} block`
                : "Select a node on the canvas"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Inspector selected={selected} doc={doc} onChange={setDoc} />
          </CardContent>
        </Card>
      </div>

      {!reducible && (
        <ComingSoon
          title="Composite policies aren't persistable yet"
          description="This policy combines RBAC/ReBAC with ABAC, which has no single backend object. You can export it or simulate it now; remove the RBAC/ReBAC blocks to save it as a real ABAC policy."
          note="POST /abac/policies accepts ABAC-only policies"
        />
      )}

      <Card>
        <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-base">Generated policy</CardTitle>
            <CardDescription>JSON · YAML · DSL · evaluation tree</CardDescription>
          </div>
          <Badge variant={reducible ? "success" : "warning"}>
            {reducible ? "ABAC-persistable" : "composite (preview only)"}
          </Badge>
        </CardHeader>
        <CardContent>
          <CodePreview doc={doc} height={360} />
        </CardContent>
      </Card>
    </div>
  );
}

function Inspector({
  selected,
  doc,
  onChange,
}: {
  selected: BlockKind | null;
  doc: PolicyDoc;
  onChange: (d: PolicyDoc) => void;
}) {
  if (selected === "decision" || selected === null) {
    return (
      <div className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="b-name">Name</FieldLabel>
          <Input
            id="b-name"
            value={doc.name}
            onChange={(e) => onChange({ ...doc, name: e.target.value })}
            placeholder="policy_name"
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="b-effect">Effect</FieldLabel>
          <SegmentedControl
            value={doc.effect}
            onValueChange={(v) => onChange({ ...doc, effect: v as Effect })}
            aria-label="Effect"
          >
            <SegmentedControlItem value="allow">Allow</SegmentedControlItem>
            <SegmentedControlItem value="deny">Deny</SegmentedControlItem>
          </SegmentedControl>
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field>
            <FieldLabel htmlFor="b-resource">Resource type</FieldLabel>
            <Input
              id="b-resource"
              value={doc.resourceType}
              onChange={(e) => onChange({ ...doc, resourceType: e.target.value })}
              placeholder="*"
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="b-action">Action</FieldLabel>
            <Input
              id="b-action"
              value={doc.action}
              onChange={(e) => onChange({ ...doc, action: e.target.value })}
              placeholder="*"
            />
          </Field>
        </div>
        <div className="grid grid-cols-2 items-end gap-3">
          <Field>
            <FieldLabel htmlFor="b-priority">Priority</FieldLabel>
            <Input
              id="b-priority"
              type="number"
              value={doc.priority}
              onChange={(e) => onChange({ ...doc, priority: Number(e.target.value) || 0 })}
            />
          </Field>
          <div className="flex items-center gap-2 pb-2 text-sm">
            <Switch
              checked={doc.enabled}
              onCheckedChange={(c) => onChange({ ...doc, enabled: c })}
              aria-label="Enabled"
            />
            Enabled
          </div>
        </div>
      </div>
    );
  }

  if (selected === "rbac") {
    return (
      <div className="flex flex-col gap-3">
        <Field>
          <FieldLabel htmlFor="b-role">Required role</FieldLabel>
          <Input
            id="b-role"
            value={doc.requireRole ?? ""}
            onChange={(e) => onChange({ ...doc, requireRole: e.target.value })}
            placeholder="admin"
          />
        </Field>
        <Button variant="outline" size="sm" onClick={() => onChange({ ...doc, requireRole: null })}>
          <Trash2Icon /> Remove block
        </Button>
      </div>
    );
  }

  if (selected === "rebac") {
    return (
      <div className="flex flex-col gap-3">
        <Field>
          <FieldLabel htmlFor="b-object">Object</FieldLabel>
          <Input
            id="b-object"
            value={doc.relation?.object ?? ""}
            onChange={(e) =>
              onChange({
                ...doc,
                relation: { object: e.target.value, relation: doc.relation?.relation ?? "" },
              })
            }
            placeholder="document:readme"
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="b-relation">Relation</FieldLabel>
          <Input
            id="b-relation"
            value={doc.relation?.relation ?? ""}
            onChange={(e) =>
              onChange({
                ...doc,
                relation: { object: doc.relation?.object ?? "", relation: e.target.value },
              })
            }
            placeholder="owner"
          />
        </Field>
        <Button variant="outline" size="sm" onClick={() => onChange({ ...doc, relation: null })}>
          <Trash2Icon /> Remove block
        </Button>
      </div>
    );
  }

  // abac
  return (
    <div className="flex flex-col gap-3">
      {doc.condition ? (
        <ConditionTree
          value={doc.condition}
          onChange={(condition) => onChange({ ...doc, condition })}
        />
      ) : (
        <p className="text-sm text-muted-foreground">No condition block.</p>
      )}
      {doc.condition && (
        <Button variant="outline" size="sm" onClick={() => onChange({ ...doc, condition: null })}>
          <Trash2Icon /> Remove block
        </Button>
      )}
    </div>
  );
}
