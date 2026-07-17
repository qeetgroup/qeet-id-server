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
  Meter,
  SegmentedControl,
  SegmentedControlItem,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { FlaskConicalIcon, Loader2Icon, PlayIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { DecisionExplain } from "@/features/authorization/components/explain/decision-explain";
import {
  DecisionBadge,
  ENGINE_DESCRIPTIONS,
} from "@/features/authorization/components/shared/decision-badge";
import { MonacoPanel } from "@/features/authorization/components/shared/monaco-panel";
import {
  BATCH_CAP,
  type DecisionRecord,
  type Engine,
  useAbacSimulate,
  useAuthzenEvaluate,
  useBatchSimulate,
  useRbacSimulate,
  useRebacSimulate,
} from "@/lib/authz-simulate";
import { pushDecision } from "@/lib/authz-store";

export const Route = createFileRoute("/_app/authorization/simulator")({
  component: SimulatorPage,
});

function SimulatorPage() {
  const [engine, setEngine] = useState<Engine>("authzen");
  const [record, setRecord] = useState<DecisionRecord | null>(null);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Ask a what-if question of any engine and see the exact allow/deny decision with a full explanation." />

      <SegmentedControl
        value={engine}
        onValueChange={(v) => setEngine(v as Engine)}
        aria-label="Engine"
      >
        <SegmentedControlItem value="authzen">Unified (AuthZEN)</SegmentedControlItem>
        <SegmentedControlItem value="abac">ABAC</SegmentedControlItem>
        <SegmentedControlItem value="rbac">RBAC</SegmentedControlItem>
        <SegmentedControlItem value="rebac">ReBAC</SegmentedControlItem>
      </SegmentedControl>
      <p className="-mt-1 text-xs text-muted-foreground">{ENGINE_DESCRIPTIONS[engine]}</p>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Request</CardTitle>
            <CardDescription>Fill in the subject, resource and action to evaluate.</CardDescription>
          </CardHeader>
          <CardContent>
            {engine === "authzen" && <AuthzenForm onResult={setRecord} />}
            {engine === "abac" && <AbacForm onResult={setRecord} />}
            {engine === "rbac" && <RbacForm onResult={setRecord} />}
            {engine === "rebac" && <RebacForm onResult={setRecord} />}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Decision</CardTitle>
            <CardDescription>The outcome and its explanation.</CardDescription>
          </CardHeader>
          <CardContent aria-live="polite">
            {record ? (
              <DecisionExplain record={record} />
            ) : (
              <div className="flex flex-col items-center gap-2 py-12 text-center">
                <FlaskConicalIcon className="size-8 text-muted-foreground" aria-hidden />
                <p className="text-sm text-muted-foreground">
                  Run a simulation to see the decision.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {engine === "authzen" && <BatchCard />}
    </div>
  );
}

function record(onResult: (r: DecisionRecord) => void) {
  return (r: DecisionRecord) => {
    onResult(r);
    pushDecision(r);
  };
}

function AuthzenForm({ onResult }: { onResult: (r: DecisionRecord) => void }) {
  const m = useAuthzenEvaluate();
  const [subjectType, setSubjectType] = useState("user");
  const [subjectId, setSubjectId] = useState("");
  const [resourceType, setResourceType] = useState("document");
  const [resourceId, setResourceId] = useState("");
  const [action, setAction] = useState("read");
  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        m.mutate(
          {
            subject: { type: subjectType.trim(), id: subjectId.trim() },
            resource: { type: resourceType.trim(), id: resourceId.trim() },
            action: action.trim(),
          },
          { onSuccess: record(onResult) },
        );
      }}
    >
      <div className="grid grid-cols-2 gap-3">
        <Field>
          <FieldLabel htmlFor="s-type">Subject type</FieldLabel>
          <Input id="s-type" value={subjectType} onChange={(e) => setSubjectType(e.target.value)} />
        </Field>
        <Field>
          <FieldLabel htmlFor="s-id">Subject ID</FieldLabel>
          <Input
            id="s-id"
            className="font-mono text-xs"
            value={subjectId}
            onChange={(e) => setSubjectId(e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="r-type">Resource type</FieldLabel>
          <Input
            id="r-type"
            value={resourceType}
            onChange={(e) => setResourceType(e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="r-id">Resource ID</FieldLabel>
          <Input
            id="r-id"
            className="font-mono text-xs"
            value={resourceId}
            onChange={(e) => setResourceId(e.target.value)}
          />
        </Field>
      </div>
      <Field>
        <FieldLabel htmlFor="a-name">Action</FieldLabel>
        <Input id="a-name" value={action} onChange={(e) => setAction(e.target.value)} />
      </Field>
      <SubmitButton pending={m.isPending} />
    </form>
  );
}

function RbacForm({ onResult }: { onResult: (r: DecisionRecord) => void }) {
  const m = useRbacSimulate();
  const [userId, setUserId] = useState("");
  const [permission, setPermission] = useState("");
  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        m.mutate(
          { user_id: userId.trim(), permission: permission.trim() },
          { onSuccess: record(onResult) },
        );
      }}
    >
      <Field>
        <FieldLabel htmlFor="rb-user">User ID</FieldLabel>
        <Input
          id="rb-user"
          className="font-mono text-xs"
          placeholder="user uuid"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
      </Field>
      <Field>
        <FieldLabel htmlFor="rb-perm">Permission</FieldLabel>
        <Input
          id="rb-perm"
          placeholder="users.read"
          value={permission}
          onChange={(e) => setPermission(e.target.value)}
        />
      </Field>
      <SubmitButton pending={m.isPending} />
    </form>
  );
}

function RebacForm({ onResult }: { onResult: (r: DecisionRecord) => void }) {
  const m = useRebacSimulate();
  const [object, setObject] = useState("");
  const [relation, setRelation] = useState("");
  const [userId, setUserId] = useState("");
  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        m.mutate(
          { object: object.trim(), relation: relation.trim(), user_id: userId.trim() },
          { onSuccess: record(onResult) },
        );
      }}
    >
      <Field>
        <FieldLabel htmlFor="re-object">Object</FieldLabel>
        <Input
          id="re-object"
          placeholder="document:readme"
          value={object}
          onChange={(e) => setObject(e.target.value)}
        />
      </Field>
      <Field>
        <FieldLabel htmlFor="re-relation">Relation</FieldLabel>
        <Input
          id="re-relation"
          placeholder="viewer"
          value={relation}
          onChange={(e) => setRelation(e.target.value)}
        />
      </Field>
      <Field>
        <FieldLabel htmlFor="re-user">User ID</FieldLabel>
        <Input
          id="re-user"
          className="font-mono text-xs"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
      </Field>
      <SubmitButton pending={m.isPending} />
    </form>
  );
}

function AbacForm({ onResult }: { onResult: (r: DecisionRecord) => void }) {
  const m = useAbacSimulate();
  const [raw, setRaw] = useState(() =>
    JSON.stringify(
      {
        subject: { department: "Engineering" },
        resource: { type: "document", id: "res-1", attrs: { environment: "production" } },
        action: "read",
        context: { hour_of_day: 14, mfa: true },
      },
      null,
      2,
    ),
  );
  const [err, setErr] = useState<string | null>(null);
  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        try {
          const p = JSON.parse(raw);
          setErr(null);
          m.mutate(
            {
              subject: p.subject ?? {},
              resource: p.resource ?? { type: "*", id: "res-1" },
              action: p.action ?? "*",
              context: p.context ?? {},
            },
            { onSuccess: record(onResult) },
          );
        } catch {
          setErr("Invalid JSON");
        }
      }}
    >
      <MonacoPanel
        value={raw}
        language="json"
        readOnly={false}
        onChange={setRaw}
        height={220}
        ariaLabel="ABAC evaluation input"
      />
      {err && <p className="text-destructive text-sm">{err}</p>}
      <SubmitButton pending={m.isPending} />
    </form>
  );
}

function SubmitButton({ pending }: { pending: boolean }) {
  return (
    <Button type="submit" disabled={pending} className="self-start">
      {pending ? <Loader2Icon className="animate-spin" /> : <PlayIcon />}
      Simulate
    </Button>
  );
}

function BatchCard() {
  const batch = useBatchSimulate();
  const [subjects, setSubjects] = useState("user:alice\nuser:bob\nuser:carol");
  const [resourceType, setResourceType] = useState("document");
  const [resourceId, setResourceId] = useState("res-1");
  const [action, setAction] = useState("read");

  function run() {
    const subs = subjects
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [type, ...rest] = l.split(":");
        return { type: type || "user", id: rest.join(":") };
      });
    batch.run(subs, { type: resourceType.trim(), id: resourceId.trim() }, action.trim());
  }

  const allowCount = batch.results.filter((r) => r.allowed).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Batch simulation</CardTitle>
        <CardDescription>
          Fan-out across up to {BATCH_CAP} subjects against one resource + action. Client-side over
          the real PDP — there is no batch endpoint yet.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="grid gap-3 lg:grid-cols-[1fr_1fr_1fr]">
          <Field>
            <FieldLabel htmlFor="b-res-type">Resource type</FieldLabel>
            <Input
              id="b-res-type"
              value={resourceType}
              onChange={(e) => setResourceType(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="b-res-id">Resource ID</FieldLabel>
            <Input
              id="b-res-id"
              className="font-mono text-xs"
              value={resourceId}
              onChange={(e) => setResourceId(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="b-action">Action</FieldLabel>
            <Input id="b-action" value={action} onChange={(e) => setAction(e.target.value)} />
          </Field>
        </div>
        <Field>
          <FieldLabel htmlFor="b-subjects">Subjects (one per line, type:id)</FieldLabel>
          <textarea
            id="b-subjects"
            className="min-h-24 rounded-md border bg-background p-2 font-mono text-xs"
            value={subjects}
            onChange={(e) => setSubjects(e.target.value)}
          />
        </Field>
        <Button onClick={run} disabled={batch.isRunning} className="self-start">
          {batch.isRunning ? <Loader2Icon className="animate-spin" /> : <PlayIcon />}
          Run batch
        </Button>
        {batch.isRunning && (
          <Meter
            value={batch.progress}
            max={subjects.split("\n").filter(Boolean).length}
            label="Progress"
          />
        )}
        {batch.results.length > 0 && (
          <>
            <div className="flex items-center gap-2 text-sm">
              <Badge variant="success">{allowCount} allow</Badge>
              <Badge variant="destructive">{batch.results.length - allowCount} deny</Badge>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Subject</TableHead>
                  <TableHead>Decision</TableHead>
                  <TableHead className="text-right">Latency</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {batch.results.map((r) => {
                  const subj = r.input.subject as { type: string; id: string } | undefined;
                  return (
                    <TableRow key={r.id}>
                      <TableCell className="font-mono text-xs">
                        {subj ? `${subj.type}:${subj.id}` : "—"}
                      </TableCell>
                      <TableCell>
                        <DecisionBadge allowed={r.allowed} />
                      </TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">
                        {r.durationMs} ms
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </>
        )}
      </CardContent>
    </Card>
  );
}
