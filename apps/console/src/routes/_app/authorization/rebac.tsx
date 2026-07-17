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
  FieldDescription,
  FieldLabel,
  Input,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, NetworkIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { RelationshipGraph } from "@/features/authorization/components/graph/relationship-graph";
import { DecisionBadge } from "@/features/authorization/components/shared/decision-badge";
import type { ApiError } from "@/lib/api";
import { useRebacSimulate } from "@/lib/authz-simulate";
import { pushDecision } from "@/lib/authz-store";
import {
  useDeleteTuple,
  useRelationGraph,
  useRelationTuples,
  useWriteTuple,
} from "@/lib/relationships";

export const Route = createFileRoute("/_app/authorization/rebac")({
  component: RebacPage,
});

function RebacPage() {
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Zanzibar-style relationship tuples: object #relation subject. Write relationships, browse them, and expand the identity graph." />
      <div className="grid gap-4 lg:grid-cols-2">
        <WriteCard />
        <CheckCard />
      </div>
      <BrowseCard />
      <GraphCard />
    </div>
  );
}

function WriteCard() {
  const writeM = useWriteTuple();
  const [object, setObject] = useState("");
  const [relation, setRelation] = useState("");
  const [subject, setSubject] = useState("");
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Write relationship</CardTitle>
        <CardDescription>
          e.g. object <code>document:readme</code>, relation <code>viewer</code>, subject{" "}
          <code>user:…</code> or <code>group:eng#member</code>.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (object.trim() && relation.trim() && subject.trim()) {
              writeM.mutate({
                object: object.trim(),
                relation: relation.trim(),
                subject: subject.trim(),
              });
            }
          }}
        >
          <Field>
            <FieldLabel htmlFor="w-object">Object</FieldLabel>
            <Input
              id="w-object"
              placeholder="document:readme"
              value={object}
              onChange={(e) => setObject(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="w-relation">Relation</FieldLabel>
            <Input
              id="w-relation"
              placeholder="viewer"
              value={relation}
              onChange={(e) => setRelation(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="w-subject">Subject</FieldLabel>
            <Input
              id="w-subject"
              placeholder="user:… or group:eng#member"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
            />
            <FieldDescription>Usersets like group:eng#member expand recursively.</FieldDescription>
          </Field>
          {writeM.error && (
            <p className="text-destructive text-sm">{(writeM.error as ApiError).message}</p>
          )}
          <Button
            type="submit"
            disabled={writeM.isPending || !object.trim() || !relation.trim() || !subject.trim()}
          >
            {writeM.isPending && <Loader2Icon className="animate-spin" />}
            Write tuple
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function CheckCard() {
  const checkM = useRebacSimulate();
  const [object, setObject] = useState("");
  const [relation, setRelation] = useState("");
  const [userId, setUserId] = useState("");
  const record = checkM.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Check relationship</CardTitle>
        <CardDescription>
          Resolve whether a user has a relation to an object (recorded in the Decision Explorer).
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (object.trim() && relation.trim() && userId.trim()) {
              checkM.mutate(
                { object: object.trim(), relation: relation.trim(), user_id: userId.trim() },
                { onSuccess: (rec) => pushDecision(rec) },
              );
            }
          }}
        >
          <Field>
            <FieldLabel htmlFor="c-object">Object</FieldLabel>
            <Input
              id="c-object"
              placeholder="document:readme"
              value={object}
              onChange={(e) => setObject(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="c-relation">Relation</FieldLabel>
            <Input
              id="c-relation"
              placeholder="viewer"
              value={relation}
              onChange={(e) => setRelation(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="c-user">User ID</FieldLabel>
            <Input
              id="c-user"
              className="font-mono text-xs"
              placeholder="user uuid"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
            />
          </Field>
          <Button
            type="submit"
            variant="outline"
            disabled={checkM.isPending || !object.trim() || !relation.trim() || !userId.trim()}
          >
            {checkM.isPending && <Loader2Icon className="animate-spin" />}
            Check
          </Button>
        </form>
        {record && (
          <div className="mt-3 flex items-center gap-2">
            <DecisionBadge allowed={record.allowed} />
            {record.rebac?.path && record.rebac.path.length > 0 && (
              <span className="text-xs text-muted-foreground">
                {record.rebac.path.length} hop{record.rebac.path.length === 1 ? "" : "s"}
              </span>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function BrowseCard() {
  const [object, setObject] = useState("");
  const tuplesQ = useRelationTuples(object);
  const deleteM = useDeleteTuple();
  const items = tuplesQ.data?.items ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Browse tuples</CardTitle>
        <CardDescription>List every relationship stored on an object.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Input
          placeholder="document:readme"
          value={object}
          onChange={(e) => setObject(e.target.value)}
          className="max-w-sm"
          aria-label="Object to browse"
        />
        {object && (
          <DataState
            isLoading={tuplesQ.isLoading}
            isError={tuplesQ.isError}
            error={tuplesQ.error}
            isEmpty={items.length === 0}
            emptyIcon={NetworkIcon}
            emptyTitle="No tuples on this object"
            skeletonRows={2}
          >
            <ul className="divide-y">
              {items.map((tuple) => (
                <li key={tuple.id} className="flex items-center justify-between gap-4 py-2">
                  <span className="font-mono text-sm">
                    {tuple.object} <span className="text-muted-foreground">#{tuple.relation}</span>{" "}
                    {tuple.subject}
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={deleteM.isPending}
                    onClick={() => deleteM.mutate(tuple.id)}
                  >
                    <Trash2Icon /> Remove
                  </Button>
                </li>
              ))}
            </ul>
          </DataState>
        )}
      </CardContent>
    </Card>
  );
}

function GraphCard() {
  const [object, setObject] = useState("");
  const [relation, setRelation] = useState("");
  const [query, setQuery] = useState<{ object: string; relation: string } | null>(null);
  const graphQ = useRelationGraph(query?.object ?? "", query?.relation ?? "");
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Identity graph</CardTitle>
        <CardDescription>
          Expand every subject reachable from an object + relation, with cycle-safe traversal.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (object.trim() && relation.trim())
              setQuery({ object: object.trim(), relation: relation.trim() });
          }}
        >
          <Input
            className="w-52"
            placeholder="document:readme"
            value={object}
            onChange={(e) => setObject(e.target.value)}
            aria-label="Root object"
          />
          <Input
            className="w-36"
            placeholder="viewer"
            value={relation}
            onChange={(e) => setRelation(e.target.value)}
            aria-label="Relation"
          />
          <Button
            type="submit"
            variant="outline"
            disabled={graphQ.isFetching || !object.trim() || !relation.trim()}
          >
            {graphQ.isFetching && <Loader2Icon className="animate-spin" />}
            Expand graph
          </Button>
          {graphQ.data && (
            <Badge variant="muted" className="self-center">
              {graphQ.data.nodes.length} nodes · {graphQ.data.edges.length} edges
            </Badge>
          )}
        </form>
        {query && (
          <DataState
            isLoading={graphQ.isLoading}
            isError={graphQ.isError}
            error={graphQ.error}
            isEmpty={!graphQ.data || graphQ.data.nodes.length === 0}
            emptyIcon={NetworkIcon}
            emptyTitle="No relationships to graph"
            skeletonRows={3}
          >
            {graphQ.data && (
              <RelationshipGraph graph={graphQ.data} rootId={query.object} height={480} />
            )}
          </DataState>
        )}
      </CardContent>
    </Card>
  );
}
