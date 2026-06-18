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
import { CheckCircle2Icon, Loader2Icon, NetworkIcon, Trash2Icon, XCircleIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  useCheckRelation,
  useDeleteTuple,
  useRelationTuples,
  useWriteTuple,
} from "@/lib/relationships";

export const Route = createFileRoute("/_app/access/relationships")({
  component: RelationshipsPage,
});

function RelationshipsPage() {
  const [object, setObject] = useState("");
  const [browseObject, setBrowseObject] = useState("");
  const tuplesQ = useRelationTuples(browseObject);
  const writeM = useWriteTuple();
  const deleteM = useDeleteTuple();

  const [relation, setRelation] = useState("");
  const [subject, setSubject] = useState("");

  const items = tuplesQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Fine-grained, relationship-based access (ReBAC). Tuples assert &ldquo;object relation subject&rdquo;; a check resolves direct grants and usersets (e.g. group:eng#member) recursively. Complements roles (RBAC) and policies (ABAC)." />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Write a tuple</CardTitle>
            <CardDescription>
              e.g. object <code>document:readme</code>, relation <code>viewer</code>, subject{" "}
              <code>user:&lt;id&gt;</code> or <code>group:eng#member</code>.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="flex flex-col gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                if (object.trim() && relation.trim() && subject.trim()) {
                  writeM.mutate(
                    { object: object.trim(), relation: relation.trim(), subject: subject.trim() },
                    { onSuccess: () => setBrowseObject(object.trim()) },
                  );
                }
              }}
            >
              <Field>
                <FieldLabel htmlFor="object">Object</FieldLabel>
                <Input
                  id="object"
                  placeholder="document:readme"
                  value={object}
                  onChange={(e) => setObject(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="relation">Relation</FieldLabel>
                <Input
                  id="relation"
                  placeholder="viewer"
                  value={relation}
                  onChange={(e) => setRelation(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="subject">Subject</FieldLabel>
                <Input
                  id="subject"
                  placeholder="user:… or group:eng#member"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
                <FieldDescription>A user, or a userset (object#relation).</FieldDescription>
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

        <CheckCard />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Tuples on an object</CardTitle>
          <CardDescription>Enter an object to list its relationship tuples.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Input
            placeholder="document:readme"
            value={browseObject}
            onChange={(e) => setBrowseObject(e.target.value)}
          />
          {browseObject && (
            <DataState
              isLoading={tuplesQ.isLoading}
              isError={tuplesQ.isError}
              error={tuplesQ.error}
              isEmpty={items.length === 0}
              emptyIcon={NetworkIcon}
              emptyTitle="No tuples on this object."
              skeletonRows={2}
            >
              <ul className="divide-y">
                {items.map((t) => (
                  <li key={t.id} className="flex items-center justify-between gap-4 py-2">
                    <span className="font-mono text-sm">
                      {t.object} <span className="text-muted-foreground">#{t.relation}</span>{" "}
                      {t.subject}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={deleteM.isPending}
                      onClick={() => deleteM.mutate(t.id)}
                    >
                      <Trash2Icon /> Delete
                    </Button>
                  </li>
                ))}
              </ul>
            </DataState>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function CheckCard() {
  const checkM = useCheckRelation();
  const [object, setObject] = useState("");
  const [relation, setRelation] = useState("");
  const [userId, setUserId] = useState("");
  const result = checkM.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Check access</CardTitle>
        <CardDescription>
          Does a user have a relation on an object? (resolves usersets)
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (object.trim() && relation.trim() && userId.trim()) {
              checkM.mutate({
                object: object.trim(),
                relation: relation.trim(),
                user_id: userId.trim(),
              });
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
        {result && (
          <div className="mt-3 flex items-center gap-2 text-sm font-medium">
            {result.allowed ? (
              <>
                <CheckCircle2Icon className="size-4 text-emerald-600 dark:text-emerald-400" />
                <Badge variant="success">allowed</Badge>
              </>
            ) : (
              <>
                <XCircleIcon className="text-destructive size-4" />
                <Badge variant="outline">denied</Badge>
              </>
            )}
          </div>
        )}
        {checkM.error && (
          <p className="mt-2 text-destructive text-sm">{(checkM.error as ApiError).message}</p>
        )}
      </CardContent>
    </Card>
  );
}
