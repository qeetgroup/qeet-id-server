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
  Switch,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, Trash2Icon, ZapIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  useAuthHooks,
  useCreateAuthHook,
  useDeleteAuthHook,
  useUpdateAuthHook,
} from "@/lib/auth-hooks";

export const Route = createFileRoute("/_app/developer/auth-hooks")({ component: AuthHooksPage });

function AuthHooksPage() {
  const hooksQ = useAuthHooks();
  const createM = useCreateAuthHook();
  const updateM = useUpdateAuthHook();
  const deleteM = useDeleteAuthHook();

  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [failOpen, setFailOpen] = useState(true);

  const items = hooksQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Run a synchronous policy endpoint during sign-in. After credentials verify, Qeet POSTs a signed event to your hook (X-Qeet-Signature, HMAC-SHA256); the hook returns {decision:'allow'|'deny'}. Hooks are bounded by a 3s timeout." />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Add a login hook</CardTitle>
          <CardDescription>
            Fired after a password is verified (the &ldquo;post_login&rdquo; trigger).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (url.trim()) {
                createM.mutate(
                  { url: url.trim(), secret: secret.trim(), fail_open: failOpen },
                  {
                    onSuccess: () => {
                      setUrl("");
                      setSecret("");
                    },
                  },
                );
              }
            }}
          >
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <Field className="flex-1">
                <FieldLabel htmlFor="url">Hook URL</FieldLabel>
                <Input
                  id="url"
                  placeholder="https://policy.acme.com/qeet/login"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </Field>
              <Field className="sm:w-56">
                <FieldLabel htmlFor="secret">Signing secret</FieldLabel>
                <Input
                  id="secret"
                  type="password"
                  placeholder="write-only"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                />
              </Field>
              <Button type="submit" disabled={createM.isPending || !url.trim()}>
                {createM.isPending && <Loader2Icon className="animate-spin" />}
                Add
              </Button>
            </div>
            <Field>
              <div className="flex items-center justify-between gap-4">
                <div>
                  <FieldLabel>Fail open</FieldLabel>
                  <FieldDescription>
                    If the hook errors or times out, allow the sign-in (recommended). Turn off to
                    block sign-ins when the hook is unreachable.
                  </FieldDescription>
                </div>
                <Switch checked={failOpen} aria-label="Fail open" onCheckedChange={setFailOpen} />
              </div>
            </Field>
          </form>
          {createM.error && (
            <p className="mt-2 text-destructive text-sm">{(createM.error as ApiError).message}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Hooks</CardTitle>
          <CardDescription>Toggle enabled / fail-open per hook.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={hooksQ.isLoading}
            isError={hooksQ.isError}
            error={hooksQ.error}
            isEmpty={items.length === 0}
            emptyIcon={ZapIcon}
            emptyTitle="No login hooks configured."
            emptyDescription="Add a hook above to gate sign-ins with your own policy."
            skeletonRows={2}
          >
            <ul className="divide-y">
              {items.map((h) => (
                <li key={h.id} className="flex items-center justify-between gap-4 px-6 py-3">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-medium">
                      <span className="truncate font-mono">{h.url}</span>
                      <Badge variant={h.fail_open ? "outline" : "destructive"}>
                        {h.fail_open ? "fail-open" : "fail-closed"}
                      </Badge>
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {h.trigger} · added <TimeSince value={h.created_at} />
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <Switch
                      checked={h.enabled}
                      aria-label="Enabled"
                      disabled={updateM.isPending}
                      onCheckedChange={(v) =>
                        updateM.mutate({ id: h.id, enabled: v, fail_open: h.fail_open })
                      }
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={deleteM.isPending}
                      onClick={() => {
                        if (confirm("Remove this hook?")) deleteM.mutate(h.id);
                      }}
                    >
                      <Trash2Icon /> Remove
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
