import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  Input,
  Skeleton,
} from "@qeetid/ui";
import { useMutation } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { useMe } from "@/lib/auth";

export const Route = createFileRoute("/account/profile")({ component: ProfilePage });

function ProfilePage() {
  const me = useMe();
  const [draft, setDraft] = useState({ display_name: "", phone: "" });

  // Hydrate the form once `me` resolves, then leave it alone so the
  // user's edits aren't blown away by background refetches.
  const hydratedRef = useState<{ done: boolean }>({ done: false })[0];
  useEffect(() => {
    if (!hydratedRef.done && me.data) {
      setDraft({
        display_name: me.data.display_name ?? "",
        phone: "",
      });
      hydratedRef.done = true;
    }
  }, [me.data, hydratedRef]);

  const saveM = useMutation({
    mutationFn: (body: { display_name?: string }) =>
      api<unknown>(`/v1/users/${me.data?.id}`, { method: "PATCH", body }),
    onSuccess: () => me.refetch(),
    meta: { successMessage: "Profile updated" },
  });

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Profile</CardTitle>
          <CardDescription>
            The name and contact details we show across Qeet ID.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {me.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-8 w-1/2" />
              <Skeleton className="h-8 w-1/2" />
            </div>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                saveM.mutate({
                  display_name: draft.display_name.trim() || undefined,
                });
              }}
            >
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="display_name">Display name</FieldLabel>
                  <Input
                    id="display_name"
                    value={draft.display_name}
                    onChange={(e) => setDraft((d) => ({ ...d, display_name: e.target.value }))}
                    placeholder="How you'd like to be addressed"
                  />
                </Field>

                <Field>
                  <FieldLabel htmlFor="email">Email</FieldLabel>
                  <Input id="email" value={me.data?.email ?? ""} disabled />
                  <FieldDescription>
                    Change your email from the security tab — it requires re-verification.
                  </FieldDescription>
                </Field>

                <Field>
                  <Button type="submit" disabled={saveM.isPending}>
                    {saveM.isPending && <Loader2Icon className="animate-spin" />}
                    {saveM.isPending ? "Saving…" : "Save changes"}
                  </Button>
                </Field>
              </FieldGroup>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
