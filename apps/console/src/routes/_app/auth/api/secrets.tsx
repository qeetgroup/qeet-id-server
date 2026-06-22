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
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckIcon, CopyIcon, EyeIcon, EyeOffIcon, KeyRoundIcon, Loader2Icon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  useCreateSecret,
  useDeleteSecret,
  useRevealSecret,
  useRotateSecret,
  useSecrets,
} from "@/lib/secrets";

export const Route = createFileRoute("/_app/auth/api/secrets")({ component: SecretsPage });

function SecretsPage() {
  const listQ = useSecrets();
  const revealM = useRevealSecret();
  const rotateM = useRotateSecret();
  const deleteM = useDeleteSecret();
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [copied, setCopied] = useState<string | null>(null);

  const items = listQ.data?.items ?? [];

  const toggleReveal = (id: string) => {
    if (revealed[id] !== undefined) {
      setRevealed((r) => {
        const next = { ...r };
        delete next[id];
        return next;
      });
      return;
    }
    revealM.mutate(id, { onSuccess: (d) => setRevealed((r) => ({ ...r, [id]: d.value })) });
  };

  const copy = (id: string, value: string) => {
    void navigator.clipboard?.writeText(value);
    setCopied(id);
    window.setTimeout(() => setCopied((c) => (c === id ? null : c)), 1500);
  };

  const rotate = (id: string, name: string) => {
    const v = window.prompt(`New value for "${name}":`);
    if (v && v.trim()) rotateM.mutate({ id, value: v.trim() });
  };

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Encrypted vault for integration secrets — 3rd-party API keys, tokens and signing material. Values are AES-256-GCM encrypted at rest and only shown via an audited reveal."
        actions={
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon className="mr-2 size-4" />
            New secret
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Secrets</CardTitle>
          <CardDescription>{items.length} secret{items.length === 1 ? "" : "s"}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={KeyRoundIcon}
            emptyTitle="No secrets yet."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((s) => {
                  const shown = revealed[s.id];
                  return (
                    <TableRow key={s.id}>
                      <TableCell className="font-mono text-xs">{s.name}</TableCell>
                      <TableCell>{s.scope ? <Badge variant="outline">{s.scope}</Badge> : "—"}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {shown !== undefined ? (
                          <span className="flex items-center gap-2">
                            <span className="max-w-[220px] truncate">{shown}</span>
                            <button
                              type="button"
                              onClick={() => copy(s.id, shown)}
                              className="text-muted-foreground hover:text-foreground"
                              aria-label="Copy"
                            >
                              {copied === s.id ? <CheckIcon className="size-3.5" /> : <CopyIcon className="size-3.5" />}
                            </button>
                          </span>
                        ) : (
                          <span className="text-muted-foreground">{s.last4 ? `••••••••${s.last4}` : "••••••••"}</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        <TimeSince value={s.updated_at} />
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => toggleReveal(s.id)}
                          disabled={revealM.isPending}
                        >
                          {shown !== undefined ? <EyeOffIcon /> : <EyeIcon />}
                          {shown !== undefined ? "Hide" : "Reveal"}
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => rotate(s.id, s.name)} disabled={rotateM.isPending}>
                          <RefreshCwIcon /> Rotate
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            if (confirm(`Delete secret "${s.name}"? Anything using it will break.`)) deleteM.mutate(s.id);
                          }}
                          disabled={deleteM.isPending}
                        >
                          <Trash2Icon /> Delete
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <CreateSecretSheet open={creating} onOpenChange={setCreating} />
    </div>
  );
}

function CreateSecretSheet({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const createM = useCreateSecret();
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const data = new FormData(e.currentTarget);
            createM.mutate(
              {
                name: String(data.get("name") ?? "").trim(),
                scope: String(data.get("scope") ?? "").trim(),
                value: String(data.get("value") ?? ""),
              },
              { onSuccess: () => onOpenChange(false) },
            );
          }}
        >
          <SheetHeader>
            <SheetTitle>New secret</SheetTitle>
            <SheetDescription>The value is encrypted immediately and can&apos;t be read back except via reveal.</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input id="name" name="name" placeholder="stripe.api_key" className="font-mono" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="scope">Scope</FieldLabel>
                <Input id="scope" name="scope" placeholder="billing (optional)" />
                <FieldDescription>A free-text label for grouping, e.g. the integration it belongs to.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="value">Value</FieldLabel>
                <Input id="value" name="value" type="password" placeholder="sk_live_…" className="font-mono" required />
              </Field>
              {createM.error && (
                <Field>
                  <FieldError>{(createM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Saving…" : "Create secret"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
