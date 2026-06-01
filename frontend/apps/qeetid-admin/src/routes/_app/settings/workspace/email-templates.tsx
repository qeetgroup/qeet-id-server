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
  StatusPill,
  Textarea,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import {
  type EmailTemplate,
  sampleVar,
  useEmailTemplates,
  usePreviewEmailTemplate,
  useResetEmailTemplate,
  useUpsertEmailTemplate,
} from "@/lib/email-templates";

export const Route = createFileRoute("/_app/settings/workspace/email-templates")({
  component: EmailTemplatesPage,
});

function EmailTemplatesPage() {
  const listQ = useEmailTemplates();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const items = listQ.data?.items ?? [];
  const selected = items.find((t) => t.key === selectedKey) ?? items[0];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Customise the transactional emails Qeet ID sends. Unedited templates use the built-in defaults." />
      <DataState
        isLoading={listQ.isLoading}
        isError={listQ.isError}
        error={listQ.error}
        isEmpty={items.length === 0}
        skeletonRows={3}
      >
        <div className="grid gap-4 md:grid-cols-[260px_1fr]">
          <Card className="h-fit">
            <CardHeader>
              <CardTitle className="text-base">Templates</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-1 p-2">
              {items.map((t) => {
                const active = selected?.key === t.key;
                return (
                  <button
                    key={t.key}
                    type="button"
                    onClick={() => setSelectedKey(t.key)}
                    className={`flex items-center justify-between rounded-md px-3 py-2 text-left text-sm transition-colors ${
                      active ? "bg-secondary text-secondary-foreground" : "hover:bg-muted"
                    }`}
                  >
                    <span>{t.name}</span>
                    {t.custom && <Badge variant="muted">custom</Badge>}
                  </button>
                );
              })}
            </CardContent>
          </Card>

          {selected && <Editor key={selected.key} template={selected} />}
        </div>
      </DataState>
    </div>
  );
}

function Editor({ template }: { template: EmailTemplate }) {
  const upsertM = useUpsertEmailTemplate();
  const resetM = useResetEmailTemplate();
  const previewM = usePreviewEmailTemplate();
  const [subject, setSubject] = useState(template.subject);
  const [body, setBody] = useState(template.body);

  const dirty = subject !== template.subject || body !== template.body;
  const preview = () => {
    const vars = Object.fromEntries(template.variables.map((v) => [v, sampleVar(v)]));
    previewM.mutate({ key: template.key, vars });
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-base">{template.name}</CardTitle>
            <CardDescription>{template.description}</CardDescription>
          </div>
          <StatusPill kind={template.custom ? "info" : "muted"}>
            {template.custom ? "Customised" : "Default"}
          </StatusPill>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="subject">Subject</FieldLabel>
          <Input id="subject" value={subject} onChange={(e) => setSubject(e.target.value)} />
        </Field>
        <Field>
          <FieldLabel htmlFor="body">Body</FieldLabel>
          <Textarea id="body" rows={6} value={body} onChange={(e) => setBody(e.target.value)} />
        </Field>

        <Field>
          <FieldLabel>Variables</FieldLabel>
          <div className="flex flex-wrap gap-1">
            {template.variables.map((v) => (
              <Badge key={v} variant="outline" className="font-mono text-xs">
                {`{{${v}}}`}
              </Badge>
            ))}
            {template.variables.length === 0 && (
              <span className="text-xs text-muted-foreground">No variables.</span>
            )}
          </div>
          <FieldDescription>Insert these placeholders; they&apos;re filled in when the email is sent.</FieldDescription>
        </Field>

        {previewM.data && (
          <div className="rounded-md border bg-muted/40 p-3 text-sm">
            <div className="font-medium">{previewM.data.subject}</div>
            <div className="mt-1 whitespace-pre-wrap text-muted-foreground">{previewM.data.body}</div>
          </div>
        )}

        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="ghost" onClick={preview} disabled={previewM.isPending}>
            Preview
          </Button>
          <Button
            variant="outline"
            onClick={() => resetM.mutate(template.key)}
            disabled={resetM.isPending || !template.custom}
          >
            Reset to default
          </Button>
          <Button
            onClick={() => upsertM.mutate({ key: template.key, subject, body })}
            disabled={upsertM.isPending || !dirty}
          >
            {upsertM.isPending ? "Saving…" : "Save template"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
