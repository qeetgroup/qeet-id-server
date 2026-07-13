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
import { useTranslation } from "react-i18next";

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
  const { t } = useTranslation("settings");
  const listQ = useEmailTemplates();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const items = listQ.data?.items ?? [];
  const selected = items.find((item) => item.key === selectedKey) ?? items[0];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("workspace.emailTemplates.description")} />
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
              <CardTitle className="text-base">{t("workspace.emailTemplates.listTitle")}</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-1 p-2">
              {items.map((item) => {
                const active = selected?.key === item.key;
                return (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => setSelectedKey(item.key)}
                    className={`flex items-center justify-between rounded-md px-3 py-2 text-left text-sm transition-colors ${
                      active ? "bg-secondary text-secondary-foreground" : "hover:bg-muted"
                    }`}
                  >
                    <span>{item.name}</span>
                    {item.custom && <Badge variant="muted">{t("workspace.emailTemplates.custom")}</Badge>}
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
  const { t } = useTranslation("settings");
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
            {template.custom ? t("workspace.emailTemplates.editor.customised") : t("workspace.emailTemplates.editor.default")}
          </StatusPill>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="subject">{t("workspace.emailTemplates.editor.subject")}</FieldLabel>
          <Input id="subject" value={subject} onChange={(e) => setSubject(e.target.value)} />
        </Field>
        <Field>
          <FieldLabel htmlFor="body">{t("workspace.emailTemplates.editor.body")}</FieldLabel>
          <Textarea id="body" rows={6} value={body} onChange={(e) => setBody(e.target.value)} />
        </Field>

        <Field>
          <FieldLabel>{t("workspace.emailTemplates.editor.variables")}</FieldLabel>
          <div className="flex flex-wrap gap-1">
            {template.variables.map((v) => (
              <Badge key={v} variant="outline" className="font-mono text-xs">
                {`{{${v}}}`}
              </Badge>
            ))}
            {template.variables.length === 0 && (
              <span className="text-xs text-muted-foreground">{t("workspace.emailTemplates.editor.noVariables")}</span>
            )}
          </div>
          <FieldDescription>{t("workspace.emailTemplates.editor.variablesHelp")}</FieldDescription>
        </Field>

        {previewM.data && (
          <div className="rounded-md border bg-muted/40 p-3 text-sm">
            <div className="font-medium">{previewM.data.subject}</div>
            <div className="mt-1 whitespace-pre-wrap text-muted-foreground">{previewM.data.body}</div>
          </div>
        )}

        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="ghost" onClick={preview} disabled={previewM.isPending}>
            {t("workspace.emailTemplates.editor.preview")}
          </Button>
          <Button
            variant="outline"
            onClick={() => resetM.mutate(template.key)}
            disabled={resetM.isPending || !template.custom}
          >
            {t("workspace.emailTemplates.editor.resetToDefault")}
          </Button>
          <Button
            onClick={() => upsertM.mutate({ key: template.key, subject, body })}
            disabled={upsertM.isPending || !dirty}
          >
            {upsertM.isPending ? t("workspace.emailTemplates.editor.saving") : t("workspace.emailTemplates.editor.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
