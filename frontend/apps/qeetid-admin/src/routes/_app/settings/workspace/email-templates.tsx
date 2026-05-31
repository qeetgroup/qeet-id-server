import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Textarea,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { EyeIcon, MailIcon, RotateCcwIcon, SendIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/settings/workspace/email-templates")({
  component: EmailTemplatesPage,
});

type Template = {
  key: string;
  label: string;
  subject: string;
  body: string;
  variables: string[];
  enabled: boolean;
};

const seed: Template[] = [
  {
    key: "welcome",
    label: "Welcome email",
    subject: "Welcome to {{tenant.name}}, {{user.given_name}}!",
    body: "Hi {{user.given_name}},\n\nThanks for joining {{tenant.name}}. Click below to verify your email.\n\n{{verify_link}}\n\n— The {{tenant.name}} team",
    variables: ["user.given_name", "user.email", "tenant.name", "verify_link"],
    enabled: true,
  },
  {
    key: "magic_link",
    label: "Magic link sign-in",
    subject: "Sign in to {{tenant.name}}",
    body: "Hi,\n\nClick this link to sign in. It expires in 15 minutes and can only be used once.\n\n{{link}}\n\nIf you didn't request this, you can ignore the email.",
    variables: ["user.email", "tenant.name", "link"],
    enabled: true,
  },
  {
    key: "password_reset",
    label: "Password reset",
    subject: "Reset your {{tenant.name}} password",
    body: "Hi,\n\nWe received a request to reset your password.\n\n{{reset_link}}\n\nIf this wasn't you, ignore this email — no change has been made.",
    variables: ["user.email", "tenant.name", "reset_link"],
    enabled: true,
  },
  {
    key: "invitation",
    label: "Team invitation",
    subject: "{{inviter.name}} invited you to join {{tenant.name}}",
    body: "Hi,\n\n{{inviter.name}} invited you to join {{tenant.name}} as a {{role.name}}.\n\nAccept your invite:\n{{accept_link}}\n\nExpires in 7 days.",
    variables: ["inviter.name", "tenant.name", "role.name", "accept_link"],
    enabled: true,
  },
  {
    key: "mfa_enrolled",
    label: "MFA enrolled",
    subject: "Two-step verification enabled",
    body: "Hi {{user.given_name}},\n\nA second factor was just enabled on your account. If you didn't do this, contact support immediately.\n\n— Security team",
    variables: ["user.given_name", "user.email"],
    enabled: false,
  },
];

function EmailTemplatesPage() {
  const [active, setActive] = useState<Template>(seed[0]!);
  const [body, setBody] = useState(active.body);
  const [subject, setSubject] = useState(active.subject);

  const switchTo = (key: string) => {
    const t = seed.find((x) => x.key === key);
    if (!t) return;
    setActive(t);
    setBody(t.body);
    setSubject(t.subject);
  };

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Templates used for transactional emails. Variables in {{ moustache }} are rendered server-side."
        actions={
          <>
            <Button variant="outline">
              <SendIcon className="mr-2 size-4" />
              Send test
            </Button>
            <Button>Save template</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[280px_1fr]">
        <Card className="h-fit">
          <CardHeader>
            <CardTitle className="text-base">Templates</CardTitle>
            <CardDescription>Select to edit</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-1 p-2">
            {seed.map((t) => (
              <button
                key={t.key}
                type="button"
                onClick={() => switchTo(t.key)}
                className={`flex items-center justify-between rounded-md px-3 py-2 text-left text-sm ${
                  active.key === t.key ? "bg-muted font-medium" : "hover:bg-muted/60"
                }`}
              >
                <span className="flex items-center gap-2">
                  <MailIcon className="size-3.5 text-muted-foreground" />
                  {t.label}
                </span>
                {!t.enabled && <Badge variant="outline" className="text-[10px]">off</Badge>}
              </button>
            ))}
          </CardContent>
        </Card>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{active.label}</CardTitle>
              <CardDescription>Subject and body for <code>{active.key}</code>.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4">
              <Field>
                <FieldLabel>From</FieldLabel>
                <div className="grid gap-2 sm:grid-cols-[1fr_2fr]">
                  <Input defaultValue="Acme Auth" />
                  <Input defaultValue="noreply@acme.com" />
                </div>
                <FieldDescription>Sender name and address. Must be a verified domain in branding.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel>Reply-to</FieldLabel>
                <Input defaultValue="support@acme.com" />
              </Field>
              <Field>
                <FieldLabel>Subject</FieldLabel>
                <Input value={subject} onChange={(e) => setSubject(e.target.value)} />
              </Field>
              <Field>
                <FieldLabel>Body (plaintext)</FieldLabel>
                <Textarea
                  className="min-h-[260px] font-mono text-xs"
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel>Locale</FieldLabel>
                <Select defaultValue="en-US">
                  <SelectTrigger className="w-[200px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="en-US">English (US)</SelectItem>
                    <SelectItem value="en-GB">English (UK)</SelectItem>
                    <SelectItem value="de-DE">Deutsch</SelectItem>
                    <SelectItem value="fr-FR">Français</SelectItem>
                    <SelectItem value="es-ES">Español</SelectItem>
                    <SelectItem value="ja-JP">日本語</SelectItem>
                  </SelectContent>
                </Select>
                <FieldDescription>Each template can have a translation per supported locale.</FieldDescription>
              </Field>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Variables</CardTitle>
              <CardDescription>Click to insert into the body.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              {active.variables.map((v) => (
                <button
                  key={v}
                  type="button"
                  onClick={() => setBody((b) => `${b} {{${v}}}`)}
                  className="rounded-md border bg-muted/40 px-2 py-1 font-mono text-xs hover:bg-muted"
                >
                  {`{{${v}}}`}
                </button>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">Live preview</CardTitle>
                  <CardDescription>Variables are replaced with sample values.</CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline">
                    <EyeIcon className="mr-2 size-3" />
                    Preview
                  </Button>
                  <Button size="sm" variant="outline">
                    <RotateCcwIcon className="mr-2 size-3" />
                    Reset
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border bg-background p-4">
                <div className="border-b pb-2 text-sm font-medium">
                  {subject.replaceAll(/{{\s*(\w+(?:\.\w+)*)\s*}}/g, "Acme")}
                </div>
                <pre className="mt-2 whitespace-pre-wrap font-sans text-sm text-muted-foreground">
                  {body.replaceAll(/{{\s*(\w+(?:\.\w+)*)\s*}}/g, (_, k) => `[${k}]`)}
                </pre>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
