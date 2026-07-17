import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { SendIcon, SparklesIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { ComingSoon } from "@/features/authorization/components/shared/coming-soon";

export const Route = createFileRoute("/_app/authorization/assistant")({
  component: AssistantPage,
});

const EXAMPLE_PROMPTS = [
  "Create a Finance Admin policy",
  "Allow HR to view employee profiles",
  "Restrict production deployments after business hours",
  "Detect overly permissive access",
  "Suggest least-privilege changes for the editor role",
];

function AssistantPage() {
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Describe access rules in plain language and let the assistant draft, explain, and harden policies for you." />

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <Card className="flex min-h-[420px] flex-col">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <SparklesIcon className="size-4 text-primary" aria-hidden />
              Policy assistant
            </CardTitle>
            <CardDescription>
              Natural-language policy authoring, explanation and review.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col gap-4">
            <div className="flex flex-1 items-center justify-center">
              <ComingSoon
                icon={SparklesIcon}
                title="Connect an AI provider to enable the assistant"
                description="The UI is ready. Once an LLM provider (e.g. the Claude API) is configured for this workspace, prompts here will generate complete policies, explain existing ones, and recommend least-privilege changes."
                note="no AI provider configured for this tenant"
              />
            </div>
            <form
              className="flex items-center gap-2"
              onSubmit={(e) => e.preventDefault()}
              aria-disabled
            >
              <Input
                placeholder="Describe a policy…  (assistant not yet connected)"
                disabled
                aria-label="Assistant prompt"
              />
              <Button type="submit" disabled aria-label="Send">
                <SendIcon />
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Try asking</CardTitle>
            <CardDescription>Example prompts the assistant will handle.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {EXAMPLE_PROMPTS.map((p) => (
              <div
                key={p}
                className="flex items-center gap-2 rounded-md border bg-muted/20 p-2.5 text-sm text-muted-foreground"
              >
                <Badge variant="muted" className="shrink-0">
                  prompt
                </Badge>
                <span>{p}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
