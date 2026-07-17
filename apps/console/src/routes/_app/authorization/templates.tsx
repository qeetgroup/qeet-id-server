import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  SegmentedControl,
  SegmentedControlItem,
} from "@qeetrix/ui";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { ArrowRightIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { setBuilderDoc } from "@/lib/authz-store";
import { POLICY_TEMPLATES, type PolicyTemplate, TEMPLATE_CATEGORIES } from "@/lib/authz-templates";

export const Route = createFileRoute("/_app/authorization/templates")({
  component: TemplatesPage,
});

function TemplatesPage() {
  const navigate = useNavigate();
  const [category, setCategory] = useState<string>("all");

  const filtered =
    category === "all" ? POLICY_TEMPLATES : POLICY_TEMPLATES.filter((t) => t.category === category);

  function use(t: PolicyTemplate) {
    setBuilderDoc(t.build());
    navigate({ to: "/authorization/builder" });
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Start from a battle-tested pattern. Choosing a template pre-fills the Policy Builder with a real, editable policy." />

      <SegmentedControl value={category} onValueChange={setCategory} aria-label="Category">
        <SegmentedControlItem value="all">All</SegmentedControlItem>
        {TEMPLATE_CATEGORIES.map((c) => (
          <SegmentedControlItem key={c} value={c}>
            {c}
          </SegmentedControlItem>
        ))}
      </SegmentedControl>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {filtered.map((t) => (
          <Card key={t.id} className="flex flex-col">
            <CardHeader>
              <div className="flex items-center justify-between gap-2">
                <Badge variant="secondary">{t.vendor}</Badge>
                <Badge variant="muted">{t.category}</Badge>
              </div>
              <CardTitle className="text-base">{t.name}</CardTitle>
              <CardDescription>{t.description}</CardDescription>
            </CardHeader>
            <CardContent className="mt-auto flex flex-col gap-3">
              <div className="flex flex-wrap gap-1">
                {t.tags.map((tag) => (
                  <span
                    key={tag}
                    className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                  >
                    {tag}
                  </span>
                ))}
              </div>
              <Button variant="outline" size="sm" className="self-start" onClick={() => use(t)}>
                Use template <ArrowRightIcon />
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
