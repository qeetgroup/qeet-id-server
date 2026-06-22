import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { ConstructionIcon } from "lucide-react";
import { navGroups } from "@/config/navigation";

export const Route = createFileRoute("/_app/$")({
  component: PlaceholderPage,
});

function titleFromSlug(slug: string) {
  return slug
    .split("-")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(" ");
}

function lookupTitle(path: string) {
  const normalized = `/${path}`;
  for (const group of navGroups) {
    for (const item of group.items) {
      if (item.url === normalized) return { group: group.label, title: item.title };
      const sub = item.items?.find((s) => s.url === normalized);
      if (sub) return { group: group.label, parent: item.title, title: sub.title };
    }
  }
  const segments = path.split("/").filter(Boolean);
  return { title: titleFromSlug(segments[segments.length - 1] ?? "Page") };
}

function PlaceholderPage() {
  const { _splat } = Route.useParams();
  const path = _splat ?? "";
  const meta = lookupTitle(path);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div className="flex flex-col gap-1">
        {meta.group && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span>{meta.group}</span>
            {meta.parent && (
              <>
                <span>›</span>
                <span>{meta.parent}</span>
              </>
            )}
          </div>
        )}
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">{meta.title}</h1>
          <span className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 text-xs font-medium text-secondary-foreground">
            <ConstructionIcon className="size-3" />
            Coming soon
          </span>
        </div>
        <p className="text-sm text-muted-foreground">
          This screen is scaffolded. Build the real UI for{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">/{path}</code> when you're ready.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Overview</CardTitle>
            <CardDescription>Summary widgets for this page</CardDescription>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Stats, recent activity, and quick actions live here.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">List / Table</CardTitle>
            <CardDescription>Records related to this page</CardDescription>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Paginated table with filters and actions.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Settings</CardTitle>
            <CardDescription>Configuration for this area</CardDescription>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Toggles, policies, and integrations.
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
