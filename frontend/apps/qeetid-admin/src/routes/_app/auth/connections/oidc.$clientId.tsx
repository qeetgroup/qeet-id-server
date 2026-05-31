import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CodeBlock,
  CopyableSecret,
  DataState,
  StatusPill,
  TimeSince,
  buttonVariants,
} from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { ArrowLeftIcon, KeySquareIcon } from "lucide-react";

import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/auth/connections/oidc/$clientId")({
  component: OidcClientDetailPage,
});

type OidcClient = {
  id: string;
  tenant_id: string;
  client_id: string;
  name: string;
  type: "public" | "confidential";
  redirect_uris: string[];
  post_logout_uris?: string[] | null;
  grant_types: string[];
  scopes: string[];
  created_at: string;
};

function OidcClientDetailPage() {
  const { clientId } = Route.useParams();
  const tenantId = useTenantId();

  // Backend doesn't ship GET /v1/oidc/clients/{id} yet — read the
  // tenant's full list and filter by client_id (the path param is the
  // public client_id, not the row UUID, to match what callers
  // copy-paste from the list page).
  const listQ = useQuery({
    queryKey: ["oidc-clients", tenantId],
    queryFn: () => api<{ items: OidcClient[] }>(`/v1/tenants/${tenantId}/oidc/clients`),
    enabled: !!tenantId,
  });

  const client = listQ.data?.items?.find((c) => c.client_id === clientId || c.id === clientId);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div>
        <Link
          to="/auth/connections/oidc"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeftIcon className="size-3.5" /> All applications
        </Link>
      </div>

      <DataState
        isLoading={listQ.isLoading}
        isError={listQ.isError}
        error={listQ.error}
        isEmpty={listQ.isSuccess && !client}
        emptyIcon={KeySquareIcon}
        emptyTitle={`No application "${clientId}" in this tenant`}
        emptyDescription={
          <>
            It may have been deleted, or you may not have permission to view it.{" "}
            <Link to="/auth/connections/oidc" className="underline">
              Back to the list
            </Link>
            .
          </>
        }
      >
        {client && (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader className="flex flex-row items-start justify-between gap-3">
                <div>
                  <CardTitle className="text-xl">{client.name}</CardTitle>
                  <CardDescription className="font-mono">{client.client_id}</CardDescription>
                </div>
                <StatusPill kind={client.type === "confidential" ? "info" : "muted"}>
                  {client.type}
                </StatusPill>
              </CardHeader>
              <CardContent className="flex flex-col gap-6">
                <section>
                  <h3 className="text-sm font-medium">Client ID</h3>
                  <div className="mt-2">
                    <CopyableSecret value={client.client_id} oneLine />
                  </div>
                </section>

                <section>
                  <h3 className="text-sm font-medium">Redirect URIs</h3>
                  <ul className="mt-2 flex flex-col gap-1.5">
                    {client.redirect_uris.length === 0 ? (
                      <li className="text-sm text-muted-foreground">None configured.</li>
                    ) : (
                      client.redirect_uris.map((u) => (
                        <li key={u} className="rounded-md border bg-muted/30 px-3 py-1.5 font-mono text-xs">
                          {u}
                        </li>
                      ))
                    )}
                  </ul>
                </section>

                {client.post_logout_uris && client.post_logout_uris.length > 0 && (
                  <section>
                    <h3 className="text-sm font-medium">Post-logout URIs</h3>
                    <ul className="mt-2 flex flex-col gap-1.5">
                      {client.post_logout_uris.map((u) => (
                        <li key={u} className="rounded-md border bg-muted/30 px-3 py-1.5 font-mono text-xs">
                          {u}
                        </li>
                      ))}
                    </ul>
                  </section>
                )}

                <section className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div>
                    <h3 className="text-sm font-medium">Grant types</h3>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {client.grant_types.map((g) => (
                        <Badge key={g} variant="secondary">
                          {g}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium">Scopes</h3>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {client.scopes.map((s) => (
                        <Badge key={s} variant="outline">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </section>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Metadata</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground">Created</p>
                  <TimeSince value={client.created_at} className="font-mono text-xs" />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Row ID</p>
                  <p className="font-mono text-xs">{client.id}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Tenant</p>
                  <p className="font-mono text-xs">{client.tenant_id}</p>
                </div>
              </CardContent>
            </Card>

            <Card className="lg:col-span-3">
              <CardHeader>
                <CardTitle className="text-base">Discovery snippet</CardTitle>
                <CardDescription>
                  Drop into your OIDC client library — these are the configured endpoints for this
                  application.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  language="json"
                  value={JSON.stringify(
                    {
                      issuer: "https://api.qeetid.com",
                      authorization_endpoint: "https://api.qeetid.com/oauth/authorize",
                      token_endpoint: "https://api.qeetid.com/oauth/token-code",
                      userinfo_endpoint: "https://api.qeetid.com/oauth/userinfo",
                      jwks_uri: "https://api.qeetid.com/.well-known/jwks.json",
                      client_id: client.client_id,
                      grant_types: client.grant_types,
                      scopes: client.scopes,
                    },
                    null,
                    2,
                  )}
                />
                <Link
                  to="/auth/connections/oidc"
                  className={`mt-3 ${buttonVariants({ variant: "outline", size: "sm" })}`}
                >
                  Back to applications
                </Link>
              </CardContent>
            </Card>
          </div>
        )}
      </DataState>
    </div>
  );
}
