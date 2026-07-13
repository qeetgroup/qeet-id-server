import {
  Alert,
  AlertDescription,
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangleIcon,
  InfoIcon,
  KeyRoundIcon,
  Loader2Icon,
  RotateCcwIcon,
} from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { type RotateKeyResult, useRotateKey, useSigningKeys } from "@/lib/signing-keys";

export const Route = createFileRoute("/_app/auth/api/signing-keys")({
  component: SigningKeysPage,
});

function PEMDialog({ result, onClose }: { result: RotateKeyResult; onClose: () => void }) {
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangleIcon className="size-4 text-amber-500" />
            New Signing Key — Save Immediately
          </DialogTitle>
          <DialogDescription>
            This private key will <strong>not</strong> be shown again. Copy it now and set it as{" "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">JWT_SIGNING_KEY</code>{" "}
            in your server environment before the next restart.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <span>
              <strong>KID:</strong>{" "}
              <code className="font-mono text-xs text-foreground">{result.kid}</code>
            </span>
            <span>
              <strong>Algorithm:</strong> {result.alg}
            </span>
          </div>

          <Alert variant="warning">
            <AlertTriangleIcon className="size-4" />
            <AlertDescription>
              Tokens signed by the old key will remain verifiable until the process restarts. After
              restart you must also add the old public key to{" "}
              <code className="font-mono text-xs">JWT_RETIRED_KEYS</code> to keep existing sessions
              valid during the grace window.
            </AlertDescription>
          </Alert>

          <pre className="max-h-64 overflow-auto rounded-md border bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all select-all">
            {result.private_key_pem}
          </pre>
        </div>

        <DialogFooter>
          <Button
            onClick={() => {
              navigator.clipboard.writeText(result.private_key_pem);
            }}
            variant="outline"
          >
            Copy PEM
          </Button>
          <Button onClick={onClose}>Done — I've saved the key</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SigningKeysPage() {
  const { t } = useTranslation("signingKeys");
  const keysQ = useSigningKeys();
  const rotate = useRotateKey();
  const keys = keysQ.data?.keys ?? [];
  const [rotateResult, setRotateResult] = useState<RotateKeyResult | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  function handleRotateClick() {
    setConfirmOpen(true);
  }

  function handleConfirm() {
    setConfirmOpen(false);
    rotate.mutate(undefined, {
      onSuccess: (data) => setRotateResult(data),
    });
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader title={t("page.title")} description={t("page.description")} />

      <Card className="border-blue-500/30 bg-blue-50/40 dark:bg-blue-950/20">
        <CardContent className="flex items-start gap-3 py-4">
          <InfoIcon className="mt-0.5 size-4 shrink-0 text-blue-600 dark:text-blue-400" />
          <p className="text-sm text-muted-foreground">
            <Trans
              t={t}
              i18nKey="notice"
              components={{
                activeState: <span className="font-medium text-foreground" />,
                retiredState: <span className="font-medium text-foreground" />,
              }}
            />
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-4">
          <div>
            <CardTitle className="text-base">{t("list.title")}</CardTitle>
            <CardDescription>{t("list.count", { count: keys.length })}</CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            disabled={rotate.isPending}
            onClick={handleRotateClick}
          >
            {rotate.isPending ? <Loader2Icon className="animate-spin" /> : <RotateCcwIcon />}
            Rotate Key
          </Button>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={keysQ.isLoading}
            isError={keysQ.isError}
            error={keysQ.error}
            isEmpty={keys.length === 0}
            emptyIcon={KeyRoundIcon}
            emptyTitle={t("list.emptyTitle")}
            skeletonRows={2}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("table.kid")}</TableHead>
                  <TableHead>{t("table.algorithm")}</TableHead>
                  <TableHead>{t("table.use")}</TableHead>
                  <TableHead>{t("table.status")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.kid}>
                    <TableCell className="font-mono text-xs">{k.kid}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{k.alg}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{k.use}</TableCell>
                    <TableCell>
                      <StatusPill
                        status={k.status}
                        kind={k.status === "active" ? "success" : "muted"}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      {/* Confirmation dialog */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangleIcon className="size-4 text-amber-500" />
              Rotate Signing Key?
            </DialogTitle>
            <DialogDescription>
              A new EC P-256 key will be generated immediately. All new tokens will be signed with
              the new key. The current key is retired to verify-only — existing tokens remain valid
              until they expire. You must save the new private key PEM before the next server
              restart.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleConfirm}>
              Rotate Now
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* PEM reveal dialog */}
      {rotateResult && <PEMDialog result={rotateResult} onClose={() => setRotateResult(null)} />}
    </div>
  );
}
