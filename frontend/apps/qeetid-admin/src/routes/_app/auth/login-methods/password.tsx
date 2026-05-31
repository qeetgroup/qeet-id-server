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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Slider,
  Switch,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { KeyRoundIcon, LockIcon, ShieldOffIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/login-methods/password")({ component: PasswordPage });

function PasswordPage() {
  const [enabled, setEnabled] = useState(true);
  const [minLen, setMinLen] = useState(12);
  const [requireUpper, setRequireUpper] = useState(true);
  const [requireDigit, setRequireDigit] = useState(true);
  const [requireSymbol, setRequireSymbol] = useState(false);
  const [hibp, setHibp] = useState(true);
  const [reuseLimit, setReuseLimit] = useState(5);
  const [maxAttempts, setMaxAttempts] = useState(5);
  const [lockout, setLockout] = useState("15m");

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Password policy and lockout behavior for this tenant."
        actions={
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Logins (24h)</CardDescription>
            <LockIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">8,412</div>
            <p className="text-xs text-muted-foreground">68% via password</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Failed attempts</CardDescription>
            <ShieldOffIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">214</div>
            <p className="text-xs text-muted-foreground">2.5% of logins</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Locked accounts</CardDescription>
            <KeyRoundIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">7</div>
            <p className="text-xs text-muted-foreground">cleared in next {lockout}</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Complexity</CardTitle>
          <CardDescription>
            Argon2id hashing is always on. These rules apply at sign-up and password change.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>Minimum length: {minLen}</FieldLabel>
            <Slider
              value={[minLen]}
              onValueChange={(v) => setMinLen(Array.isArray(v) ? (v[0] ?? 12) : v)}
              min={8}
              max={32}
              step={1}
            />
            <FieldDescription>NIST SP 800-63B recommends ≥ 8; we suggest 12 with a passphrase hint.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>Password history</FieldLabel>
            <Select value={String(reuseLimit)} onValueChange={(v) => setReuseLimit(Number(v))}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="0">No reuse check</SelectItem>
                <SelectItem value="3">Last 3 passwords</SelectItem>
                <SelectItem value="5">Last 5 passwords</SelectItem>
                <SelectItem value="10">Last 10 passwords</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>Block reusing the user's previous passwords.</FieldDescription>
          </Field>

          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Require uppercase letter</FieldLabel>
                <FieldDescription>At least one A–Z character.</FieldDescription>
              </div>
              <Switch checked={requireUpper} onCheckedChange={setRequireUpper} />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Require digit</FieldLabel>
                <FieldDescription>At least one 0–9 character.</FieldDescription>
              </div>
              <Switch checked={requireDigit} onCheckedChange={setRequireDigit} />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Require symbol</FieldLabel>
                <FieldDescription>At least one of <code>!@#$%^&amp;*</code>.</FieldDescription>
              </div>
              <Switch checked={requireSymbol} onCheckedChange={setRequireSymbol} />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Block compromised passwords (HIBP)</FieldLabel>
                <FieldDescription>k-anonymous check against haveibeenpwned.com.</FieldDescription>
              </div>
              <Switch checked={hibp} onCheckedChange={setHibp} />
            </div>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Lockout</CardTitle>
          <CardDescription>Protect accounts from brute-force attempts.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel>Max failed attempts: {maxAttempts}</FieldLabel>
            <Slider
              value={[maxAttempts]}
              onValueChange={(v) => setMaxAttempts(Array.isArray(v) ? (v[0] ?? 5) : v)}
              min={3}
              max={20}
              step={1}
            />
          </Field>
          <Field>
            <FieldLabel>Lockout duration</FieldLabel>
            <Select value={lockout} onValueChange={(v) => v && setLockout(v)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="5m">5 minutes</SelectItem>
                <SelectItem value="15m">15 minutes</SelectItem>
                <SelectItem value="1h">1 hour</SelectItem>
                <SelectItem value="24h">24 hours</SelectItem>
                <SelectItem value="manual">Until manual unlock</SelectItem>
              </SelectContent>
            </Select>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Hashing algorithm</CardTitle>
          <CardDescription>Read-only — controlled at the platform level.</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Badge>Argon2id</Badge>
            <code className="text-xs text-muted-foreground">m=64MB, t=3, p=4</code>
          </div>
          <Button variant="outline" size="sm" disabled>
            Rotate hashes
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
