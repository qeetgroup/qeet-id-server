import {
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, MailIcon, MessageSquareIcon, PlusIcon, SendIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  type OtpChannel,
  useChallengeOtpFactor,
  useConfirmOtpFactor,
  useDeleteOtpFactor,
  useEnrollOtpStart,
  useOtpFactors,
} from "@/lib/mfa";

export const Route = createFileRoute("/_app/auth/mfa/sms-email")({ component: SmsEmailPage });

function SmsEmailPage() {
  const listQ = useOtpFactors();
  const challengeM = useChallengeOtpFactor();
  const deleteM = useDeleteOtpFactor();
  const [adding, setAdding] = useState(false);

  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="One-time passcodes delivered to a verified email address or phone number, used as a second factor."
        actions={
          <Button size="sm" onClick={() => setAdding(true)}>
            <PlusIcon className="mr-2 size-4" />
            Add factor
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>OTP factors</CardTitle>
          <CardDescription>Each delivers a single-use code at sign-in. Codes expire after 10 minutes.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={MailIcon}
            emptyTitle="No email or SMS factors yet."
            skeletonRows={2}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Channel</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((f) => (
                  <TableRow key={f.id}>
                    <TableCell>
                      <span className="flex items-center gap-2">
                        {f.channel === "email" ? (
                          <MailIcon className="size-4 text-muted-foreground" />
                        ) : (
                          <MessageSquareIcon className="size-4 text-muted-foreground" />
                        )}
                        {f.channel === "email" ? "Email" : "SMS"}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{f.destination}</TableCell>
                    <TableCell>
                      <StatusPill kind={f.verified ? "success" : "warning"}>
                        {f.verified ? "Verified" : "Pending"}
                      </StatusPill>
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => challengeM.mutate(f.id)}
                        disabled={!f.verified || challengeM.isPending}
                        title="Send a test code to verify delivery"
                      >
                        <SendIcon /> Send test
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (confirm(`Remove this ${f.channel} factor?`)) deleteM.mutate(f.id);
                        }}
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> Remove
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <AddFactorSheet open={adding} onOpenChange={setAdding} />
    </div>
  );
}

function AddFactorSheet({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const enrollM = useEnrollOtpStart();
  const confirmM = useConfirmOtpFactor();
  const [channel, setChannel] = useState<OtpChannel>("email");
  const [destination, setDestination] = useState("");
  const [factorId, setFactorId] = useState<string | null>(null);
  const [code, setCode] = useState("");

  const reset = () => {
    setChannel("email");
    setDestination("");
    setFactorId(null);
    setCode("");
    enrollM.reset();
    confirmM.reset();
  };

  const close = (o: boolean) => {
    if (!o) reset();
    onOpenChange(o);
  };

  return (
    <Sheet open={open} onOpenChange={close}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <div className="flex h-full flex-col">
          <SheetHeader>
            <SheetTitle>Add an OTP factor</SheetTitle>
            <SheetDescription>
              {factorId
                ? "Enter the code we just sent to confirm you control this destination."
                : "We'll send a one-time code to confirm the destination."}
            </SheetDescription>
          </SheetHeader>

          <div className="flex-1 overflow-y-auto p-4">
            {!factorId ? (
              <form
                id="otp-start"
                onSubmit={(e) => {
                  e.preventDefault();
                  enrollM.mutate(
                    { channel, destination: destination.trim() },
                    { onSuccess: (d) => setFactorId(d.factor_id) },
                  );
                }}
              >
                <FieldGroup>
                  <Field>
                    <FieldLabel>Channel</FieldLabel>
                    <Select value={channel} onValueChange={(v) => setChannel(v as OtpChannel)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="email">Email</SelectItem>
                        <SelectItem value="sms">SMS</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="destination">
                      {channel === "email" ? "Email address" : "Phone number"}
                    </FieldLabel>
                    <Input
                      id="destination"
                      value={destination}
                      onChange={(e) => setDestination(e.target.value)}
                      placeholder={channel === "email" ? "you@example.com" : "+15551234567"}
                      required
                    />
                    <FieldDescription>
                      {channel === "sms" ? "Use E.164 format (+ country code)." : "A code will be emailed here."}
                    </FieldDescription>
                  </Field>
                  {enrollM.error && (
                    <Field>
                      <FieldError>{(enrollM.error as ApiError).message}</FieldError>
                    </Field>
                  )}
                </FieldGroup>
              </form>
            ) : (
              <form
                id="otp-confirm"
                onSubmit={(e) => {
                  e.preventDefault();
                  confirmM.mutate(
                    { id: factorId, code: code.trim() },
                    { onSuccess: () => close(false) },
                  );
                }}
              >
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="code">Verification code</FieldLabel>
                    <Input
                      id="code"
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="123456"
                      className="font-mono tracking-widest"
                      required
                    />
                    <FieldDescription>Sent to {destination}. Expires in 10 minutes.</FieldDescription>
                  </Field>
                  {confirmM.error && (
                    <Field>
                      <FieldError>{(confirmM.error as ApiError).message}</FieldError>
                    </Field>
                  )}
                </FieldGroup>
              </form>
            )}
          </div>

          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            {!factorId ? (
              <Button type="submit" form="otp-start" disabled={enrollM.isPending || !destination.trim()}>
                {enrollM.isPending && <Loader2Icon className="animate-spin" />}
                {enrollM.isPending ? "Sending…" : "Send code"}
              </Button>
            ) : (
              <Button type="submit" form="otp-confirm" disabled={confirmM.isPending || !code.trim()}>
                {confirmM.isPending && <Loader2Icon className="animate-spin" />}
                {confirmM.isPending ? "Confirming…" : "Confirm"}
              </Button>
            )}
          </SheetFooter>
        </div>
      </SheetContent>
    </Sheet>
  );
}
