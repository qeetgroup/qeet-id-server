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
import { MailIcon, MessageSquareIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/mfa/sms-email")({ component: SmsEmailPage });

function SmsEmailPage() {
  const [emailEnabled, setEmailEnabled] = useState(true);
  const [smsEnabled, setSmsEnabled] = useState(false);
  const [codeLen, setCodeLen] = useState(6);
  const [ttl, setTtl] = useState("10m");
  const [perPhoneCap, setPerPhoneCap] = useState(5);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="OTP delivery via email or SMS as a second factor or step-up challenge." />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <MailIcon className="size-4" />
              Email OTP
            </CardTitle>
            <CardDescription>SendGrid · 14,210 users enrolled</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <Badge variant={emailEnabled ? "default" : "outline"}>{emailEnabled ? "enabled" : "off"}</Badge>
            <Switch checked={emailEnabled} onCheckedChange={setEmailEnabled} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <MessageSquareIcon className="size-4" />
              SMS OTP
            </CardTitle>
            <CardDescription>Twilio · 6,302 users enrolled</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between space-y-1">
            <div>
              <Badge variant={smsEnabled ? "default" : "outline"}>{smsEnabled ? "enabled" : "off"}</Badge>
              <p className="mt-1 text-xs text-muted-foreground">
                NIST SP 800-63B classifies SMS as AAL2 restricted.
              </p>
            </div>
            <Switch checked={smsEnabled} onCheckedChange={setSmsEnabled} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Code parameters</CardTitle>
          <CardDescription>Applied to both email and SMS OTPs.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>Code length: {codeLen} digits</FieldLabel>
            <Slider
              value={[codeLen]}
              onValueChange={(v) => setCodeLen(Array.isArray(v) ? (v[0] ?? 6) : v)}
              min={4}
              max={10}
              step={2}
            />
            <FieldDescription>Even-length codes only; longer = better entropy.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>TTL</FieldLabel>
            <Select value={ttl} onValueChange={(v) => v && setTtl(v)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="5m">5 minutes</SelectItem>
                <SelectItem value="10m">10 minutes</SelectItem>
                <SelectItem value="15m">15 minutes</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel>Per-phone request cap: {perPhoneCap} / hour</FieldLabel>
            <Slider
              value={[perPhoneCap]}
              onValueChange={(v) => setPerPhoneCap(Array.isArray(v) ? (v[0] ?? 5) : v)}
              min={1}
              max={20}
              step={1}
            />
            <FieldDescription>Mitigates SMS-pumping abuse against premium-rate numbers.</FieldDescription>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Allow recovery codes as fallback</FieldLabel>
                <FieldDescription>Users can use a single-use recovery code if OTP delivery fails.</FieldDescription>
              </div>
              <Switch defaultChecked />
            </div>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Step-up policy</CardTitle>
          <CardDescription>Force a fresh OTP challenge for sensitive operations.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <div className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
            <span>Change password</span>
            <Switch defaultChecked />
          </div>
          <div className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
            <span>Add or remove MFA factor</span>
            <Switch defaultChecked />
          </div>
          <div className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
            <span>Generate / rotate API key</span>
            <Switch defaultChecked />
          </div>
          <div className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
            <span>Delete account</span>
            <Switch defaultChecked />
          </div>
          <div className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
            <span>Connect new device</span>
            <Switch />
          </div>
          <div className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
            <span>Privileged admin action</span>
            <Switch defaultChecked />
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="outline">Discard</Button>
        <Button>Save changes</Button>
      </div>
    </div>
  );
}
