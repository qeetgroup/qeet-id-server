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
  Switch,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { MailIcon, SmartphoneIcon, SparklesIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/login-methods/passwordless")({
  component: PasswordlessPage,
});

function PasswordlessPage() {
  const [email, setEmail] = useState(true);
  const [sms, setSms] = useState(false);
  const [magicLink, setMagicLink] = useState(true);
  const [ttl, setTtl] = useState("10m");

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Configure OTP- and link-based passwordless flows." />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <MailIcon className="size-4" />
              Email OTP
            </CardTitle>
            <CardDescription>One-time codes delivered by email.</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <Badge variant={email ? "default" : "outline"}>{email ? "enabled" : "off"}</Badge>
            <Switch checked={email} onCheckedChange={setEmail} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <SmartphoneIcon className="size-4" />
              SMS OTP
            </CardTitle>
            <CardDescription>One-time codes via Twilio.</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <Badge variant={sms ? "default" : "outline"}>{sms ? "enabled" : "off"}</Badge>
            <Switch checked={sms} onCheckedChange={setSms} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <SparklesIcon className="size-4" />
              Magic links
            </CardTitle>
            <CardDescription>Single-use URLs that complete login.</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <Badge variant={magicLink ? "default" : "outline"}>{magicLink ? "enabled" : "off"}</Badge>
            <Switch checked={magicLink} onCheckedChange={setMagicLink} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Common settings</CardTitle>
          <CardDescription>Applied to all enabled passwordless factors.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>Code / link TTL</FieldLabel>
            <Select value={ttl} onValueChange={(v) => v && setTtl(v)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="5m">5 minutes</SelectItem>
                <SelectItem value="10m">10 minutes</SelectItem>
                <SelectItem value="15m">15 minutes</SelectItem>
                <SelectItem value="1h">1 hour</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>Tokens older than this are rejected automatically.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>Code length</FieldLabel>
            <Select defaultValue="6">
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="6">6 digits</SelectItem>
                <SelectItem value="8">8 digits</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>Only applies to email and SMS OTP.</FieldDescription>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Single-use only</FieldLabel>
                <FieldDescription>Codes and links are invalidated on first use.</FieldDescription>
              </div>
              <Switch defaultChecked />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Auto-verify email on first use</FieldLabel>
                <FieldDescription>Mark the user's email as verified once they complete OTP.</FieldDescription>
              </div>
              <Switch defaultChecked />
            </div>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Delivery providers</CardTitle>
          <CardDescription>Where OTPs and links are sent from.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <div className="flex items-center justify-between rounded-md border px-3 py-2">
            <div className="flex items-center gap-2">
              <MailIcon className="size-4 text-muted-foreground" />
              <span className="text-sm font-medium">SendGrid</span>
            </div>
            <Badge variant="outline">primary · email</Badge>
          </div>
          <div className="flex items-center justify-between rounded-md border px-3 py-2">
            <div className="flex items-center gap-2">
              <MailIcon className="size-4 text-muted-foreground" />
              <span className="text-sm font-medium">AWS SES</span>
            </div>
            <Badge variant="outline">failover · email</Badge>
          </div>
          <div className="flex items-center justify-between rounded-md border px-3 py-2">
            <div className="flex items-center gap-2">
              <SmartphoneIcon className="size-4 text-muted-foreground" />
              <span className="text-sm font-medium">Twilio</span>
            </div>
            <Badge variant="outline">primary · sms</Badge>
          </div>
          <div className="flex items-center justify-between rounded-md border px-3 py-2">
            <div className="flex items-center gap-2">
              <SmartphoneIcon className="size-4 text-muted-foreground" />
              <span className="text-sm font-medium">AWS SNS</span>
            </div>
            <Badge variant="outline">failover · sms</Badge>
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
