import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Field,
  FieldDescription,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { BotIcon, PlayIcon, PlusIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/developer/bots")({ component: BotsPage });

type Automation = {
  id: string;
  name: string;
  trigger: string;
  action: string;
  enabled: boolean;
  lastRun: string;
  successRate: number;
};

const seed: Automation[] = [
  {
    id: "1",
    name: "Suspend users from blocked countries",
    trigger: "user.created",
    action: "user.suspend",
    enabled: true,
    lastRun: "14m ago",
    successRate: 100,
  },
  {
    id: "2",
    name: "Notify Slack on new admin",
    trigger: "role.assigned",
    action: "slack.post",
    enabled: true,
    lastRun: "2h ago",
    successRate: 98.3,
  },
  {
    id: "3",
    name: "Auto-revoke stale API keys",
    trigger: "schedule.daily",
    action: "apikey.revoke",
    enabled: true,
    lastRun: "yesterday",
    successRate: 100,
  },
  {
    id: "4",
    name: "Welcome email for verified users",
    trigger: "user.email_verified",
    action: "email.send",
    enabled: false,
    lastRun: "—",
    successRate: 0,
  },
];

function BotsPage() {
  const [open, setOpen] = useState(false);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Event-driven automations stitched together from triggers and actions. No code required."
        actions={
          <Button onClick={() => setOpen(true)}>
            <PlusIcon className="mr-2 size-4" />
            New automation
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Active automations</CardDescription>
            <BotIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {seed.filter((a) => a.enabled).length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Runs (24h)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">3,420</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Avg. success rate</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">99.4%</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Automations</CardTitle>
          <CardDescription>Triggered by platform events or schedules.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Trigger</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Last run</TableHead>
                <TableHead>Success</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {seed.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="font-medium">{a.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {a.trigger}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {a.action}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{a.lastRun}</TableCell>
                  <TableCell className="text-sm">{a.successRate ? `${a.successRate}%` : "—"}</TableCell>
                  <TableCell>
                    {a.enabled ? <Badge>enabled</Badge> : <Badge variant="outline">disabled</Badge>}
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="ghost">
                        <PlayIcon className="size-3" />
                      </Button>
                      <Button size="sm" variant="ghost">
                        Edit
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="sm:max-w-md">
          <SheetHeader>
            <SheetTitle>New automation</SheetTitle>
            <SheetDescription>Pick a trigger and an action. Add filters in the next step.</SheetDescription>
          </SheetHeader>
          <div className="mt-4 grid gap-4">
            <Field>
              <FieldLabel>Name</FieldLabel>
              <Input placeholder="Notify on new admin role" />
            </Field>
            <Field>
              <FieldLabel>Trigger</FieldLabel>
              <Select>
                <SelectTrigger>
                  <SelectValue placeholder="Select trigger…" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user.created">user.created</SelectItem>
                  <SelectItem value="user.email_verified">user.email_verified</SelectItem>
                  <SelectItem value="user.suspended">user.suspended</SelectItem>
                  <SelectItem value="role.assigned">role.assigned</SelectItem>
                  <SelectItem value="session.revoked">session.revoked</SelectItem>
                  <SelectItem value="schedule.hourly">schedule.hourly</SelectItem>
                  <SelectItem value="schedule.daily">schedule.daily</SelectItem>
                </SelectContent>
              </Select>
              <FieldDescription>Events come from the same outbox that powers webhooks.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel>Action</FieldLabel>
              <Select>
                <SelectTrigger>
                  <SelectValue placeholder="Select action…" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="email.send">email.send</SelectItem>
                  <SelectItem value="slack.post">slack.post</SelectItem>
                  <SelectItem value="user.suspend">user.suspend</SelectItem>
                  <SelectItem value="apikey.revoke">apikey.revoke</SelectItem>
                  <SelectItem value="webhook.fire">webhook.fire</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </div>
          <SheetFooter className="mt-6 flex justify-end gap-2">
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button>Continue</Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
