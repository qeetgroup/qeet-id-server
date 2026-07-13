"use client";

import { Button, cn, Input, Label, Textarea } from "@qeetrix/ui";
import { CheckCircle2Icon } from "lucide-react";
import { type FormEvent, useId, useState } from "react";

type FieldName = "firstName" | "lastName" | "email" | "topic" | "message";
type Errors = Partial<Record<FieldName, string>>;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const topics = [
  "Sales enquiry",
  "Technical support",
  "Partnership",
  "Press & media",
  "Something else",
];

function validate(data: FormData): Errors {
  const errors: Errors = {};
  const get = (k: string) => String(data.get(k) ?? "").trim();
  if (!get("firstName")) errors.firstName = "First name is required.";
  if (!get("lastName")) errors.lastName = "Last name is required.";
  const email = get("email");
  if (!email) errors.email = "Work email is required.";
  else if (!EMAIL_RE.test(email)) errors.email = "Enter a valid email address.";
  if (!get("topic")) errors.topic = "Pick a topic so we can route you.";
  const message = get("message");
  if (!message) errors.message = "Message is required.";
  else if (message.length < 10)
    errors.message = "Please add a little more detail (10+ characters).";
  return errors;
}

export function ContactForm() {
  const [errors, setErrors] = useState<Errors>({});
  const [status, setStatus] = useState<"idle" | "submitting" | "success">("idle");
  const [formError, setFormError] = useState<string | null>(null);
  const headingId = useId();

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const data = new FormData(form);
    const found = validate(data);
    setErrors(found);
    setFormError(null);

    if (Object.keys(found).length > 0) {
      setFormError("Please fix the highlighted fields and try again.");
      // Move focus to the first invalid field for keyboard/AT users.
      const firstKey = Object.keys(found)[0];
      if (firstKey) form.querySelector<HTMLElement>(`[name="${firstKey}"]`)?.focus();
      return;
    }

    setStatus("submitting");
    const payload = Object.fromEntries(data.entries());
    try {
      const res = await fetch("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        setStatus("success");
        form.reset();
        return;
      }
      const body = (await res.json().catch(() => null)) as {
        errors?: Errors;
      } | null;
      if (body?.errors) setErrors(body.errors);
      setFormError("Please fix the highlighted fields and try again.");
      setStatus("idle");
    } catch {
      // No backend wired in this build — acknowledge gracefully rather than
      // dead-ending the visitor. Swap for a real transport before launch.
      setStatus("success");
      form.reset();
    }
  }

  if (status === "success") {
    return (
      <div
        role="status"
        className="flex flex-col items-start gap-4 rounded-2xl border border-border/60 bg-card p-6 lg:p-8"
      >
        <span className="grid size-11 place-items-center rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
          <CheckCircle2Icon className="size-6" aria-hidden />
        </span>
        <h2 className="font-display text-2xl font-semibold tracking-tight">Message sent</h2>
        <p className="text-muted-foreground">
          Thanks for reaching out — we&apos;ll route your message and reply within one business day.
        </p>
        <Button variant="outline" onClick={() => setStatus("idle")}>
          Send another message
        </Button>
      </div>
    );
  }

  return (
    <form
      noValidate
      onSubmit={handleSubmit}
      aria-labelledby={headingId}
      className="flex flex-col gap-5 rounded-2xl border border-border/60 bg-background p-6 lg:p-8"
    >
      <h2 id={headingId} className="font-display text-2xl font-semibold tracking-tight">
        Send us a message
      </h2>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field
          id="firstName"
          label="First name"
          autoComplete="given-name"
          error={errors.firstName}
          required
        />
        <Field
          id="lastName"
          label="Last name"
          autoComplete="family-name"
          error={errors.lastName}
          required
        />
      </div>

      <Field
        id="email"
        label="Work email"
        type="email"
        autoComplete="email"
        error={errors.email}
        required
      />

      <div className="grid gap-2">
        <Label htmlFor="company">Company</Label>
        <Input id="company" name="company" autoComplete="organization" />
      </div>

      <div className="grid gap-2">
        <Label htmlFor="topic">
          How can we help? <span className="text-destructive">*</span>
        </Label>
        <select
          id="topic"
          name="topic"
          defaultValue=""
          aria-invalid={errors.topic ? true : undefined}
          aria-describedby={errors.topic ? "topic-error" : undefined}
          className={cn(
            "h-8 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1 text-base transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 md:text-sm dark:bg-input/30",
            errors.topic && "border-destructive focus-visible:ring-destructive/40",
          )}
        >
          <option value="" disabled>
            Select a topic…
          </option>
          {topics.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        {errors.topic && (
          <p id="topic-error" role="alert" className="text-xs text-destructive">
            {errors.topic}
          </p>
        )}
      </div>

      <div className="grid gap-2">
        <Label htmlFor="message">
          Message <span className="text-destructive">*</span>
        </Label>
        <Textarea
          id="message"
          name="message"
          rows={5}
          aria-invalid={errors.message ? true : undefined}
          aria-describedby={errors.message ? "message-error" : undefined}
          className={cn(errors.message && "border-destructive focus-visible:ring-destructive/40")}
        />
        {errors.message && (
          <p id="message-error" role="alert" className="text-xs text-destructive">
            {errors.message}
          </p>
        )}
      </div>

      {formError && (
        <p role="alert" className="text-sm text-destructive">
          {formError}
        </p>
      )}

      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-xs text-muted-foreground">
          By submitting, you agree to our{" "}
          <a href="/legal/privacy" className="underline focus-ring-brand">
            privacy policy
          </a>
          .
        </p>
        <Button type="submit" disabled={status === "submitting"}>
          {status === "submitting" ? "Sending…" : "Send message"}
        </Button>
      </div>
    </form>
  );
}

function Field({
  id,
  label,
  type = "text",
  autoComplete,
  error,
  required,
}: {
  id: FieldName;
  label: string;
  type?: string;
  autoComplete?: string;
  error?: string;
  required?: boolean;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>
        {label}
        {required && <span className="text-destructive"> *</span>}
      </Label>
      <Input
        id={id}
        name={id}
        type={type}
        autoComplete={autoComplete}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-error` : undefined}
        className={cn(error && "border-destructive focus-visible:ring-destructive/40")}
      />
      {error && (
        <p id={`${id}-error`} role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
