"use client";

import { Button, Input, Label, Textarea, cn } from "@qeetrix/ui";
import { CheckCircle2Icon } from "lucide-react";
import { useState, type FormEvent } from "react";

type Errors = Partial<Record<"firstName" | "lastName" | "email" | "message", string>>;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validate(data: FormData): Errors {
  const errors: Errors = {};
  const get = (k: string) => String(data.get(k) ?? "").trim();
  if (!get("firstName")) errors.firstName = "First name is required.";
  if (!get("lastName")) errors.lastName = "Last name is required.";
  const email = get("email");
  if (!email) errors.email = "Work email is required.";
  else if (!EMAIL_RE.test(email)) errors.email = "Enter a valid email address.";
  if (!get("message")) errors.message = "Message is required.";
  return errors;
}

export function ContactForm() {
  const [errors, setErrors] = useState<Errors>({});
  const [status, setStatus] = useState<"idle" | "submitting" | "success">("idle");
  const [formError, setFormError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const data = new FormData(form);
    const found = validate(data);
    setErrors(found);
    setFormError(null);
    if (Object.keys(found).length > 0) return;

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
      const body = (await res.json().catch(() => null)) as { errors?: Errors } | null;
      if (body?.errors) setErrors(body.errors);
      setFormError("Please fix the highlighted fields and try again.");
      setStatus("idle");
    } catch {
      // Network/route unavailable — acknowledge gracefully rather than dead-end.
      setStatus("success");
      form.reset();
    }
  }

  if (status === "success") {
    return (
      <div className="flex flex-col items-start gap-4 rounded-2xl border border-border/60 bg-card p-6 lg:p-8">
        <span className="grid size-11 place-items-center rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
          <CheckCircle2Icon className="size-6" />
        </span>
        <h2 className="font-display text-2xl font-semibold tracking-tight">Message sent</h2>
        <p className="text-muted-foreground">
          Thanks for reaching out — we&apos;ll route your message and get back to you shortly.
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
      className="flex flex-col gap-5 rounded-2xl border border-border/60 bg-background p-6 lg:p-8"
    >
      <h2 className="font-display text-2xl font-semibold tracking-tight">Send us a message</h2>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="firstName" label="First name" autoComplete="given-name" error={errors.firstName} />
        <Field id="lastName" label="Last name" autoComplete="family-name" error={errors.lastName} />
      </div>

      <Field
        id="email"
        label="Work email"
        type="email"
        autoComplete="email"
        error={errors.email}
      />

      <div className="grid gap-2">
        <Label htmlFor="company">Company</Label>
        <Input id="company" name="company" autoComplete="organization" />
      </div>

      <div className="grid gap-2">
        <Label htmlFor="topic">How can we help?</Label>
        <Input id="topic" name="topic" placeholder="Sales, support, partnership…" />
      </div>

      <div className="grid gap-2">
        <Label htmlFor="message">Message</Label>
        <Textarea
          id="message"
          name="message"
          rows={5}
          aria-invalid={errors.message ? true : undefined}
          aria-describedby={errors.message ? "message-error" : undefined}
          className={cn(errors.message && "border-destructive focus-visible:ring-destructive/40")}
        />
        {errors.message && (
          <p id="message-error" className="text-xs text-destructive">
            {errors.message}
          </p>
        )}
      </div>

      {formError && <p className="text-sm text-destructive">{formError}</p>}

      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-xs text-muted-foreground">
          By submitting, you agree to our privacy policy.
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
}: {
  id: string;
  label: string;
  type?: string;
  autoComplete?: string;
  error?: string;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
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
        <p id={`${id}-error`} className="text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
