import type { NextRequest } from "next/server";

interface ContactPayload {
  firstName?: string;
  lastName?: string;
  email?: string;
  company?: string;
  topic?: string;
  message?: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function POST(request: NextRequest) {
  let body: ContactPayload;
  try {
    body = (await request.json()) as ContactPayload;
  } catch {
    return Response.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }

  const errors: Record<string, string> = {};
  if (!body.firstName?.trim()) errors.firstName = "First name is required.";
  if (!body.lastName?.trim()) errors.lastName = "Last name is required.";
  if (!body.email?.trim()) errors.email = "Work email is required.";
  else if (!EMAIL_RE.test(body.email.trim())) errors.email = "Enter a valid email address.";
  if (!body.message?.trim()) errors.message = "Message is required.";

  if (Object.keys(errors).length > 0) {
    return Response.json({ ok: false, errors }, { status: 422 });
  }

  // No mail backend wired up yet — accept and acknowledge. Swap this
  // for a real transport (Resend, queue, CRM) before launch.
  return Response.json({ ok: true });
}
