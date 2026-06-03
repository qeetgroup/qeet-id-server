import { LoginForm } from "./login-form";

// Server component: searchParams is async in this Next.js. We await it and hand
// the (already authenticated-against) authorize URL to the client form, which
// posts credentials and then navigates the browser back to it.
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ return_to?: string }>;
}) {
  const { return_to } = await searchParams;
  return <LoginForm returnTo={return_to ?? ""} />;
}
