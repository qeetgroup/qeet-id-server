import type { ReactNode } from "react";

import { auth, currentUser } from "@qeetid/nextjs";
import { QeetidProvider } from "@qeetid/react";

import "./globals.css";

export const metadata = {
  title: "Qeet ID — Example App",
  description: "Example Next.js app authenticating with Qeet ID.",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Compute auth state on the server so the client renders correctly on first
  // paint (without reading the HttpOnly session cookie in the browser).
  const { isAuthenticated, userId, tenantId, sessionId } = await auth();
  const info = isAuthenticated ? await currentUser() : null;
  const user = info
    ? {
        sub: info.sub,
        email: typeof info.email === "string" ? info.email : undefined,
        displayName: typeof info.name === "string" ? info.name : undefined,
        tenantId: info.tenant_id,
      }
    : null;

  return (
    <html lang="en">
      <body>
        {/* signUpUrl points at login because @qeetid/nextjs doesn't mount a
            dedicated sign-up route; the hosted login handles new accounts. */}
        <QeetidProvider
          initialState={{ isAuthenticated, userId, tenantId, sessionId, user }}
          signUpUrl="/api/auth/login"
        >
          {children}
        </QeetidProvider>
      </body>
    </html>
  );
}
