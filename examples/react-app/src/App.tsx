import { useEffect, useRef, useState, type ReactNode } from "react";

import { QeetidProvider, SignedIn, SignedOut, SignInWithQeet, UserButton } from "@qeetid/react";

import {
  fetchUserInfo,
  getStoredToken,
  handleCallback,
  login,
  logout,
  type StoredToken,
  type UserInfo,
} from "./qeet";

// A tiny path switch instead of a router dependency — the OAuth redirects all
// arrive as full-page navigations, which Vite's SPA fallback serves as index.html.
export function App() {
  const path = window.location.pathname;
  if (path === "/login") return <LoginRedirect />;
  if (path === "/logout") return <LogoutRedirect />;
  if (path === "/callback") return <Callback />;
  return <Home />;
}

function LoginRedirect() {
  useEffect(() => {
    const returnTo = new URLSearchParams(window.location.search).get("return_to") ?? "/";
    void login(returnTo);
  }, []);
  return <Centered>Redirecting to Qeet…</Centered>;
}

function LogoutRedirect() {
  useEffect(() => {
    logout();
  }, []);
  return <Centered>Signing out…</Centered>;
}

function Callback() {
  const [error, setError] = useState<string | null>(null);
  const ran = useRef(false);
  useEffect(() => {
    if (ran.current) return; // the auth code is single-use; guard against StrictMode's double-invoke
    ran.current = true;
    handleCallback()
      .then((returnTo) => window.location.replace(returnTo))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  if (error) {
    return (
      <Centered>
        <p>Sign-in failed: {error}</p>
        <a href="/" className="link-btn">
          Back home
        </a>
      </Centered>
    );
  }
  return <Centered>Completing sign-in…</Centered>;
}

type HomeState =
  | { status: "loading" }
  | { status: "ready"; token: StoredToken | null; user: UserInfo | null };

function Home() {
  const [state, setState] = useState<HomeState>({ status: "loading" });

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setState({ status: "ready", token: null, user: null });
      return;
    }
    void fetchUserInfo(token.accessToken).then((user) =>
      setState({ status: "ready", token, user }),
    );
  }, []);

  if (state.status === "loading") return <Centered>Loading…</Centered>;

  const { token, user } = state;
  const isAuthenticated = Boolean(token && user);

  return (
    <QeetidProvider
      initialState={{
        isAuthenticated,
        userId: user?.sub,
        tenantId: typeof user?.tenant_id === "string" ? user.tenant_id : undefined,
        user: user
          ? {
              sub: user.sub,
              email: typeof user.email === "string" ? user.email : undefined,
              displayName: typeof user.name === "string" ? user.name : undefined,
            }
          : null,
      }}
      loginUrl="/login"
      logoutUrl="/logout"
      signUpUrl="/login"
    >
      <main className="container">
        <h1>Qeet ID — React SPA Example</h1>
        <p className="muted">
          A Vite single-page app that signs in with Qeet ID using a client-side OAuth2 + PKCE flow
          (public client) and <code>@qeetid/react</code> components.
        </p>

        <SignedOut>
          <p>You are signed out. Click below to sign in with Qeet.</p>
          <div className="btn-wrap">
            <SignInWithQeet />
          </div>
        </SignedOut>

        <SignedIn>
          <div className="row">
            <p style={{ margin: 0 }}>You are signed in. 🎉</p>
            <UserButton />
          </div>

          <h2>Your profile (OIDC userinfo)</h2>
          <pre className="code">{JSON.stringify(user, null, 2)}</pre>

          <h2>Access token</h2>
          <p className="muted">Dev only — copy this bearer token to test an API example.</p>
          <pre className="code token">{token?.accessToken}</pre>
        </SignedIn>
      </main>
    </QeetidProvider>
  );
}

function Centered({ children }: { children: ReactNode }) {
  return <main className="container center">{children}</main>;
}
