"use client";

import Link from "next/link";

import { SignedIn, SignedOut, SignInWithQeet, UserButton } from "@qeetid/react";

export default function Home() {
  return (
    <main className="container">
      <h1>Qeet ID — Example App</h1>
      <p className="muted">
        A minimal Next.js app that authenticates users with Qeet ID using{" "}
        <code>@qeetid/nextjs</code> + <code>@qeetid/react</code>.
      </p>

      <SignedOut>
        <p>You are signed out. Click below to sign in with Qeet.</p>
        <div className="btn-wrap">
          <SignInWithQeet/>
        </div>
      </SignedOut>

      <SignedIn>
        <p>You are signed in. 🎉</p>
        <div className="row">
          <Link href="/dashboard" className="link-btn">
            Go to dashboard →
          </Link>
          <UserButton />
        </div>
      </SignedIn>
    </main>
  );
}
