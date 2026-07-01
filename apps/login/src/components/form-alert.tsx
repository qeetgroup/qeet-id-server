"use client";

import { Alert, AlertDescription } from "@qeetrix/ui";
import type { ReactNode } from "react";

/**
 * Inline error banner for auth forms. Renders nothing when there's no message,
 * so callers can pass a nullable error straight through. Uses the design
 * system's `danger` alert variant for consistent error styling.
 */
export function FormAlert({ children }: { children?: ReactNode }) {
  if (!children) return null;
  return (
    <Alert variant="danger" role="alert">
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  );
}
