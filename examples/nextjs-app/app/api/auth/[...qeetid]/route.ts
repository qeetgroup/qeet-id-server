import { handleAuth } from "@qeet-id/nextjs";

// Serves /api/auth/login, /api/auth/callback, and /api/auth/logout.
export const GET = handleAuth();
