import { handleAuth } from "@qeetid/nextjs";

// Serves /api/auth/login, /api/auth/callback, and /api/auth/logout.
export const GET = handleAuth();
