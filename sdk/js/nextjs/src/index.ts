// Node-runtime entry (route handlers, Server Components, Server Actions).
// The middleware lives at "@qeet-id/nextjs/middleware" so the Edge bundle never
// pulls in Node-only code.
export { handleAuth } from "./handlers.js";
export { auth, currentUser, getToken, protect, getAuth, type CurrentUser } from "./server.js";
export { Protect, type ProtectProps } from "./protect.js";
export { getConfig, callbackUrl, type QeetIDConfig } from "./config.js";
export type { SessionData, AuthState } from "./types.js";
