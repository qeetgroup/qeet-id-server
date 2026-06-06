// Cross-app links from the marketing site to the dashboard (qeetid-admin), which
// hosts the real /sign-in and /sign-up pages. Marketing only links to them.
// Override the base with NEXT_PUBLIC_DASHBOARD_URL (e.g. http://localhost:3002
// in local dev); defaults to the production dashboard domain.
const DASHBOARD_URL = process.env.NEXT_PUBLIC_DASHBOARD_URL ?? "https://manage.qeet.in";

export const SIGN_IN_URL = `${DASHBOARD_URL}/sign-in`;
export const SIGN_UP_URL = `${DASHBOARD_URL}/sign-up`;
