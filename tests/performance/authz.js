import { check, sleep } from "k6";
import http from "k6/http";

const BASE_URL = __ENV.BASE_URL || "http://localhost:4001";

export const options = {
  scenarios: {
    ramp: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: 30 },
        { duration: "1m", target: 30 },
        { duration: "30s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<200"],
  },
};

// Seeded via `make seed` (cmd/seed/main.go): rohan@qeet.in is engineerRole in
// Qeet Group (qeet.in tenant) and a member of group:engineering, which the
// seed data's ReBAC tuples grant "viewer" on document:security-runbook via
// the group#member userset — so the ReBAC check below exercises a real
// recursive resolution, not a trivial direct grant.
const CREDS = { email: "rohan@qeet.in", password: "Password123!" };

export function setup() {
  const res = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify(CREDS), {
    headers: { "Content-Type": "application/json" },
  });
  if (res.status !== 200) {
    throw new Error(`setup login failed: ${res.status} ${res.body}`);
  }
  const body = JSON.parse(res.body);
  return {
    accessToken: body.access_token,
    userId: body.user_id,
    tenantId: body.tenant_id,
  };
}

export default function (data) {
  const headers = { Authorization: `Bearer ${data.accessToken}` };

  // RBAC: role-permission check.
  const rbacRes = http.get(
    `${BASE_URL}/v1/check?user_id=${data.userId}&tenant_id=${data.tenantId}&permission=role.read`,
    { headers },
  );
  check(rbacRes, {
    "rbac check 200": (r) => r.status === 200,
    "rbac allowed": (r) => {
      try {
        return JSON.parse(r.body).allowed === true;
      } catch {
        return false;
      }
    },
  });

  sleep(0.2);

  // ReBAC: recursive group-membership resolution (user -> group#member -> document viewer).
  const rebacRes = http.post(
    `${BASE_URL}/v1/tenants/${data.tenantId}/relation-tuples/check`,
    JSON.stringify({
      object: "document:security-runbook",
      relation: "viewer",
      user_id: `user:${data.userId}`,
    }),
    { headers: { ...headers, "Content-Type": "application/json" } },
  );
  check(rebacRes, {
    "rebac check 200": (r) => r.status === 200,
    "rebac allowed": (r) => {
      try {
        return JSON.parse(r.body).allowed === true;
      } catch {
        return false;
      }
    },
  });

  sleep(0.5);
}
