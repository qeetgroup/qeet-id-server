import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://localhost:4001";

export const options = {
  scenarios: {
    soak: {
      executor: "constant-vus",
      vus: 20,
      duration: "60m",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.001"],
    http_req_duration: ["p(95)<500"],
  },
};

// Seeded via `make seed` (cmd/seed/main.go) — memberRole in Qeet Group (qeet.in).
const CREDS = { email: "sneha@qeet.in", password: "Password123!" };

let accessToken = null;
let refreshToken = null;

function doLogin() {
  const res = http.post(
    `${BASE_URL}/v1/auth/login`,
    JSON.stringify(CREDS),
    { headers: { "Content-Type": "application/json" } },
  );
  if (res.status === 200) {
    const body = JSON.parse(res.body);
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
  }
}

export function setup() {
  doLogin();
}

export default function () {
  if (!accessToken) {
    doLogin();
    sleep(1);
    return;
  }

  const headers = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  };

  // Mix of read operations
  const op = Math.random();
  if (op < 0.5) {
    // Profile read
    const res = http.get(`${BASE_URL}/v1/users/me`, { headers });
    check(res, { "profile 200": (r) => r.status === 200 || r.status === 401 });
    if (res.status === 401) accessToken = null; // will re-login next iteration
  } else {
    // Token refresh
    const res = http.post(
      `${BASE_URL}/v1/auth/refresh`,
      JSON.stringify({ refresh_token: refreshToken }),
      { headers: { "Content-Type": "application/json" } },
    );
    if (res.status === 200) {
      const body = JSON.parse(res.body);
      accessToken = body.access_token;
      refreshToken = body.refresh_token;
    }
  }

  sleep(3);
}
