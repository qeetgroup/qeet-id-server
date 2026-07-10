import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL || "http://localhost:4001";

const loginErrors = new Rate("login_errors");
const refreshLatency = new Trend("refresh_latency");

export const options = {
  scenarios: {
    constant_load: {
      executor: "constant-vus",
      vus: 50,
      duration: "2m",
    },
    ramp: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: 50 },
        { duration: "1m", target: 50 },
        { duration: "30s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<300"],
    login_errors: ["rate<0.01"],
  },
};

// Seeded via `make seed` (cmd/seed/main.go) — Qeet Group (qeet.in) leadership
// accounts: sneha is memberRole (read-only), aarav is adminRole.
const CREDENTIALS = [
  { email: "sneha@qeet.in", password: "Password123!" },
  { email: "aarav@qeet.in", password: "Password123!" },
];

export default function () {
  const creds = CREDENTIALS[Math.floor(Math.random() * CREDENTIALS.length)];

  // Login
  const loginRes = http.post(
    `${BASE_URL}/v1/auth/login`,
    JSON.stringify({ email: creds.email, password: creds.password }),
    { headers: { "Content-Type": "application/json" } },
  );

  const loginOk = check(loginRes, {
    "login 200": (r) => r.status === 200,
    "has access_token": (r) => {
      try {
        return JSON.parse(r.body).access_token !== undefined;
      } catch {
        return false;
      }
    },
  });
  loginErrors.add(!loginOk);

  if (!loginOk) {
    sleep(1);
    return;
  }

  const tokens = JSON.parse(loginRes.body);

  sleep(0.5);

  // Token refresh
  const start = Date.now();
  const refreshRes = http.post(
    `${BASE_URL}/v1/auth/refresh`,
    JSON.stringify({ refresh_token: tokens.refresh_token }),
    { headers: { "Content-Type": "application/json" } },
  );
  refreshLatency.add(Date.now() - start);

  check(refreshRes, {
    "refresh 200": (r) => r.status === 200,
  });

  sleep(1);
}
