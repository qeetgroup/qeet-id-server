// Load test of a local Qeet ID server (make load): sign-in, token renewal, signed-in reads and the
// OpenID discovery documents, each at a steady rate below the server's per-address limits, so one
// machine measures latency rather than the rate limiter. The thresholds are the service level
// objectives in observability/README.md; k6 fails the run when one is missed.
import http from "k6/http";
import { check } from "k6";
import { randomBytes } from "k6/crypto";
import exec from "k6/execution";

const base = __ENV.BASE_URL || "http://localhost:4001";
const duration = __ENV.DURATION || "1m";
const people = Number(__ENV.PEOPLE || 4);
const json = { headers: { "Content-Type": "application/json" } };
const hex = (bytes) =>
  Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");

// The public routes (sign-in, renewal) share 5 requests a second per address; the discovery
// documents 50; a signed-in person 30. Requests carry a browser's User-Agent: sign-in scores a
// client that names itself a tool as a bot.
export const options = {
  userAgent:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
  scenarios: {
    sign_in: {
      executor: "constant-arrival-rate",
      rate: 2,
      timeUnit: "1s",
      duration,
      preAllocatedVUs: 4,
      exec: "signIn",
    },
    renew: {
      executor: "constant-arrival-rate",
      rate: 1,
      timeUnit: "1s",
      duration,
      preAllocatedVUs: 2,
      exec: "renew",
    },
    reads: {
      executor: "constant-arrival-rate",
      rate: 20 * people,
      timeUnit: "1s",
      duration,
      preAllocatedVUs: 20,
      exec: "read",
    },
    discovery: {
      executor: "constant-arrival-rate",
      rate: 20,
      timeUnit: "1s",
      duration,
      preAllocatedVUs: 10,
      exec: "discover",
    },
  },
  thresholds: {
    "http_req_duration{name:sign-in}": ["p(99)<500"],
    "http_req_duration{name:renew}": ["p(99)<500"],
    "http_req_duration{name:read}": ["p(95)<200"],
    "http_req_duration{name:discovery}": ["p(95)<100"],
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
};

// setup signs one run's accounts up and returns them with their tokens. Their password is made
// here for the run, so none is written down, and it meets a policy asking for every kind of character.
export function setup() {
  const password = `Lt1-${hex(randomBytes(16))}`;
  const started = Date.now();
  const accounts = Array.from({ length: people }, (_, i) => {
    const email = `load-${started}-${i}@example.test`;
    const res = http.post(
      `${base}/v1/auth/signup`,
      JSON.stringify({ email, password, display_name: "Load Test" }),
      {
        ...json,
        tags: { name: "sign-up" },
      },
    );
    if (res.status !== 201) throw new Error(`sign-up ${res.status}: ${res.body}`);
    return { email, access: res.json("access_token"), refresh: res.json("refresh_token") };
  });
  return { password, accounts };
}

// pick takes the run's accounts in turn, so the load is spread evenly and a run can be repeated.
const pick = (accounts) => accounts[exec.scenario.iterationInTest % accounts.length];

export function signIn({ password, accounts }) {
  const res = http.post(
    `${base}/v1/auth/login`,
    JSON.stringify({ email: pick(accounts).email, password }),
    {
      ...json,
      tags: { name: "sign-in" },
    },
  );
  check(res, { "signed in": (r) => r.status === 200 && r.json("access_token") !== undefined });
}

// renew opens a session and renews it, as an application keeping its person signed in does.
export function renew({ password, accounts }) {
  const session = http.post(
    `${base}/v1/auth/login`,
    JSON.stringify({ email: pick(accounts).email, password }),
    json,
  );
  const res = http.post(
    `${base}/v1/auth/refresh`,
    JSON.stringify({ refresh_token: session.json("refresh_token") }),
    {
      ...json,
      tags: { name: "renew" },
    },
  );
  check(res, { renewed: (r) => r.status === 200 && r.json("refresh_token") !== undefined });
}

export function read({ accounts }) {
  const res = http.get(`${base}/v1/auth/me`, {
    headers: { Authorization: `Bearer ${pick(accounts).access}` },
    tags: { name: "read" },
  });
  check(res, { "read as the person": (r) => r.status === 200 });
}

export function discover() {
  const config = http.get(`${base}/.well-known/openid-configuration`, {
    tags: { name: "discovery" },
  });
  const keys = http.get(`${base}/.well-known/jwks.json`, { tags: { name: "discovery" } });
  check(config, { "discovery document": (r) => r.status === 200 });
  check(keys, { "signing keys": (r) => r.status === 200 && r.json("keys").length > 0 });
}
