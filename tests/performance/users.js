import { check, sleep } from "k6";
import http from "k6/http";

const BASE_URL = __ENV.BASE_URL || "http://localhost:4001";
const API_KEY = __ENV.API_KEY || ""; // set via: k6 run -e API_KEY=sk_...

export const options = {
  scenarios: {
    ramp: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: 20 },
        { duration: "1m", target: 20 },
        { duration: "30s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<200"],
  },
};

export default function () {
  const headers = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
  };

  // List users
  const listRes = http.get(`${BASE_URL}/v1/users?limit=20`, { headers });
  check(listRes, {
    "list users 200": (r) => r.status === 200,
    "has items array": (r) => {
      try {
        return Array.isArray(JSON.parse(r.body).items);
      } catch {
        return false;
      }
    },
  });

  sleep(0.5);

  // Get user by ID (use first item from list)
  try {
    const users = JSON.parse(listRes.body).items;
    if (users && users.length > 0) {
      const getRes = http.get(`${BASE_URL}/v1/users/${users[0].id}`, {
        headers,
      });
      check(getRes, { "get user 200": (r) => r.status === 200 });
    }
  } catch {
    // ignore parse errors from rate-limited responses
  }

  sleep(1);
}
