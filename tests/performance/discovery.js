import { check } from "k6";
import http from "k6/http";

// Latency benchmark for the public, unauthenticated OIDC discovery + JWKS
// endpoints that every relying party hits on startup and key rotation. These
// live outside the rate-limited /v1 groups, so this measures pure latency.
// SLO (PRD §8): JWKS/discovery p95 < 20 ms.
const BASE_URL = __ENV.BASE_URL || "http://localhost:4001";

export const options = {
  scenarios: {
    steady: { executor: "constant-vus", vus: 20, duration: "30s" },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_req_duration{endpoint:discovery}": ["p(95)<20"],
    "http_req_duration{endpoint:jwks}": ["p(95)<20"],
  },
};

export default function () {
  const disc = http.get(`${BASE_URL}/.well-known/openid-configuration`, {
    tags: { endpoint: "discovery" },
  });
  check(disc, {
    "discovery 200": (r) => r.status === 200,
    "discovery has issuer": (r) => {
      try {
        return !!JSON.parse(r.body).issuer;
      } catch {
        return false;
      }
    },
  });

  const jwks = http.get(`${BASE_URL}/.well-known/jwks.json`, {
    tags: { endpoint: "jwks" },
  });
  check(jwks, {
    "jwks 200": (r) => r.status === 200,
    "jwks has keys": (r) => {
      try {
        return (JSON.parse(r.body).keys || []).length > 0;
      } catch {
        return false;
      }
    },
  });
}
