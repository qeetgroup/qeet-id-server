// Builds the Postman collection in api/postman from the five API documents in api/openapi, plus a
// local environment. Run make postman (or make openapi) from the repository root: devtool calls this
// with the output folder. The output is deterministic, so make openapi-check can compare it.
//
// The converter fakes example values from Math.random and the clock, and gives items random ids:
// the first two are fixed here, the ids derived from each item's place. Auth comes from each operation's own
// security in the document, which the converter reduces to one bearer token.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import * as prettier from "prettier";

const docs = ["auth", "management", "federation", "developer", "operations"];
const localURL = "http://localhost:4001";
const repoRoot = resolve(import.meta.dirname, "..", "..", "..");

// Seeded before the converter loads: its faker keeps a reference to Math.random, and fakes dates
// from the current time, which is fixed here too.
let rng = seeded(1);
Math.random = () => rng();
const fixedNow = Date.UTC(2026, 0, 1);
globalThis.Date = class extends Date {
  constructor(...args) {
    super(...(args.length ? args : [fixedNow]));
  }

  static now() {
    return fixedNow;
  }
};
const Converter = createRequire(import.meta.url)("openapi-to-postmanv2");

function seeded(a) {
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function convert(data) {
  return new Promise((resolve, reject) =>
    Converter.convertV2(
      { type: "string", data },
      { folderStrategy: "Tags", parametersResolution: "Example", enableOptionalParameters: false },
      (err, status) => {
        if (err) return reject(err);
        if (!status.result) return reject(new Error(status.reason));
        resolve(status.output[0].data);
      },
    ),
  );
}

// stableID is a UUID-shaped id derived from where the item sits, so it never changes between builds.
function stableID(seed) {
  const h = createHash("sha256").update(seed).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

// write saves value as JSON formatted by the repository's Prettier settings, wherever out is.
async function write(name, value) {
  const config = await prettier.resolveConfig(join(repoRoot, "api", "postman", name), {
    editorconfig: true,
  });
  writeFileSync(
    join(out, name),
    await prettier.format(JSON.stringify(value), { ...config, filepath: name }),
  );
}

const kv = (pairs) => Object.entries(pairs).map(([key, value]) => ({ key, value, type: "string" }));

// authFor maps an operation's first security requirement to Postman auth. Cookie sessions (the
// hosted-login and admin-portal cookies) need none: Postman's cookie jar sends what sign-in set.
function authFor(security, schemes) {
  const name = Object.keys(security?.[0] ?? {})[0];
  const scheme = schemes[name];
  if (!scheme || scheme.in === "cookie") return { type: "noauth" };
  if (name === "apiKeyAuth")
    return {
      type: "apikey",
      apikey: kv({ key: "Authorization", value: "ApiKey {{apiKey}}", in: "header" }),
    };
  if (scheme.type === "oauth2") {
    return {
      type: "oauth2",
      oauth2: kv({
        grant_type: "client_credentials",
        accessTokenUrl: `{{baseUrl}}${scheme.flows.clientCredentials.tokenUrl}`,
        clientId: "{{oauthClientId}}",
        clientSecret: "{{oauthClientSecret}}",
        client_authentication: "header",
        tokenName: "qeet-id",
        addTokenTo: "header",
      }),
    };
  }
  const variable =
    { scimBearer: "scimToken", adminPortalLink: "adminPortalLink" }[name] ?? "bearerToken";
  return { type: "bearer", bearer: kv({ token: `{{${variable}}}` }) };
}

// pathVariable is the environment variable a path parameter reads. A bare {id} is named after its
// resource so different resources don't share one: /v1/api-keys/{id} reads apiKeyID.
function pathVariable(template, key) {
  if (key !== "id") return key;
  const segment = template.match(/\/([^/{}]+)\/\{id\}/)[1];
  const singular = segment.replace(/ies$/, "y").replace(/([^s])s$/, (m, c, i) => (i > 1 ? c : m));
  const camel = singular.toLowerCase().replace(/-(.)/g, (_, c) => c.toUpperCase());
  return camel + "ID";
}

// savedVariables names what a call's answer should fill in the environment, from its documented
// success example: a session's tokens and person (bearerToken, refreshToken, userID), and a create's
// id as the path parameter of the created resource (POST /v1/organizations fills organizationID).
function savedVariables(spec, template, method, responses) {
  let example;
  try {
    example = JSON.parse(responses[0]?.body ?? "");
  } catch {
    return [];
  }
  const saves = [];
  // Every answer with an access token is a session but the OAuth token endpoint's (an application's)
  // and the token vault's (another provider's).
  if (example?.access_token && !/^\/v1\/(oauth|vault)\//.test(template)) {
    saves.push(["bearerToken", "access_token"]);
    if (example.refresh_token) saves.push(["refreshToken", "refresh_token"]);
    if (example.user_id) saves.push(["userID", "user_id"]);
    else if (example.user?.id) saves.push(["userID", "user?.id"]);
  }
  const child = Object.keys(spec.paths)
    .map((p) => p.match(/^(.*)\/\{([^}]+)\}$/))
    .find((m) => m?.[1] === template);
  if (method !== "POST" || !child || !(child[2] === "id" || child[2].endsWith("ID"))) return saves;
  // The new id is at the top, or in the object named for the resource ({"organization": {"id"}}).
  const variable = pathVariable(child[0], child[2]);
  const wrapper = variable.slice(0, -2).replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
  const field = example?.id ? "id" : example?.[wrapper]?.id ? `${wrapper}?.id` : "";
  if (field) saves.push([variable, field]);
  return saves;
}

// afterResponse is the test script that copies those fields of a successful answer into the environment.
const afterResponse = (saves) => [
  "if (pm.response.code >= 200 && pm.response.code < 300) {",
  "  const body = pm.response.json();",
  ...saves.map(
    ([variable, field]) => `  if (body.${field}) pm.environment.set('${variable}', body.${field});`,
  ),
  "}",
];

// linkFields points the request fields that name a known id (organization_id, role_id) or the
// refresh token at their environment variables, so one call feeds the next: the documents' example
// ids never exist on your server.
function linkFields(req, known) {
  const linked = (key) => {
    if (key === "refresh_token") return "refreshToken";
    const stem = key.match(/^([a-z]+(?:_[a-z]+)*)_id$/)?.[1];
    const name = stem ? stem.replace(/_(.)/g, (_, c) => c.toUpperCase()) + "ID" : "";
    return known.has(name) ? name : "";
  };
  for (const q of req.url.query ?? []) {
    if (linked(q.key)) q.value = `{{${linked(q.key)}}}`;
  }
  let body;
  try {
    body = req.body?.mode === "raw" ? JSON.parse(req.body.raw) : null;
  } catch {
    return;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return;
  const fields = Object.keys(body).filter((k) => linked(k) && typeof body[k] === "string");
  for (const k of fields) body[k] = `{{${linked(k)}}}`;
  if (fields.length) req.body.raw = JSON.stringify(body, null, 2);
}

const requests = (items, out = []) => {
  for (const item of items) item.item ? requests(item.item, out) : out.push(item);
  return out;
};

// stabilize replaces every generated id, walking in a fixed order.
function stabilize(node, path) {
  if (Array.isArray(node)) return node.forEach((v, i) => stabilize(v, `${path}/${i}`));
  if (node === null || typeof node !== "object") return;
  for (const [key, value] of Object.entries(node)) {
    if ((key === "id" || key === "_postman_id") && typeof value === "string")
      node[key] = stableID(`${path}/${key}`);
    else stabilize(value, `${path}/${key}`);
  }
}

async function build(doc, spec, known, variables) {
  rng = seeded(1);
  const collection = await convert(readFileSync(join("..", `${doc}.yaml`), "utf8"));
  const schemes = spec.components?.securitySchemes ?? {};
  for (const item of requests(collection.item)) {
    const req = item.request;
    const template = "/" + req.url.path.map((s) => s.replace(/^:(.+)$/, "{$1}")).join("/");
    const op = spec.paths?.[template]?.[req.method.toLowerCase()];
    if (!op) throw new Error(`${doc}: no operation for ${req.method} ${template}`);
    req.auth = authFor(op.security, schemes);
    linkFields(req, known);
    for (const v of req.url.variable ?? []) {
      const name = pathVariable(template, v.key);
      v.value = `{{${name}}}`;
      variables.add(name);
    }
    // The success examples show what a call returns; every error shares one documented format.
    item.response = (item.response ?? []).filter((r) => r.code >= 200 && r.code < 300);
    const saves = savedVariables(spec, template, req.method, item.response);
    if (saves.length)
      item.event = [
        { listen: "test", script: { type: "text/javascript", exec: afterResponse(saves) } },
      ];
  }
  // One folder per document, named as the document is, holding the converter's folder per tag.
  const name = spec.info.title.replace(/^Qeet ID — /, "").replace(/ API.*$/, "");
  return {
    folder: { name, description: collection.info.description, item: collection.item },
    server: spec.servers[0].url,
  };
}

const out = process.argv[2];
if (!out) throw new Error("usage: bun postman.mjs <output folder>");
mkdirSync(out, { recursive: true });
const specs = docs.map((doc) => Bun.YAML.parse(readFileSync(join("..", `${doc}.yaml`), "utf8")));
// Every path parameter's variable, across the documents, for linkFields.
const known = new Set(
  specs.flatMap((spec) =>
    Object.keys(spec.paths).flatMap((p) =>
      [...p.matchAll(/\{([^}]+)\}/g)].map((m) => pathVariable(p, m[1])),
    ),
  ),
);
const variables = new Set();
const folders = [];
let server;
for (const [i, doc] of docs.entries()) {
  const built = await build(doc, specs[i], known, variables);
  if (server && built.server !== server)
    throw new Error(`${doc}: its first server isn't ${server}`);
  server = built.server;
  folders.push(built.folder);
}
const collection = {
  info: {
    _postman_id: "",
    name: "Qeet ID API",
    description: {
      content: [
        "Every Qeet ID API call, one folder per API document. Generated by make postman from api/openapi/*.yaml:",
        "edit the API sources in api/openapi/src, not this file.",
        "",
        "To call a local server (make dev), import qeet-id-local.postman_environment.json too and select it.",
        "Sign up or sign in first: the answer fills bearerToken, and creating a resource fills its id variable,",
        "such as organizationID. api/postman/README.md has the details.",
      ].join("\n"),
      type: "text/plain",
    },
    schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
  },
  item: folders,
  variable: [{ key: "baseUrl", value: server, type: "string" }],
};
stabilize(collection, "qeet-id");
await write("qeet-id.postman_collection.json", collection);
const secret = (key) => ({ key, value: "", type: "secret", enabled: true });
const environment = {
  id: stableID("environment/local"),
  name: "Qeet ID (local)",
  values: [
    { key: "baseUrl", value: localURL, type: "default", enabled: true },
    ...[
      "bearerToken",
      "refreshToken",
      "apiKey",
      "scimToken",
      "oauthClientId",
      "oauthClientSecret",
      "adminPortalLink",
    ].map(secret),
    ...[...variables].sort().map((key) => ({ key, value: "", type: "default", enabled: true })),
  ],
  _postman_variable_scope: "environment",
};
await write("qeet-id-local.postman_environment.json", environment);
