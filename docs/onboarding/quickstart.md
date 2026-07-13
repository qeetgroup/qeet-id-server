# Quickstart

Get Qeet ID running locally in about 10 minutes.

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Go | 1.25+ | [go.dev/dl](https://go.dev/dl) |
| Node.js | ≥24 | `nvm install` (reads `.nvmrc`) |
| pnpm | 9.15.4 | `npm install -g pnpm@9.15.4` |
| Docker | any recent | [docs.docker.com](https://docs.docker.com/get-docker/) |
| golang-migrate | any | `brew install golang-migrate` |

Node version is critical — the frontend fails to build on Node 18 (the macOS default). Always activate the correct version first:

```bash
nvm use   # reads the repo .nvmrc (Node 24)
```

## Setup (5 commands)

```bash
# 1. Install all dependencies (Go + JS)
make install

# 2. Start PostgreSQL and apply migrations
make db-up migrate-up

# 3. Copy environment config (fill in SMTP if you want email; otherwise OTPs print to backend log)
cp .env.example .env

# 4. Load demo data (two workspaces, six users, roles, webhooks, SSO, audit history)
make seed-reset

# 5. Start everything (API + all three frontend apps)
make dev
```

That's it. You should see:

```
API       http://localhost:4001   (Go server)
Admin     http://localhost:3002   (@qeetid/admin — Vite)
Website   http://localhost:3001   (@qeetid/web — Next.js)
Login     http://localhost:3004   (@qeetid/login — Next.js)
```

## Log in

Open the admin console at `http://localhost:3002`. Log in with any of the seed accounts — all use password `Password123!`:

| Email | Workspace | Role |
|---|---|---|
| `saibabu@qeet.in` | Qeet Group + Qeet Sandbox | Owner (both) |
| `aarav@qeet.in` | Qeet Group | Admin |
| `rohan@qeet.in` | Qeet Group | Engineer |
| `sneha@qeet.in` | Qeet Group | Member |

The `saibabu@qeet.in` account owns **both** the Qeet Group and Qeet Sandbox workspaces — use it to explore the workspace switcher.

The seed also creates **seven fictional customer workspaces** (Northwind Capital, Meridian Health, Lumen Labs, Aster Retail, Vertex Logistics, Cobalt Studios, Fjord Analytics) spanning every plan tier and region, each with its own owner and a generated roster of members (~80 users total). Their owner logins are **printed at the end of `make seed`** (they're generated, so grab them from that output). All accounts share the `Password123!` password.

## First things to explore

1. **Users** — browse, invite, suspend a user
2. **Roles** — view the default roles; create a custom role with specific permissions
3. **Developer → API Keys** — create an API key; the plaintext secret is shown once
4. **Developer → Auth Hooks** — configure a webhook that gates login
5. **Access → Audit Log** — see every action hash-chained and timestamped
6. **Access → Passkeys** — register a passkey from the login app at `http://localhost:3004`

## Backend-only mode

If you only need the API (no frontend):

```bash
make dev-backend    # starts Go server on :4001 only
```

## OTP / magic-link in development

Without SMTP configured, one-time codes and magic-link tokens are printed directly to the backend terminal output. Look for lines like:

```
{"level":"INFO","msg":"dev OTP","email":"rohan@qeet.in","code":"482910"}
```

## Resetting the database

```bash
make seed-reset   # wipe and re-seed (dev only; irreversible)
make db-reset     # wipe schema and re-apply migrations (no seed data)
```

## Running tests

```bash
make test               # Go unit tests + frontend tests (no Docker)
make test-integration   # Go integration tests (requires Docker — spins up ephemeral Postgres)
make test-api           # Postman/Newman API tests (requires running API on :4001)
make test-api FOLDER=Auth  # scope to a Postman collection folder
```
