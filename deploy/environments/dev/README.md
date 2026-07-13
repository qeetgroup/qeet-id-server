# Local Development

This directory contains the Docker Compose configuration for local development. It runs only the infrastructure services (PostgreSQL) — the Go API and frontend apps run on the host via `make dev`.

## Usage

All `make db-*` targets point here automatically:

```bash
make db-up       # start Postgres on :5001
make db-down     # stop Postgres
make db-psql     # open interactive psql shell
make db-reset    # drop all schemas + remigrate
make db-wipe     # migrate down-all + migrate up
```

Or directly with Compose:

```bash
docker compose -f deploy/environments/dev/docker-compose.yml up -d
docker compose -f deploy/environments/dev/docker-compose.yml down
docker compose -f deploy/environments/dev/docker-compose.yml logs postgres
```

## Services

| Service | Port | Purpose |
|---|---|---|
| `postgres` | 5001 | PostgreSQL 16 — primary datastore |

Redis is **not** included in local dev — the rate limiter falls back to the in-process store automatically when `REDIS_URL` is unset.

## Configuration

Credentials are loaded from `.env` (gitignored) at the repo root. Start from:

```bash
cp .env.example .env
# Edit .env — at minimum set POSTGRES_PASSWORD
```

The dev project name is `qeet-id-dev` (encoded in `docker-compose.yml`). This ensures volumes and networks never collide with the production-shaped stack in `../compose/`.

## Data persistence

Postgres data is stored in a named Docker volume `qeet-id-dev_pgdata`. To wipe it completely:

```bash
make db-down
docker volume rm qeet-id-dev_pgdata
make db-up migrate-up
```

## Differences from production

| Aspect | Local | Production |
|---|---|---|
| Stack | Postgres only | Full stack (API + Caddy + Redis + Postgres) |
| TLS | None (HTTP) | Caddy (HTTPS) |
| Secrets | `.env` file | AWS Secrets Manager / Docker secrets |
| Redis | In-process fallback | Real Redis instance |
| Image | Host Go binary | Distroless container |
