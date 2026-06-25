# Deploy — qeet-id API (EC2 + RDS, Docker Compose, GitHub Actions)

The qeet-id backend runs as a single Docker container on one EC2 host, behind
**Caddy** (automatic HTTPS) at **`api.id.qeet.in`**, with **Postgres on RDS**.
CI/CD builds the image, pushes it to **GHCR**, and deploys over **SSH**.

One container is the whole backend: the server embeds the background workers and
auto-applies DB migrations on startup. No Terraform, no Kubernetes.

```
deploy/
  docker-compose.yml   # app (GHCR image) + caddy
  Caddyfile            # reverse proxy → app:4001, auto-TLS
  .env.example         # template for the host-only /opt/qeet-id/.env
  README.md            # this file
.github/workflows/deploy.yml   # build → push GHCR → scp → ssh compose up
```

---

## One-time setup

### 1. RDS (Postgres)
- Create a **PostgreSQL 16** instance (e.g. `db.t4g.micro`), **not publicly
  accessible**, in the same VPC as the EC2 host.
- Security group: allow **5432** inbound **only from the EC2 instance's security
  group**.
- Note the endpoint → goes into `DB_URL`. The DB name is `qeet_id`.

### 2. EC2 host
- **Amazon Linux 2023**, `t3.small` (amd64 — matches the image built by CI).
- Security group: inbound **80** and **443** from `0.0.0.0/0`; **22** only from
  your IP (or skip SSH and use SSM Session Manager).
- Allocate an **Elastic IP** and associate it (stable address for DNS).
- Install Docker + the Compose plugin:
  ```bash
  sudo dnf update -y
  sudo dnf install -y docker
  sudo systemctl enable --now docker
  sudo usermod -aG docker ec2-user            # re-login to take effect
  sudo mkdir -p /usr/local/lib/docker/cli-plugins
  sudo curl -fsSL \
    "https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  ```

### 3. Host config + secrets (`/opt/qeet-id`)
```bash
sudo mkdir -p /opt/qeet-id && sudo chown ec2-user:ec2-user /opt/qeet-id
cd /opt/qeet-id
# Copy deploy/.env.example here as .env and fill in real values:
#   - DB_URL (RDS endpoint + password)
#   - JWT_SECRET   = openssl rand -hex 32
#   - SECRETS_KEY  = openssl rand -base64 32
nano .env

# EC P-256 signing key (multi-line PEM, kept out of .env):
openssl ecparam -name prime256v1 -genkey -noout > jwt_signing_key.pem
chmod 600 .env jwt_signing_key.pem
```
`.env` and `jwt_signing_key.pem` live **only on the host** — never commit them.

### 4. DNS (GoDaddy, zone `qeet.in`)
- Add an **A record**: Host = **`api.id`**, Value = the **Elastic IP**
  (this resolves `api.id.qeet.in`). Set TTL ~600s during setup.
- It must resolve **before the first deploy** so Caddy can complete the ACME
  challenge and issue the TLS cert.
- **CAA gotcha:** if `qeet.in` has a `CAA` record, it must permit
  `letsencrypt.org` or Caddy can't get a cert. A zone with no CAA allows any CA
  (fine for a fresh setup).

### 5. GitHub repo secrets
Settings → Secrets and variables → Actions → **New repository secret**:

| Secret | Value |
|---|---|
| `EC2_HOST` | the Elastic IP (or `api.id.qeet.in` once DNS resolves) |
| `EC2_USER` | `ec2-user` |
| `EC2_SSH_KEY` | the **private** SSH key (PEM) for that host |

GHCR pull on the host uses the workflow's built-in `GITHUB_TOKEN` — no extra
secret. (If a pull is ever denied, set the GHCR package visibility to *internal*
for the org, or use a `read:packages` PAT.)

---

## Deploy

Push to `main` (or run the **Deploy** workflow manually). The pipeline:
1. builds the image from the repo-root `Dockerfile`,
2. pushes `ghcr.io/qeetgroup/qeet-id:latest` and `:<commit-sha>`,
3. copies `docker-compose.yml` + `Caddyfile` to `/opt/qeet-id`,
4. SSHes in, pulls the `:<sha>` image, `docker compose up -d`, waits for
   `/readyz`.

## Verify

```bash
curl -i https://api.id.qeet.in/readyz                          # 200
curl -s https://api.id.qeet.in/.well-known/openid-configuration | grep issuer
#   -> "issuer":"https://api.id.qeet.in"
curl -s https://api.id.qeet.in/.well-known/jwks.json           # returns keys
```
On the host: `docker compose ps`, `docker compose logs app` (shows migrations +
server on :4001), `docker compose logs caddy` (cert obtained for api.id.qeet.in).

## Rollback

Deploy a previous image without rebuilding:
```bash
# on the host
cd /opt/qeet-id
export JWT_SIGNING_KEY="$(cat jwt_signing_key.pem)"
IMAGE=ghcr.io/qeetgroup/qeet-id:<older-sha> docker compose up -d
```
Or re-run the **Deploy** workflow from the older commit in the Actions UI.

## Notes
- **Migrations** run automatically on app startup (embedded). Keep schema changes
  backward-compatible across a deploy.
- **Scaling**: this is a single instance, so in-process rate limiting is correct
  and `REDIS_URL` stays blank. Running more than one app instance later requires
  setting `REDIS_URL` (ElastiCache) for shared limits.
- **First boot before DNS**: set `SITE_ADDRESS=:80` in `.env` to serve plain
  HTTP, then switch to `SITE_ADDRESS=api.id.qeet.in` once the A record resolves
  and redeploy for TLS.
