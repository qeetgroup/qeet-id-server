# Deploying Qeet ID to Production

This guide walks you through deploying Qeet ID on a single AWS EC2 instance using Docker Compose. The database runs on AWS RDS (managed PostgreSQL) — no database container needed.

**What you'll set up:**
```
Your Browser
     │
     ▼
  Caddy  ←── handles HTTPS automatically (Let's Encrypt)
     │
     ▼
 Qeet ID App  ←── runs migrations on startup, then serves traffic
     │
     ├──► Redis  (rate limiting, runs locally on EC2)
     │
     └──► AWS RDS  (your PostgreSQL database)
```

**Domains this guide uses:**
| URL | Purpose |
|---|---|
| `api.id.qeet.in` | REST API |
| `auth.id.qeet.in` | Hosted login (OAuth / passkeys) |
| `console.id.qeet.in` | Admin console |

Point all three DNS A records to your EC2 Elastic IP before deploying.

---

## Step 1 — Create the Database (AWS RDS)

1. Go to **AWS Console → RDS → Create database**
2. Choose:
   - Engine: **PostgreSQL 16**
   - Template: **Production** (or Free tier for testing)
   - Instance class: `db.t3.micro` to start
   - DB instance identifier: `qeet-id`
   - Master username: `qeetid`
   - Master password: choose a strong password and save it
   - DB name: `qeet_id`
3. Under **Connectivity**:
   - VPC: same VPC you'll use for EC2
   - Public access: **No** (EC2 will reach it privately)
4. Create the database and wait for it to become **Available**
5. Copy the **Endpoint** — it looks like `qeet-id.xxxx.us-east-1.rds.amazonaws.com`

---

## Step 2 — Launch the EC2 Instance

1. Go to **AWS Console → EC2 → Launch instance**
2. Choose:
   - AMI: **Amazon Linux 2023** or **Ubuntu 22.04**
   - Instance type: `t3.small` (minimum) — `t3.medium` recommended
   - Storage: 20 GB gp3
   - Key pair: create or choose one (you'll need this to SSH in)
3. After launch, allocate an **Elastic IP** and associate it with the instance
   - This gives you a static IP that won't change on restart
4. Point your DNS A records (`api.id.qeet.in`, `auth.id.qeet.in`, `console.id.qeet.in`) to this Elastic IP

---

## Step 3 — Configure Security Groups

**EC2 Security Group** — allow inbound:
| Port | Protocol | Source | Why |
|---|---|---|---|
| 22 | TCP | Your IP | SSH access |
| 80 | TCP | 0.0.0.0/0 | HTTP (Caddy redirects to HTTPS) |
| 443 | TCP | 0.0.0.0/0 | HTTPS |

**RDS Security Group** — allow inbound:
| Port | Protocol | Source | Why |
|---|---|---|---|
| 5432 | TCP | EC2 Security Group | App connects to database |

> The RDS instance must not be publicly accessible — only your EC2 can reach it.

---

## Step 4 — Install Docker on EC2

SSH into your instance and run the setup script:

```bash
# From your local machine — copy the script to EC2
scp -i your-key.pem deploy/prod/setup.sh ec2-user@<ELASTIC-IP>:~/

# SSH in and run it
ssh -i your-key.pem ec2-user@<ELASTIC-IP>
bash ~/setup.sh

# Log out and back in so Docker permissions take effect
exit
ssh -i your-key.pem ec2-user@<ELASTIC-IP>

# Verify Docker is working
docker run --rm hello-world
```

---

## Step 5 — Get the Code and Build the Image

```bash
# Clone the repository
git clone https://github.com/qeetgroup/qeet-id.git /opt/qeet-id-src
cd /opt/qeet-id-src

# Build the Docker image (this takes 2–3 minutes the first time)
docker build -t qeet-id:latest .
```

The image includes the Go binary + all migration files embedded inside it.
When the app starts, it automatically applies any pending migrations.

---

## Step 6 — Generate Secrets

Run these commands to generate the values you'll need in your `.env` file.
**Save the output somewhere safe before continuing.**

```bash
# JWT_SECRET — used to sign refresh tokens
openssl rand -base64 48

# JWT_SIGNING_KEY — EC P-256 private key for signing access tokens
# Copy the full output (everything from -----BEGIN to -----END) as a single line with \n
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt \
  | awk 'NF {printf "%s\\n", $0}' \
  | sed 's/\\n$//'

# SECRETS_KEY — encrypts secrets stored in the vault
openssl rand -base64 32

# CSRF_KEY — protects against cross-site request forgery
openssl rand -base64 32

# SAML_IDP_KEY + SAML_IDP_CERT — signs SAML assertions (skip if not using SAML)
openssl req -x509 -newkey rsa:2048 -keyout /tmp/saml.key -out /tmp/saml.crt \
  -days 3650 -nodes -subj "/CN=Qeet ID SAML IdP"
awk 'NF {printf "%s\\n", $0}' /tmp/saml.key | sed 's/\\n$//'   # → SAML_IDP_KEY
awk 'NF {printf "%s\\n", $0}' /tmp/saml.crt | sed 's/\\n$//'   # → SAML_IDP_CERT
rm /tmp/saml.key /tmp/saml.crt
```

---

## Step 7 — Configure the Environment

```bash
# Create the working directory for Docker Compose
mkdir -p /opt/qeet-id
cd /opt/qeet-id

# Copy the three config files from the repo
cp /opt/qeet-id-src/deploy/prod/docker-compose.yml .
cp /opt/qeet-id-src/deploy/prod/Caddyfile .
cp /opt/qeet-id-src/deploy/prod/.env.example .env

# Open the .env file and fill in the values
nano .env
```

**Required values to fill in:**

| Variable | What to put |
|---|---|
| `DB_URL` | `postgres://qeetid:PASSWORD@YOUR-RDS-ENDPOINT:5432/qeet_id?sslmode=require` |
| `JWT_SECRET` | output from Step 6 |
| `JWT_SIGNING_KEY` | output from Step 6 |
| `SECRETS_KEY` | output from Step 6 |
| `CSRF_KEY` | output from Step 6 |
| `SAML_IDP_KEY` | output from Step 6 (or leave blank to auto-generate in dev) |
| `SAML_IDP_CERT` | output from Step 6 (or leave blank to auto-generate in dev) |

Everything else in `.env.example` has sensible defaults — review but don't change unless needed.

---

## Step 8 — Start the Stack

```bash
cd /opt/qeet-id

# Start all services in the background
docker compose up -d

# Watch the startup logs — you should see migrations run, then "listening"
docker compose logs -f app
```

**What to look for in the logs:**
```
INFO  running database migrations
INFO  database migrations up to date
INFO  starting  service=qeet-id version=...
INFO  listening addr=:4001
```

**Verify everything is working:**
```bash
curl https://api.id.qeet.in/healthz
# Expected: {"status":"ok","version":"..."}

curl https://api.id.qeet.in/readyz
# Expected: {"status":"ok"}
# (readyz also checks that the database is reachable)
```

If the health checks pass, your deployment is live. 🎉

---

## Updating to a New Version

```bash
# 1. Pull the latest code
cd /opt/qeet-id-src
git pull

# 2. Rebuild the image
docker build -t qeet-id:latest .

# 3. Restart just the app (migrations run automatically on startup)
cd /opt/qeet-id
docker compose up -d --no-deps app

# 4. Confirm it came up cleanly
docker compose logs --tail=20 app
```

---

## Rolling Back to a Previous Version

```bash
# 1. Check out the version you want to go back to
cd /opt/qeet-id-src
git checkout vX.Y.Z       # e.g. v0.9.1

# 2. Rebuild
docker build -t qeet-id:latest .

# 3. Restart the app
cd /opt/qeet-id
docker compose up -d --no-deps app
```

> **Never run `migrate down` in production.** If a migration introduced a bug, write a new migration to fix it — don't roll back the schema.

---

## Useful Commands

```bash
# See what's running
docker compose ps

# Live logs
docker compose logs -f app       # app logs (migrations, requests, errors)
docker compose logs -f caddy     # TLS / proxy logs

# Restart the app without changing the image
docker compose restart app

# Check Redis is alive
docker compose exec redis redis-cli ping    # → PONG

# Connect directly to the database (useful for debugging)
docker run --rm -it --network qeet-id-prod_internal postgres:16-alpine \
  psql "postgres://qeetid:PASSWORD@<RDS-ENDPOINT>:5432/qeet_id?sslmode=require"

# Stop everything (keeps data volumes)
docker compose down

# Stop and wipe all data (destructive — dev only!)
docker compose down -v
```

---

## Troubleshooting

**App won't start — `migrations failed`**
- Check `DB_URL` in `.env` — make sure the password and endpoint are correct
- Check the RDS security group allows port 5432 from your EC2

**App won't start — `refusing to start: ...`**
- The production safety check failed — a required secret is missing or insecure
- Run `docker compose logs app` and look for `config:` in the error message

**Caddy shows certificate errors**
- DNS hasn't propagated yet — wait a few minutes and retry
- Make sure ports 80 and 443 are open in the EC2 security group

**`readyz` returns 503**
- The app cannot reach the database
- Check `docker compose logs app` for `connect db` errors
