#!/usr/bin/env bash
# One-shot EC2 bootstrap — run once on a fresh Amazon Linux 2023 or Ubuntu instance.
set -euo pipefail

# Install Docker
if command -v apt-get &>/dev/null; then
    apt-get update -y
    apt-get install -y ca-certificates curl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
else
    dnf install -y docker
    systemctl enable --now docker
    # Docker Compose plugin for Amazon Linux
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" \
        -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi

# Add current user to docker group (re-login required)
usermod -aG docker "${SUDO_USER:-$USER}" 2>/dev/null || true

# Install git (to clone the repo on this machine)
if command -v apt-get &>/dev/null; then apt-get install -y git; else dnf install -y git; fi

# Working directory for compose files
mkdir -p /opt/qeet-id

echo ""
echo "Bootstrap complete. Next steps:"
echo "  1. Re-login so docker group takes effect"
echo "  2. Clone repo:  git clone https://github.com/qeetgroup/qeet-id /opt/qeet-id-src"
echo "  3. Build image: cd /opt/qeet-id-src && docker build -t qeet-id:latest ."
echo "  4. Copy files:  cp deploy/prod/{docker-compose.yml,Caddyfile,.env.example} /opt/qeet-id/"
echo "  5. Configure:   cd /opt/qeet-id && cp .env.example .env && nano .env"
echo "  6. Start:       docker compose up -d"
