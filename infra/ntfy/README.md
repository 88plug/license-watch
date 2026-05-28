# Self-hosted ntfy.sh on Hetzner CX11

One-paste setup. Target: ~$4/mo single VM, public push endpoint,
Let's Encrypt TLS, admin protected by HTTP basic auth.

## 1. Provision the VM

Hetzner Cloud Console → New Project → Add Server:

- Location: closest to you (Falkenstein / Helsinki / Ashburn)
- Image: Ubuntu 24.04
- Type: CX11 (2 vCPU shared / 4 GB RAM / 40 GB SSD / 20 TB traffic)
- SSH key: add yours
- Cloud-init: leave blank

Note the IPv4 + IPv6.

Point an A (and AAAA) record:

```
ntfy.example.com  A    <ipv4>
ntfy.example.com  AAAA <ipv6>
```

Wait for DNS to propagate. Verify:

```sh
dig +short ntfy.example.com
```

## 2. Harden the box (one-paste)

```sh
ssh root@ntfy.example.com '
  set -euo pipefail
  apt-get update
  apt-get -y dist-upgrade
  apt-get -y install ufw fail2ban unattended-upgrades
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw --force enable
  dpkg-reconfigure -f noninteractive unattended-upgrades
'
```

## 3. Install Docker (one-paste)

```sh
ssh root@ntfy.example.com '
  set -euo pipefail
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
'
```

## 4. Deploy ntfy + Caddy

On your laptop:

```sh
# Generate the bcrypt hash for the admin password (interactive prompt).
docker run --rm -it caddy:2.10.0-alpine caddy hash-password
# Copy the resulting "$2a$14$..." hash.
```

On the server:

```sh
ssh root@ntfy.example.com '
  set -euo pipefail
  mkdir -p /opt/ntfy
'
scp docker-compose.yml Caddyfile root@ntfy.example.com:/opt/ntfy/
ssh root@ntfy.example.com '
  set -euo pipefail
  cd /opt/ntfy
  cat > .env <<EOF
NTFY_DOMAIN=ntfy.example.com
NTFY_BASE_URL=https://ntfy.example.com
ACME_EMAIL=andrew@88plug.com
ADMIN_USER=admin
ADMIN_PASS_HASH=PASTE_BCRYPT_HASH_HERE
EOF
  chmod 600 .env
  docker compose up -d
  docker compose ps
'
```

Verify:

```sh
curl -fsS https://ntfy.example.com/v1/health
```

Expected output: `{"healthy":true}`.

## 5. Create your first topic + user

```sh
ssh root@ntfy.example.com '
  set -euo pipefail
  cd /opt/ntfy
  docker compose exec ntfy ntfy user add --role=admin admin
  docker compose exec ntfy ntfy access admin "*" rw
  docker compose exec ntfy ntfy user add watcher
  docker compose exec ntfy ntfy access watcher "license-watch*" wo
  docker compose exec ntfy ntfy access watcher "license-watch-heartbeat" wo
'
```

Subscribe from your phone (ntfy app):

- Server: `https://ntfy.example.com`
- Topic:  `license-watch`
- Auth:   `watcher` + its password

## 6. Point license-watch at it

In your `internal/notify/notify.yml` (or via env-var injection in CI):

```yaml
alerts:
  urls:
    - "ntfys://watcher:THEPASSWORD@ntfy.example.com/license-watch"
heartbeat:
  urls:
    - "ntfys://watcher:THEPASSWORD@ntfy.example.com/license-watch-heartbeat"
```

Test:

```sh
python -m internal.notify.notify alert \
  --title "test" --body "hello from license-watch"
```

You should see a push within ~1s.

## 7. Updates

```sh
ssh root@ntfy.example.com '
  cd /opt/ntfy
  docker compose pull
  docker compose up -d
'
```

Versions are pinned in `docker-compose.yml`; bump them deliberately when
the [ntfy changelog](https://github.com/binwiederhier/ntfy/blob/main/CHANGELOG.md)
warrants.
