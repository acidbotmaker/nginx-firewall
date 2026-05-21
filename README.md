# nginx-firewall

A self-hosted IP-whitelist firewall in front of a single TCP+UDP upstream. Nginx does the filtering; a small FastAPI service (REST + UI, SQLite) manages the allowlist and triggers nginx reloads automatically.

## How it works

```
client ──► nginx (stream, allow/deny) ──► your upstream
                  ▲
                  │ reads /etc/nginx/dynamic/allowlist.conf
                  │ (auto-reload via inotifywait)
                  │
              FastAPI ──► writes the allowlist
              + admin UI / REST API / API tokens
              + SQLite for persistence
```

Two containers share a named volume holding `allowlist.conf`. FastAPI writes it atomically; nginx watches the file and `nginx -s reload`s itself on every change. No docker socket required.

## Quick start

```bash
cp .env.example .env
# edit .env: UPSTREAM_HOST, TARGET_TCP, TARGET_UDP, EXTERNAL_TCP, EXTERNAL_UDP, SECRET_KEY
docker compose up --build -d
docker compose logs fastapi   # grab the generated initial admin password
```

Open `http://127.0.0.1:8080` and log in. Add your own IP (e.g. `1.2.3.4` or `10.0.0.0/24`) and traffic to the upstream ports will start flowing. By default everything else is denied.

## Auth

- **Admin password** — single password gates the UI and the REST API (via session cookie).
  - First-run: a random password is generated and printed to the `fastapi` container logs.
  - Reset: `docker compose exec fastapi python -m firewall.cli reset-password` (interactive) or `... reset-password --random` (prints a new one).
- **API tokens** — created from the UI or CLI; sent as `Authorization: Bearer <token>`. Only ever shown once at creation (stored as a sha256 hash in the DB).
  - CLI: `docker compose exec fastapi python -m firewall.cli create-token ci-bot`
  - Revoke: `... revoke-token <id>` or via the UI.

## API

All endpoints under `/api` accept either a session cookie (login) or a bearer token.

| Method | Path                | Body                                | Notes |
| ------ | ------------------- | ----------------------------------- | ----- |
| POST   | `/api/auth/login`   | `{"password": "..."}`               | session cookie |
| GET    | `/api/ips`          | —                                   | list entries |
| POST   | `/api/ips`          | `{"value":"1.2.3.4","label":"","enabled":true}` | CIDR ok |
| PUT    | `/api/ips/{id}`     | `{"label":"...","enabled":true}`    | value is immutable |
| DELETE | `/api/ips/{id}`     | —                                   | |
| GET    | `/api/tokens`       | —                                   | metadata only |
| POST   | `/api/tokens`       | `{"name":"ci-bot"}`                 | returns plaintext once |
| DELETE | `/api/tokens/{id}`  | —                                   | revoke |
| POST   | `/api/reload`       | —                                   | force allowlist rewrite |

Any write to `/api/ips/*` regenerates `allowlist.conf` and nginx reloads itself within ~1s.

## Network model

- The admin UI binds to `127.0.0.1:8080` on the host by default. Don't expose it directly to the internet — put a TLS reverse proxy (e.g. Caddy, Traefik) in front, or only access it via SSH tunnel / VPN. Override with `ADMIN_BIND=0.0.0.0:8080` in `.env` only if you've added TLS.
- `EXTERNAL_TCP` / `EXTERNAL_UDP` are the public ports nginx listens on — these are published on the host on `0.0.0.0` and face the internet. That's the whole point: clients hit these, nginx enforces the allowlist, traffic that survives reaches the upstream.
- `TARGET_TCP` / `TARGET_UDP` are the internal ports the upstream actually listens on. nginx forwards allowed traffic to `UPSTREAM_HOST:TARGET_*`. The external and target ports can be the same (e.g. both `51820`) or different (e.g. listen on public `443/tcp`, forward to internal `2222/tcp`).
- `UPSTREAM_HOST` is resolved inside the nginx container. Use `host.docker.internal` to reach a service on the docker host, or a service/container name on the same docker network.

## Out of scope

- TLS on the admin UI (put a reverse proxy in front).
- Multiple upstreams (one fixed upstream per deployment — duplicate the compose stack to protect more services).
- IPv6 publishing on the host (entries are accepted; host port-publishing config may need adjustment).
- Audit trail of who changed what (only `created_at` / `updated_at` per entry).

## Development

Without Docker, install requirements and run uvicorn:

```bash
cd app
pip install -r requirements.txt
DB_PATH=./firewall.db \
ALLOWLIST_PATH=./allowlist.conf \
SECRET_KEY=$(python -c 'import secrets;print(secrets.token_urlsafe(48))') \
uvicorn firewall.main:app --reload --port 8080
```
