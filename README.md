# nginx-firewall

A self-hosted IP-whitelist firewall in front of one or more TCP/UDP upstreams. Nginx does the filtering; a small FastAPI service (REST + UI, SQLite) manages the services and their per-service allowlists and triggers nginx reloads automatically.

## How it works

```
client ──► nginx (stream, per-service allow/deny) ──► your upstreams
                  ▲
                  │ reads /etc/nginx/dynamic/services.conf
                  │   + svc-<id>.allow.conf  (one allowlist per service)
                  │ (auto-reload via inotifywait)
                  │
              FastAPI ──► writes the service blocks + allowlists
              + admin UI / REST API / API tokens
              + SQLite for persistence
```

Two containers share a named volume holding the generated config. FastAPI writes it atomically (allowlists first, then `services.conf`, so a reload never sees a dangling `include`); nginx watches the directory and `nginx -s reload`s itself on every change. No docker socket required.

Each **service** is a public port nginx listens on (`external`) forwarded to an upstream `host:target`, with its own IP allowlist. Add, edit, enable/disable, and delete services from the UI or the `/api/services` endpoints — no compose/env changes needed (see [Network model](#network-model) for the port-publishing caveat).

## Quick start

```bash
cp .env.example .env
# edit .env: SECRET_KEY (and ADMIN_BIND / APP_ENV if needed)
docker compose up --build -d
docker compose logs fastapi   # grab the generated initial admin password
```

Open `http://127.0.0.1:8080` and log in, then:

1. **Services** page — add a service (name, upstream host, protocol, external port → target port).
2. **IP whitelist** page — pick that service and add your own IP (e.g. `1.2.3.4` or `10.0.0.0/24`).

Traffic from allowed IPs to that service's external port starts flowing. By default everything else is denied. Repeat for as many services as you need.

## Auth

- **Admin password** — single password gates the UI and the REST API (via session cookie).
  - First-run: a random password is generated and printed to the `fastapi` container logs.
  - Reset: `docker compose exec fastapi python -m firewall.cli reset-password` (interactive) or `... reset-password --random` (prints a new one).
- **API tokens** — created from the UI or CLI; sent as `Authorization: Bearer <token>`. Only ever shown once at creation (stored as a sha256 hash in the DB).
  - CLI: `docker compose exec fastapi python -m firewall.cli create-token ci-bot`
  - Revoke: `... revoke-token <id>` or via the UI.

## API

All endpoints under `/api` accept either a session cookie (login) or a bearer token.

| Method | Path                  | Body                                | Notes |
| ------ | --------------------- | ----------------------------------- | ----- |
| POST   | `/api/auth/login`     | `{"password": "..."}`               | session cookie |
| GET    | `/api/services`       | —                                   | list services |
| POST   | `/api/services`       | `{"name":"ssh","upstream_host":"127.0.0.1","protocol":"tcp","external_port":2222,"target_port":22,"enabled":true}` | |
| PUT    | `/api/services/{id}`  | any subset of the create fields     | |
| DELETE | `/api/services/{id}`  | —                                   | cascades to its IP rules |
| GET    | `/api/ips`            | — (optional `?service_id=`)         | list entries |
| POST   | `/api/ips`            | `{"service_id":1,"value":"1.2.3.4","label":"","enabled":true}` | CIDR ok |
| PUT    | `/api/ips/{id}`       | `{"label":"...","enabled":true}`    | value + service are immutable |
| DELETE | `/api/ips/{id}`       | —                                   | |
| GET    | `/api/tokens`         | —                                   | metadata only |
| POST   | `/api/tokens`         | `{"name":"ci-bot"}`                 | returns plaintext once |
| DELETE | `/api/tokens/{id}`    | —                                   | revoke |
| POST   | `/api/reload`         | —                                   | force config rewrite |

Any write to `/api/services/*` or `/api/ips/*` regenerates `services.conf` + the per-service allowlists, and nginx reloads itself within ~1s.

When `APP_ENV=DEV`, interactive API docs are served at `/docs` (Swagger UI) and `/redoc`; they're disabled otherwise.

## Network model

- The admin UI binds to `127.0.0.1:8080` on the host by default. Don't expose it directly to the internet — put a TLS reverse proxy (e.g. Caddy, Traefik) in front, or only access it via SSH tunnel / VPN. Override with `ADMIN_BIND=0.0.0.0:8080` in `.env` only if you've added TLS.
- Each service's **external port** is what faces the internet: clients hit it, nginx enforces that service's allowlist, surviving traffic reaches `upstream_host:target_port`.
- Because external ports are managed dynamically in the DB, the nginx container runs with **`network_mode: host`** by default so any port you add in the UI goes live immediately. Host networking is a **Linux** feature — on Docker Desktop (macOS/Windows) it won't publish host ports. There, edit `docker-compose.yml`: comment out `network_mode: host` and uncomment the `ports:` block, listing each external port you'll use (adding a service on a new port then means updating that list and `docker compose up -d`).
- With host networking, `upstream_host` is resolved on the host's network namespace: use `127.0.0.1` for a service running on the same host. With the bridge fallback, use `host.docker.internal` (uncomment the matching `extra_hosts`) or a container name on the same network.

## Out of scope

- TLS on the admin UI (put a reverse proxy in front).
- IPv6 publishing on the host (entries are accepted; host port-publishing config may need adjustment).
- Audit trail of who changed what (only `created_at` / `updated_at` per entry).

## Development

Without Docker, install requirements and run uvicorn:

```bash
cd app
pip install -r requirements.txt
DB_PATH=./firewall.db \
DYNAMIC_DIR=./dynamic \
APP_ENV=DEV \
SECRET_KEY=$(python -c 'import secrets;print(secrets.token_urlsafe(48))') \
uvicorn firewall.main:app --reload --port 8080
```

The app writes `services.conf` and `svc-<id>.allow.conf` into `DYNAMIC_DIR`; point nginx's `include` at that directory if you wire one up locally.
