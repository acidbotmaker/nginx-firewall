#!/bin/sh
set -eu

: "${UPSTREAM_HOST:?UPSTREAM_HOST is required}"
: "${TARGET_TCP:?TARGET_TCP is required}"
: "${TARGET_UDP:?TARGET_UDP is required}"
: "${EXTERNAL_TCP:?EXTERNAL_TCP is required}"
: "${EXTERNAL_UDP:?EXTERNAL_UDP is required}"

envsubst '${UPSTREAM_HOST} ${TARGET_TCP} ${TARGET_UDP} ${EXTERNAL_TCP} ${EXTERNAL_UDP}' \
    < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

if [ ! -f /etc/nginx/dynamic/allowlist.conf ]; then
    printf 'deny all;\n' > /etc/nginx/dynamic/allowlist.conf
fi

# Validate the final config before starting.
nginx -t

# Watch the allowlist file and reload nginx on changes. The FastAPI service
# writes atomically (tempfile + os.replace), so close_write fires once per
# change with a valid file already in place.
(
    while inotifywait -e close_write,moved_to,create /etc/nginx/dynamic 2>/dev/null; do
        if nginx -t 2>/tmp/nginx-test.err; then
            nginx -s reload
            echo "[reloader] reloaded nginx at $(date -Iseconds)"
        else
            echo "[reloader] config invalid, keeping previous:" >&2
            cat /tmp/nginx-test.err >&2
        fi
    done
) &

exec nginx -g 'daemon off;'
