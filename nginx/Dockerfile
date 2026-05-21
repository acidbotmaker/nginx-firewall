FROM nginx:1.31.0-alpine

RUN apk add --no-cache inotify-tools gettext

RUN mkdir -p /etc/nginx/dynamic \
    && printf 'deny all;\n' > /etc/nginx/dynamic/allowlist.conf

COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
