FROM nginx:1.31.0-alpine

RUN apk add --no-cache inotify-tools gettext

RUN mkdir -p /etc/nginx/dynamic \
    && printf '# No services configured yet.\n' > /etc/nginx/dynamic/services.conf

COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
