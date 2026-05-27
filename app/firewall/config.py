import os
from pathlib import Path


class Settings:
    db_path: Path = Path(os.environ.get("DB_PATH", "/data/firewall.db"))
    # Directory holding all nginx-generated config (per-service allowlists +
    # the stream server blocks). Defaults to the dir nginx watches via inotify.
    dynamic_dir: Path = Path(os.environ.get("DYNAMIC_DIR", "/etc/nginx/dynamic"))
    secret_key: str = os.environ.get("SECRET_KEY", "")
    session_max_age: int = int(os.environ.get("SESSION_MAX_AGE", str(60 * 60 * 24 * 7)))
    app_env: str = os.environ.get("APP_ENV", "PROD").upper()

    @property
    def is_dev(self) -> bool:
        return self.app_env == "DEV"

    @property
    def services_conf_path(self) -> Path:
        return self.dynamic_dir / "services.conf"

    def allowlist_path(self, service_id: int) -> Path:
        return self.dynamic_dir / f"svc-{service_id}.allow.conf"


settings = Settings()
