import os
from pathlib import Path


class Settings:
    db_path: Path = Path(os.environ.get("DB_PATH", "/data/firewall.db"))
    allowlist_path: Path = Path(
        os.environ.get("ALLOWLIST_PATH", "/etc/nginx/dynamic/allowlist.conf")
    )
    secret_key: str = os.environ.get("SECRET_KEY", "")
    session_max_age: int = int(os.environ.get("SESSION_MAX_AGE", str(60 * 60 * 24 * 7)))
    app_env: str = os.environ.get("APP_ENV", "PROD").upper()

    @property
    def is_dev(self) -> bool:
        return self.app_env == "DEV"


settings = Settings()
