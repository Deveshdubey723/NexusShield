from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _path_from_env(name: str, default: str) -> Path:
    value = Path(os.getenv(name, default)).expanduser()
    return value if value.is_absolute() else PROJECT_ROOT / value


@dataclass
class Settings:
    database_path: Path = _path_from_env(
        "NEXUS_DATABASE_PATH", "backend/data/nexus_shield.sqlite3"
    )
    upload_dir: Path = _path_from_env("NEXUS_UPLOAD_DIR", "backend/data/uploads")
    max_upload_bytes: int = int(os.getenv("NEXUS_MAX_UPLOAD_BYTES", "5242880"))
    cors_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv(
            "NEXUS_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    )


settings = Settings()
