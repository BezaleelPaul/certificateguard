from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List
import os


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./certificateguard.db"
    SECRET_KEY: str = "dev_secret_key_certificate_guard_super_secure_32_bytes_min_12345"
    ENVIRONMENT: str = "development"
    PORT: int = 8000
    STORAGE_PATH: str = "./storage"
    MAX_FILE_SIZE_MB: int = 15
    MAX_PDF_PAGES: int = 10
    PLAYWRIGHT_TIMEOUT_MS: int = 15000
    MOCK_ISSUER_URL: str = "http://localhost:8001"
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


settings = Settings()
