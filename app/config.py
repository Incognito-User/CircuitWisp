from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    exploitdb_api_key: str | None = None
    github_token: str | None = None
    log_level: str = "INFO"
    request_timeout: int = 10

    class Config:
        env_file = ".env"

settings = Settings()
