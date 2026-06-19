"""应用配置管理"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """应用配置，从环境变量读取"""

    # 数据库
    database_url: str = "postgresql+asyncpg://scanner:scanner_pass_2024@localhost:5432/vuln_scanner"

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # 扫描配置
    max_scan_depth: int = 3
    max_pages_per_target: int = 50
    request_timeout: int = 10
    scan_delay: float = 0.5  # 请求间隔（秒）

    # WAF
    waf_detection_enabled: bool = True
    waf_bypass_enabled: bool = True

    # 应用
    app_name: str = "VulnScanner"
    debug: bool = True

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
