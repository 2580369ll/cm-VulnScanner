"""数据库模型 — 扫描任务"""

import uuid
from datetime import datetime

from sqlalchemy import String, Integer, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base
from app.models.vulnerability import Vulnerability


class ScanTask(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    scan_depth: Mapped[int] = mapped_column(Integer, default=2)
    vuln_types: Mapped[str] = mapped_column(String(256), default="sqli,xss,file_upload")
    custom_headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    custom_cookies: Mapped[str | None] = mapped_column(Text, nullable=True)
    custom_payloads: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON: {"sqli":["'OR 1=1--"],...}
    proxy: Mapped[str | None] = mapped_column(String(256), nullable=True)
    total_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    total_vulns: Mapped[int] = mapped_column(Integer, default=0)
    scanned_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    waf_detected: Mapped[str | None] = mapped_column(String(128), nullable=True)

    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "target_url": self.target_url, "status": self.status,
            "scan_depth": self.scan_depth,
            "vuln_types": self.vuln_types.split(",") if self.vuln_types else [],
            "total_endpoints": self.total_endpoints, "total_vulns": self.total_vulns,
            "scanned_endpoints": self.scanned_endpoints, "waf_detected": self.waf_detected,
            "custom_payloads": self.custom_payloads,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
