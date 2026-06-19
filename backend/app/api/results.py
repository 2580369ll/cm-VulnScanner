"""漏洞结果 API"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import get_db
from app.models.vulnerability import Vulnerability

router = APIRouter(tags=["results"])


@router.get("/tasks/{task_id}/results")
async def list_task_results(task_id: str, db: AsyncSession = Depends(get_db)):
    """获取某任务的所有漏洞结果"""
    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.task_id == task_id)
        .order_by(Vulnerability.severity.asc(), Vulnerability.created_at.desc())
    )
    vulns = result.scalars().all()
    return {"vulnerabilities": [v.to_dict() for v in vulns], "total": len(vulns)}


@router.get("/results/{vuln_id}")
async def get_result(vuln_id: str, db: AsyncSession = Depends(get_db)):
    """获取单个漏洞详情"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return {"vulnerability": vuln.to_dict()}
