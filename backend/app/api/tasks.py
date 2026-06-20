"""扫描任务 API"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import get_db
from app.models.task import ScanTask
from app.tasks.scan_task import run_scan_task

router = APIRouter(tags=["tasks"])


@router.post("/tasks")
async def create_task(data: dict, db: AsyncSession = Depends(get_db)):
    """创建扫描任务并异步执行"""
    target_url = data["target_url"]

    # URL 标准化：公网靶场地址 → Docker 内部地址
    target_url = target_url.replace("121.43.231.191:8080/targets/", "targets:8080/")
    target_url = target_url.replace("121.43.231.191:8082/targets/", "targets:8080/")

    task = ScanTask(
        target_url=target_url,
        scan_depth=data.get("scan_depth", 2),
        vuln_types=",".join(data.get("vuln_types", ["sqli", "xss", "file_upload"])),
        custom_headers=data.get("custom_headers"),
        custom_cookies=data.get("custom_cookies"),
        custom_payloads=data.get("custom_payloads"),
        proxy=data.get("proxy"),
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    # 提交异步扫描任务
    run_scan_task.delay(task.id)

    return {"task": task.to_dict()}


@router.get("/tasks")
async def list_tasks(
    page: int = 1,
    page_size: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """获取任务列表（分页）"""
    offset = (page - 1) * page_size

    # 总数
    total_result = await db.execute(select(func.count(ScanTask.id)))
    total = total_result.scalar()

    # 列表
    result = await db.execute(
        select(ScanTask).order_by(ScanTask.created_at.desc()).offset(offset).limit(page_size)
    )
    tasks = result.scalars().all()

    return {
        "tasks": [t.to_dict() for t in tasks],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/tasks/{task_id}")
async def get_task(task_id: str, db: AsyncSession = Depends(get_db)):
    """获取任务详情"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"task": task.to_dict()}


@router.delete("/tasks/{task_id}")
async def delete_task(task_id: str, db: AsyncSession = Depends(get_db)):
    """删除任务及其结果"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    await db.delete(task)
    await db.commit()
    return {"message": "任务已删除"}


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, db: AsyncSession = Depends(get_db)):
    """取消正在运行的扫描任务"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status not in ("pending", "running"):
        raise HTTPException(status_code=400, detail="只能取消等待中或运行中的任务")

    # 设置取消信号到 Redis
    from app.config import settings
    import redis
    r = redis.from_url(settings.redis_url)
    r.setex(f"cancel:{task_id}", 300, "1")
    r.close()

    task.status = "cancelled"
    await db.commit()
    return {"message": "任务已取消"}


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """获取仪表盘统计数据"""
    from app.models.vulnerability import Vulnerability

    total_tasks = (await db.execute(select(func.count(ScanTask.id)))).scalar()
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar()
    completed_tasks = (
        await db.execute(
            select(func.count(ScanTask.id)).where(ScanTask.status == "completed")
        )
    ).scalar()

    # 按类型统计漏洞
    vuln_types = await db.execute(
        select(Vulnerability.vuln_type, func.count(Vulnerability.id)).group_by(Vulnerability.vuln_type)
    )
    vuln_type_stats = {row[0]: row[1] for row in vuln_types}

    return {
        "total_tasks": total_tasks,
        "total_vulns": total_vulns,
        "completed_tasks": completed_tasks,
        "vuln_by_type": vuln_type_stats,
    }
