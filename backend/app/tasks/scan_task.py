"""异步扫描任务"""

import asyncio
import json
from datetime import datetime

from celery.utils.log import get_task_logger

from app.tasks.celery_app import celery_app
from app.api.websocket import broadcast_progress

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="scan_task")
def run_scan_task(self, task_id: str):
    """
    异步执行扫描任务

    在 Celery worker 中运行，通过 asyncio 调用异步扫描引擎
    """
    logger.info(f"扫描任务启动: {task_id}")

    async def _run():
        from app.models import async_session
        from app.models.task import ScanTask
        from app.scanner.engine import ScanEngine

        async with async_session() as db:
            # 获取任务
            from sqlalchemy import select
            result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
            task = result.scalar_one_or_none()
            if not task:
                logger.error(f"任务不存在: {task_id}")
                return

            # 更新状态为运行中
            task.status = "running"
            task.started_at = datetime.utcnow()
            await db.commit()

            # 解析自定义选项
            headers = json.loads(task.custom_headers) if task.custom_headers else None
            cookies = json.loads(task.custom_cookies) if task.custom_cookies else None
            vuln_types = task.vuln_types.split(",")

            # 进度回调
            async def progress_callback(msg: dict):
                msg["task_id"] = task_id
                await broadcast_progress(task_id, msg)

                # 更新扫描进度
                msg_type = msg.get("type")
                if msg_type == "crawl_complete":
                    task.total_endpoints = msg.get("total_endpoints", 0)
                    await db.commit()
                elif msg_type == "endpoint_scanned":
                    task.scanned_endpoints += 1
                    await db.commit()
                elif msg_type == "vulnerability_found":
                    task.total_vulns += 1
                    await db.commit()
                elif msg_type == "waf_detected":
                    task.waf_detected = msg.get("waf", "unknown")
                    await db.commit()

            try:
                # 创建并运行扫描引擎
                engine = ScanEngine(
                    target_url=task.target_url,
                    scan_depth=task.scan_depth,
                    vuln_types=vuln_types,
                    custom_headers=headers,
                    custom_cookies=cookies,
                    proxy=task.proxy,
                    progress_callback=progress_callback,
                    task_id=task_id,
                )

                findings = await engine.run()

                # 保存结果
                from app.models.vulnerability import Vulnerability

                for f in findings:
                    vuln = Vulnerability(
                        task_id=task_id,
                        vuln_type=f["type"],
                        severity=f["severity"],
                        confidence=f.get("confidence", 0.8),
                        endpoint=f["endpoint"],
                        parameter=f.get("parameter", ""),
                        method=f.get("method", "GET"),
                        payload=f.get("payload", ""),
                        payload_variant=f.get("payload_variant"),
                        request_raw=f.get("request_raw"),
                        response_raw=f.get("response_raw"),
                        response_evidence=f.get("response_evidence"),
                        poc=f.get("poc"),
                        description=f.get("description"),
                        remediation=f.get("remediation"),
                    )
                    db.add(vuln)

                # 检查是否被取消
                if task.status == "cancelled":
                    return
                task.total_vulns = len(findings)
                task.status = "completed"
                task.completed_at = datetime.utcnow()
                await db.commit()

                await progress_callback({
                    "type": "scan_complete",
                    "total_vulns": len(findings),
                    "total_endpoints": task.total_endpoints,
                })

            except Exception as e:
                logger.error(f"扫描失败: {task_id} - {e}")
                task.status = "failed"
                await db.commit()
                await progress_callback({
                    "type": "scan_error",
                    "error": str(e),
                })
                raise

    asyncio.run(_run())
