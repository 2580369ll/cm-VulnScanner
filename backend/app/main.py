"""FastAPI 应用入口"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings
from app.models import init_db
from app.api.tasks import router as tasks_router
from app.api.results import router as results_router
from app.api.websocket import router as ws_router

# 速率限制：每分钟最多 20 次请求
limiter = Limiter(key_func=get_remote_address, default_limits=["20/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期：启动时初始化数据库"""
    await init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="自动化 Web 漏洞扫描器 — SQL注入 / XSS / 文件上传检测",
    lifespan=lifespan,
)

# CORS 中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:8082",
        "http://121.43.231.191:8082",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 速率限制
app.state.limiter = limiter

# 注册路由
app.include_router(tasks_router, prefix="/api")
app.include_router(results_router, prefix="/api")
app.include_router(ws_router, prefix="/ws")


@app.get("/api/health")
async def health_check():
    """健康检查 — 无需认证"""
    return {"status": "ok", "app": settings.app_name}


