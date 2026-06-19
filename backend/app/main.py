"""FastAPI 应用入口"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models import init_db
from app.auth import AuthMiddleware, SECRET_TOKEN
from app.api.tasks import router as tasks_router
from app.api.results import router as results_router
from app.api.websocket import router as ws_router


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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 认证中间件
app.add_middleware(AuthMiddleware)

# 注册路由
app.include_router(tasks_router, prefix="/api")
app.include_router(results_router, prefix="/api")
app.include_router(ws_router, prefix="/ws")


@app.get("/api/health")
async def health_check():
    """健康检查 — 无需认证"""
    return {"status": "ok", "app": settings.app_name}


@app.post("/api/auth/login")
async def login(data: dict):
    """简单登录：验证 Token"""
    token = data.get("token", "")
    if token == SECRET_TOKEN:
        return {"success": True, "token": token}
    return {"success": False, "detail": "Token 无效"}
