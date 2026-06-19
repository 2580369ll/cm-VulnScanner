"""简单的 Bearer Token 认证中间件"""

import os

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# 默认 Token，可通过环境变量覆盖
SECRET_TOKEN = os.getenv("SCANNER_TOKEN", "vulnscanner2024")

# 不需要认证的路径
PUBLIC_PATHS = [
    "/api/health",
    "/docs",
    "/openapi.json",
    "/api/auth/login",
]


class AuthMiddleware(BaseHTTPMiddleware):
    """Bearer Token 认证中间件"""

    async def dispatch(self, request: Request, call_next):
        # 允许公开路径和 OPTIONS 请求通过
        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith("/docs") or path.startswith("/openapi"):
            return await call_next(request)

        if request.method == "OPTIONS":
            return await call_next(request)

        # WebSocket 连接也检查 token（通过 query 参数）
        if path.startswith("/ws/"):
            token = request.query_params.get("token", "")
            if token != SECRET_TOKEN:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "WebSocket 认证失败"},
                )
            return await call_next(request)

        # HTTP 请求检查 Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "缺少认证 Token"},
            )

        token = auth_header[7:]  # 去掉 "Bearer " 前缀
        if token != SECRET_TOKEN:
            return JSONResponse(
                status_code=403,
                content={"detail": "Token 无效"},
            )

        return await call_next(request)


@staticmethod
def verify_token(token: str) -> bool:
    """验证 Token 是否有效"""
    return token == SECRET_TOKEN
