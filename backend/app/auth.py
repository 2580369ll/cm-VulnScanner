"""JWT Bearer Token 认证中间件"""

import os
import time
import jwt

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# JWT 配置
JWT_SECRET = os.getenv("JWT_SECRET", "vulnscanner-jwt-secret-change-me")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

# 不需要认证的路径
PUBLIC_PATHS = [
    "/api/health",
    "/docs",
    "/openapi.json",
    "/api/auth/login",
]


def create_token() -> str:
    """生成 JWT Token，24 小时过期"""
    payload = {
        "exp": int(time.time()) + TOKEN_EXPIRE_HOURS * 3600,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> bool:
    """验证 JWT Token 有效性"""
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False


class AuthMiddleware(BaseHTTPMiddleware):
    """JWT Bearer Token 认证中间件"""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # 公开路径放行
        if path in PUBLIC_PATHS or path.startswith("/docs") or path.startswith("/openapi"):
            return await call_next(request)
        if request.method == "OPTIONS":
            return await call_next(request)

        # WebSocket: token 通过 query 参数传递
        if path.startswith("/ws/"):
            token = request.query_params.get("token", "")
            if not verify_token(token):
                return JSONResponse(status_code=403, content={"detail": "WebSocket 认证失败"})
            return await call_next(request)

        # HTTP: Bearer Token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "缺少认证 Token"})

        token = auth_header[7:]
        if not verify_token(token):
            return JSONResponse(status_code=403, content={"detail": "Token 无效或已过期"})

        return await call_next(request)
