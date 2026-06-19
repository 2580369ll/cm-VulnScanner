"""Pytest fixtures and helpers for VulnScanner tests"""
import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture
def mock_response():
    """创建一个 mock HTTP 响应"""
    def _make(status=200, text="", headers=None):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.headers = headers or {}
        resp.request = MagicMock()
        resp.request.headers = {}
        resp.request.content = b""
        return resp
    return _make


@pytest.fixture
def mock_client(mock_response):
    """创建一个 mock httpx AsyncClient"""
    client = AsyncMock()
    client.get = AsyncMock()
    client.post = AsyncMock()
    client.request = AsyncMock()
    return client


@pytest.fixture
def injection_point():
    """创建一个标准 SQLi 注入点"""
    from app.scanner.plugins.base import InjectionPoint
    return InjectionPoint(
        url="http://test.local/search",
        method="GET",
        param_name="q",
        param_type="query",
    )
