"""SQL 注入插件单元测试"""
import pytest
from unittest.mock import AsyncMock

from app.scanner.plugins.sqli import SQLiPlugin
from app.scanner.plugins.base import InjectionPoint


class TestSQLiPlugin:
    """SQL 注入检测测试"""

    def test_error_based_detection(self, mock_client, mock_response, injection_point):
        """测试 Error-based 检测：响应包含 MySQL 错误"""
        # 模拟包含 MySQL 错误的响应
        error_body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        mock_client.get.return_value = mock_response(200, error_body)

        plugin = SQLiPlugin(mock_client)
        import asyncio; findings = asyncio.run(plugin.check(injection_point))

        assert len(findings) == 1
        assert findings[0].vuln_type == "sqli"
        assert findings[0].severity == "high"
        assert "mysql" in findings[0].description.lower()

    def test_boolean_blind_detection(self, mock_client, mock_response, injection_point):
        """测试 Boolean-based 盲注：TRUE/FALSE 响应不同"""
        # TRUE: 长响应, FALSE: 短响应
        true_resp = mock_response(200, "A" * 3000)
        false_resp = mock_response(200, "A" * 2000)

        call_count = 0
        async def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return true_resp if call_count % 2 == 1 else false_resp

        mock_client.get.side_effect = side_effect

        plugin = SQLiPlugin(mock_client)
        import asyncio; findings = asyncio.run(plugin.check(injection_point))

        assert len(findings) >= 1

    def test_no_vulnerability_clean(self, mock_client, mock_response, injection_point):
        """测试无漏洞情况：正常响应"""
        mock_client.get.return_value = mock_response(200, "<html>Normal page</html>")

        plugin = SQLiPlugin(mock_client)
        import asyncio; findings = asyncio.run(plugin.check(injection_point))

        assert len(findings) == 0


def run_sync(coro):
    """Helper to run async coroutine synchronously"""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


# Monkey-patch for pytest.run_sync
pytest.run_sync = staticmethod(run_sync)
