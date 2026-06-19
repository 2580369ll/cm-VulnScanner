"""WAF 检测器单元测试"""
import pytest

from app.scanner.waf_detector import WAFDetector, WAF_SIGNATURES


class TestWAFDetector:
    """WAF 检测器测试"""

    def test_signatures_loaded(self):
        """验证 WAF 签名库已加载"""
        assert len(WAF_SIGNATURES["headers"]) > 0
        assert len(WAF_SIGNATURES["body"]) > 0
        assert len(WAF_SIGNATURES["status_codes"]) > 0

    def test_aliyun_waf_detection(self, mock_client, mock_response):
        """测试阿里云 WAF 检测"""
        resp = mock_response(
            200,
            "Request blocked",
            {"X-CDN": "aliyun"}
        )
        mock_client.get.return_value = resp

        detector = WAFDetector(mock_client)
        import asyncio
        result = asyncio.run(detector.detect("http://test.local/"))

        assert result.get("name") == "阿里云CDN"

    def test_no_waf(self, mock_client, mock_response):
        """测试无 WAF 情况"""
        resp = mock_response(200, "<html>OK</html>", {"Server": "nginx"})
        mock_client.get.return_value = resp

        detector = WAFDetector(mock_client)
        import asyncio
        result = asyncio.run(detector.detect("http://test.local/"))

        assert result == {}
