"""Web 爬虫 — 发现注入点（链接、表单、文件上传入口）"""

import asyncio
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.scanner.plugins.base import InjectionPoint


class Crawler:
    """轻量级爬虫：爬取同域页面，提取注入点"""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_domain: str,
        max_depth: int = 3,
        max_pages: int = 50,
    ):
        self.client = client
        self.base_domain = base_domain
        self.max_depth = max_depth
        self.max_pages = max_pages

        self.visited: set[str] = set()
        self.injection_points: list[InjectionPoint] = []

    async def crawl(self, start_url: str) -> list[InjectionPoint]:
        """从起始 URL 开始爬取"""
        to_visit: list[tuple[str, int]] = [(start_url, 0)]

        while to_visit and len(self.visited) < self.max_pages:
            url, depth = to_visit.pop(0)

            if url in self.visited:
                continue
            if depth > self.max_depth:
                continue
            if not self._is_same_domain(url):
                continue

            self.visited.add(url)

            try:
                response = await self.client.get(url)
                if response.status_code != 200:
                    continue

                html = response.text
                soup = BeautifulSoup(html, "lxml")

                # 1) 提取页面中的表单注入点
                self._extract_forms(soup, url)

                # 2) 提取页面中的链接（同域）
                if depth < self.max_depth:
                    new_links = self._extract_links(soup, url)
                    for link in new_links:
                        if link not in self.visited:
                            to_visit.append((link, depth + 1))

                # 3) URL 参数注入点
                self._extract_url_params(url)

                # 4) JSON API 端点注入点
                self._extract_api_endpoints(soup, url)

            except Exception:
                continue

            # 礼貌性延迟
            await asyncio.sleep(0.3)

        return self.injection_points

    def _is_same_domain(self, url: str) -> bool:
        """检查是否同域"""
        try:
            return urlparse(url).netloc == self.base_domain
        except Exception:
            return False

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        """提取页面中的所有表单"""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "GET") or "GET").upper()
            form_url = urljoin(page_url, action) if action else page_url
            if not self._is_same_domain(form_url):
                continue

            inputs = []
            has_file = False

            for inp in form.find_all("input"):
                inp_name = inp.get("name", "")
                inp_type = inp.get("type", "text")

                if inp_type == "file":
                    has_file = True
                    self.injection_points.append(InjectionPoint(
                        url=form_url,
                        method="POST",
                        param_name=inp_name,
                        param_type="file",
                        form_action=form_url,
                        form_inputs=[{
                            "name": i.get("name", ""),
                            "type": i.get("type", "text"),
                        } for i in form.find_all("input")],
                    ))

                if inp_name:
                    inputs.append({"name": inp_name, "type": inp_type})

            # 非文件上传表单：每个输入字段都是一个注入点
            if not has_file and inputs:
                for inp in inputs:
                    if inp["type"] not in ("submit", "button", "image", "hidden"):
                        self.injection_points.append(InjectionPoint(
                            url=form_url,
                            method=method,
                            param_name=inp["name"],
                            param_type="body",
                            form_action=form_url,
                            form_inputs=inputs,
                        ))

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        """提取页面中的所有同域链接"""
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            # 跳过锚点、javascript、mailto
            if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full_url = urljoin(page_url, href.split("?")[0])  # 去参数
            if self._is_same_domain(full_url) and full_url not in self.visited:
                links.append(full_url)
        return links

    def _extract_url_params(self, url: str):
        """提取 URL 查询参数作为注入点"""
        parsed = urlparse(url)
        if not parsed.query:
            return

        from urllib.parse import parse_qs
        params = parse_qs(parsed.query)

        for param_name, values in params.items():
            self.injection_points.append(InjectionPoint(
                url=url.split("?")[0],
                method="GET",
                param_name=param_name,
                param_type="query",
            ))

    def _extract_api_endpoints(self, soup: BeautifulSoup, page_url: str):
        """从页面 JS 中提取 API 端点"""
        # 查找 fetch/axios/ajax 调用
        scripts = soup.find_all("script")
        for script in scripts:
            if not script.string:
                continue
            import re
            # 匹配常见的 API URL 模式
            patterns = [
                r'["\'](/api/[^"\'\s]+)["\']',
                r'["\'](/v\d+/[^"\'\s]+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, script.string)
                for match in matches:
                    if match.startswith("/"):
                        full_url = urljoin(page_url, match.split("?")[0])
                        if self._is_same_domain(full_url) and "?" in match:
                            self._extract_url_params(urljoin(page_url, match))
