"""IDOR (Insecure Direct Object Reference) Payload 库

覆盖范围:
1. 常见 API 端点模式（使用顺序 ID）
2. ID 枚举值列表
3. 响应分析模式 — 确认数据泄露（PII / 账户信息）
4. 辅助函数
"""

# ========== 常见 API 端点模式 ==========
# 使用 {id} 占位符表示 ID 参数位置
IDOR_ENDPOINT_PATTERNS = [
    # 用户相关
    "/api/users/{id}",
    "/api/user/{id}",
    "/api/v1/users/{id}",
    "/api/v1/user/{id}",
    "/api/v2/users/{id}",
    "/api/v2/user/{id}",
    "/users/{id}",
    "/user/{id}",
    "/users/{id}/profile",
    "/user/{id}/profile",
    "/api/profile/{id}",
    "/profile/{id}",
    "/api/users/{id}/details",
    "/api/user/{id}/info",
    "/api/members/{id}",
    "/member/{id}",

    # 订单相关
    "/api/orders/{id}",
    "/api/order/{id}",
    "/api/v1/orders/{id}",
    "/api/v1/order/{id}",
    "/orders/{id}",
    "/order/{id}",
    "/api/orders/{id}/details",
    "/api/order/{id}/items",
    "/api/orders/{id}/status",
    "/api/purchases/{id}",
    "/purchase/{id}",

    # 发票/账单
    "/api/invoices/{id}",
    "/api/invoice/{id}",
    "/api/v1/invoices/{id}",
    "/invoices/{id}",
    "/invoice/{id}",
    "/api/bills/{id}",
    "/api/billing/{id}",
    "/api/payments/{id}",
    "/payment/{id}",

    # 文档/文件
    "/api/documents/{id}",
    "/api/document/{id}",
    "/api/v1/documents/{id}",
    "/documents/{id}",
    "/document/{id}",
    "/api/files/{id}",
    "/file/{id}",
    "/api/documents/{id}/download",
    "/api/documents/{id}/view",
    "/api/files/{id}/download",

    # 账户
    "/api/accounts/{id}",
    "/api/account/{id}",
    "/api/v1/accounts/{id}",
    "/accounts/{id}",
    "/account/{id}",
    "/api/accounts/{id}/details",
    "/api/accounts/{id}/balance",
    "/api/accounts/{id}/transactions",
    "/api/wallet/{id}",
    "/wallet/{id}",

    # 帖子/内容
    "/api/posts/{id}",
    "/api/post/{id}",
    "/api/v1/posts/{id}",
    "/posts/{id}",
    "/post/{id}",
    "/api/articles/{id}",
    "/article/{id}",
    "/api/messages/{id}",
    "/api/message/{id}",
    "/messages/{id}",
    "/message/{id}",
    "/api/comments/{id}",
    "/comment/{id}",

    # 工单/支持
    "/api/tickets/{id}",
    "/api/ticket/{id}",
    "/tickets/{id}",
    "/ticket/{id}",
    "/api/support/tickets/{id}",
    "/api/tickets/{id}/details",

    # 地址
    "/api/addresses/{id}",
    "/api/address/{id}",
    "/addresses/{id}",
    "/address/{id}",

    # 购物车
    "/api/carts/{id}",
    "/api/cart/{id}",
    "/cart/{id}",
    "/api/carts/{id}/items",

    # 订阅
    "/api/subscriptions/{id}",
    "/api/subscription/{id}",
    "/subscriptions/{id}",
    "/subscription/{id}",

    # 报告
    "/api/reports/{id}",
    "/api/report/{id}",
    "/reports/{id}",
    "/report/{id}",
]

# ========== ID 枚举值列表 ==========
# 按探测优先级排序
ID_VALUES = [
    # 基础序号 — 最常见
    1,
    2,
    3,
    4,
    5,
    # 跳跃序号 — 测试随机访问
    10,
    20,
    50,
    100,
    101,
    200,
    500,
    1000,
    1001,
    9999,
    # 特殊值
    0,       # 有时索引从 0 开始
    -1,      # 负数可能触发异常行为
]

# ========== 响应分析模式 — JSON 字段 ==========
# 检测响应 JSON 中是否包含 PII / 账户数据
JSON_PII_FIELDS = [
    # 个人信息
    "username",
    "user_name",
    "name",
    "fullname",
    "full_name",
    "realname",
    "real_name",
    "nickname",
    "nick_name",
    "display_name",
    "first_name",
    "last_name",
    "gender",
    "birthday",
    "birth_date",
    "date_of_birth",
    "age",

    # 联系方式
    "email",
    "e_mail",
    "email_address",
    "phone",
    "phone_number",
    "mobile",
    "mobile_phone",
    "tel",
    "telephone",
    "contact",
    "wechat",
    "qq",

    # 敏感凭据
    "password",
    "passwd",
    "pass",
    "hash",
    "password_hash",
    "pin",
    "secret",
    "token",
    "api_key",
    "api_token",

    # 身份标识
    "ssn",
    "social_security",
    "id_card",
    "id_number",
    "identity",
    "passport",
    "passport_number",
    "national_id",
    "driver_license",

    # 地址
    "address",
    "addr",
    "street",
    "city",
    "state",
    "province",
    "country",
    "zip",
    "zipcode",
    "zip_code",
    "postal_code",
    "location",

    # 财务
    "credit_card",
    "credit_card_number",
    "card_number",
    "bank_account",
    "bank_card",
    "balance",
    "salary",
    "income",
    "amount",
    "price",
    "total",

    # 账户信息
    "role",
    "permission",
    "is_admin",
    "is_active",
    "status",
    "created_at",
    "updated_at",
    "last_login",
    "login_time",
    "register_date",
    "ip_address",
]

# ========== 响应分析模式 — HTML 内容特征 ==========
# 检测响应 HTML 中是否包含用户相关页面
HTML_PII_PATTERNS = [
    "profile",
    "account settings",
    "account setting",
    "user info",
    "user information",
    "personal info",
    "personal information",
    "my account",
    "account details",
    "dashboard",
    "settings",
    "edit profile",
    "user profile",
    "member profile",
    "order detail",
    "order details",
    "order info",
    "purchase history",
    "invoice",
    "billing",
    "payment method",
    "saved cards",
    "address book",
    "shipping address",
    "security settings",
    "privacy settings",
]

# ========== 响应分析模式 — 订单/发票特征 ==========
ORDER_PII_PATTERNS = [
    "order_id",
    "order_number",
    "order_date",
    "order_status",
    "order_total",
    "order_items",
    "shipping_address",
    "billing_address",
    "tracking_number",
    "invoice_number",
    "invoice_date",
    "payment_status",
    "transaction_id",
    "product_name",
    "product_id",
    "quantity",
    "unit_price",
    "total_price",
    "subtotal",
    "tax",
    "discount",
    "coupon",
]


def get_idor_paths() -> list[str]:
    """获取所有 IDOR 探测路径模板

    Returns:
        路径模板列表，使用 {id} 占位符
    """
    return IDOR_ENDPOINT_PATTERNS


def get_id_values() -> list[int]:
    """获取 ID 枚举值列表（按优先级排序）

    Returns:
        用于枚举的 ID 值列表
    """
    return ID_VALUES


def get_paths_for_url(base_url: str, id_value: int) -> list[str]:
    """根据基础 URL 和 ID 值生成完整探测 URL

    Args:
        base_url: 目标基础 URL
        id_value: 要替换的 ID 值

    Returns:
        完整 URL 列表
    """
    urls = []
    for path_template in IDOR_ENDPOINT_PATTERNS:
        path = path_template.replace("{id}", str(id_value))
        full_url = f"{base_url.rstrip('/')}{path}"
        urls.append(full_url)
    return urls


def get_idor_paths_by_category() -> dict[str, list[str]]:
    """按分类获取 IDOR 路径模板

    Returns:
        分类字典，key 为分类名，value 为路径模板列表
    """
    categories = {
        "users": [],
        "orders": [],
        "invoices": [],
        "documents": [],
        "accounts": [],
        "posts": [],
        "tickets": [],
        "addresses": [],
        "carts": [],
        "subscriptions": [],
        "reports": [],
    }

    for path in IDOR_ENDPOINT_PATTERNS:
        path_lower = path.lower()
        for cat in categories:
            if f"/{cat}" in path_lower or f"/api/{cat}" in path_lower:
                categories[cat].append(path)
                break
        else:
            # 归入 users（作为 fallback）
            categories["users"].append(path)

    return categories


def analyze_response_for_pii(body: str, content_type: str = "") -> dict | None:
    """分析响应正文是否包含 PII / 账户数据

    支持 JSON 和 HTML 两种响应格式。
    自动检测 Content-Type 决定使用哪种分析策略。

    Args:
        body: HTTP 响应正文
        content_type: 响应 Content-Type 头（可选）

    Returns:
        如果检测到 PII，返回 {
            "format": "json" | "html" | "text",
            "pii_fields": [匹配到的字段列表],
            "evidence": str,
            "pii_count": int,
        }
        否则返回 None
    """
    if not body or len(body.strip()) == 0:
        return None

    # 根据 Content-Type 决定分析策略
    is_json = (
        "application/json" in content_type.lower()
        or body.strip().startswith("{")
        or body.strip().startswith("[")
    )
    is_html = (
        "text/html" in content_type.lower()
        or "<html" in body[:200].lower()
        or "<!doctype" in body[:200].lower()
    )

    if is_json:
        return _analyze_json_pii(body)
    elif is_html:
        return _analyze_html_pii(body)
    else:
        # 通用检测 — 同时尝试 JSON 和 HTML
        result = _analyze_json_pii(body)
        if result:
            return result
        return _analyze_html_pii(body)


def analyze_response_for_order_data(body: str) -> dict | None:
    """分析响应中是否包含订单/发票数据

    Args:
        body: HTTP 响应正文

    Returns:
        如果检测到订单数据，返回 {"format": str, "order_fields": list, "evidence": str}，否则 None
    """
    if not body:
        return None

    matched = []
    body_lower = body.lower()
    for pattern in ORDER_PII_PATTERNS:
        if pattern.lower() in body_lower:
            matched.append(pattern)

    if matched:
        return {
            "format": "json" if body.strip().startswith(("{", "[")) else "mixed",
            "order_fields": matched,
            "evidence": f"匹配到订单/发票字段: {', '.join(matched[:8])}",
            "field_count": len(matched),
        }

    return None


def compare_idor_responses(responses: dict[int, str]) -> list[dict]:
    """比较不同 ID 的响应，判断是否存在 IDOR

    比较逻辑:
    1. 相同 ID → 不同 ID 的响应正文不同 → 返回了不同数据
    2. 不同 ID 都返回 200 → 未做权限控制
    3. 响应中包含不同的 PII 数据 → 确认数据泄露

    Args:
        responses: {id_value: response_body} 映射

    Returns:
        分析结果列表，每项包含差异详情
    """
    if len(responses) < 2:
        return []

    results = []
    ids = sorted(responses.keys())

    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            id_a = ids[i]
            id_b = ids[j]
            body_a = responses[id_a]
            body_b = responses[id_b]

            # 比较长度差异
            len_diff = abs(len(body_a) - len(body_b))

            # 比较内容差异
            is_different = body_a != body_b

            # 分析各自包含的 PII 字段
            pii_a = analyze_response_for_pii(body_a)
            pii_b = analyze_response_for_pii(body_b)

            if is_different:
                record = {
                    "id_a": id_a,
                    "id_b": id_b,
                    "len_a": len(body_a),
                    "len_b": len(body_b),
                    "len_diff": len_diff,
                    "different": True,
                    "pii_a_count": pii_a.get("pii_count", 0) if pii_a else 0,
                    "pii_b_count": pii_b.get("pii_count", 0) if pii_b else 0,
                }

                # 判断是否两个响应都包含 PII
                if pii_a and pii_b:
                    record["evidence"] = (
                        f"ID {id_a} 和 ID {id_b} 返回了不同的用户数据，"
                        f"各自包含 PII 字段（{pii_a.get('pii_count', 0)} vs {pii_b.get('pii_count', 0)}）"
                    )
                elif pii_a or pii_b:
                    record["evidence"] = (
                        f"ID {id_a} 和 ID {id_b} 响应不同，至少一个包含 PII 数据"
                    )
                else:
                    record["evidence"] = (
                        f"ID {id_a} 和 ID {id_b} 响应内容不同（长度差 {len_diff} 字节），"
                        f"可能返回了不同资源的数据"
                    )

                results.append(record)

    return results


# ====== 内部辅助函数 ======

def _analyze_json_pii(body: str) -> dict | None:
    """检测 JSON 响应中的 PII 字段"""
    body_lower = body.lower()
    matched = []

    for field in JSON_PII_FIELDS:
        # 匹配 JSON 键: "field": value 或 "field":
        field_lower = field.lower()
        if f'"{field_lower}"' in body_lower or f"'{field_lower}'" in body_lower:
            matched.append(field)

    if matched:
        return {
            "format": "json",
            "pii_fields": matched,
            "evidence": f"JSON 响应包含 PII 字段: {', '.join(matched[:10])}",
            "pii_count": len(matched),
        }

    return None


def _analyze_html_pii(body: str) -> dict | None:
    """检测 HTML 响应中的用户相关内容"""
    body_lower = body.lower()
    matched = []

    for pattern in HTML_PII_PATTERNS:
        if pattern.lower() in body_lower:
            matched.append(pattern)

    if matched:
        return {
            "format": "html",
            "pii_fields": matched,
            "evidence": f"HTML 响应包含用户相关特征: {', '.join(matched[:10])}",
            "pii_count": len(matched),
        }

    return None
