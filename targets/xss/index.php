<?php
/**
 * XSS 跨站脚本漏洞靶场
 *
 * 包含三种 XSS 类型：
 * 1. 反射型 XSS (comment 参数直接输出)
 * 2. 存储型 XSS (留言板)
 * 3. DOM-based XSS (JS 读取 URL hash 写入 innerHTML)
 */

session_start();

// ====== 存储型 XSS: 留言板 ======
$comments_file = __DIR__ . '/comments.json';
$comments = file_exists($comments_file) ? json_decode(file_get_contents($comments_file), true) : [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['name'], $_POST['message'])) {
    $comments[] = [
        'name' => $_POST['name'],
        'message' => $_POST['message'],
        'time' => date('Y-m-d H:i:s'),
    ];
    file_put_contents($comments_file, json_encode($comments, JSON_UNESCAPED_UNICODE));
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ====== 反射型 XSS: 搜索框 ======
$search = $_GET['q'] ?? '';
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>XSS 靶场 — VulnScanner Test</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .card { background: #16213e; padding: 20px; margin: 20px 0; border-radius: 8px; border: 1px solid #0f3460; }
        .card h2 { margin-top: 0; color: #53a8b6; }
        input, textarea, button { padding: 10px; border-radius: 4px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; width: 100%; margin: 5px 0; }
        button { background: #e94560; cursor: pointer; border: none; font-weight: bold; }
        .comment { background: #0f3460; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .comment .meta { font-size: 12px; color: #888; }
        #dom-container { background: #0f3460; padding: 15px; border-radius: 4px; min-height: 30px; }
    </style>
</head>
<body>
    <h1>🧪 XSS 跨站脚本漏洞靶场</h1>
    <p>此靶场用于测试 VulnScanner 的 XSS 检测能力</p>

    <!-- 反射型 XSS: 搜索 -->
    <div class="card">
        <h2>注入点 1: 反射型 XSS (GET q 参数)</h2>
        <form method="GET">
            <input type="text" name="q" placeholder="搜索..." value="<?= htmlspecialchars($search) ?>">
            <button type="submit">搜索</button>
        </form>
        <!-- 漏洞：直接输出用户输入，未做 HTML 编码 -->
        <p>搜索结果: <?= $search ?></p>
    </div>

    <!-- 存储型 XSS: 留言板 -->
    <div class="card">
        <h2>注入点 2: 存储型 XSS (留言板)</h2>
        <form method="POST">
            <input type="text" name="name" placeholder="昵称">
            <textarea name="message" rows="3" placeholder="留言内容..."></textarea>
            <button type="submit">提交留言</button>
        </form>

        <h3>留言列表:</h3>
        <?php foreach (array_reverse($comments) as $comment): ?>
        <div class="comment">
            <!-- 漏洞：直接输出存储的用户输入 -->
            <strong><?= $comment['name'] ?></strong>
            <span class="meta"><?= $comment['time'] ?></span>
            <p><?= $comment['message'] ?></p>
        </div>
        <?php endforeach; ?>
        <?php if (empty($comments)): ?>
        <p style="color:#888">暂无留言</p>
        <?php endif; ?>
    </div>

    <!-- DOM-based XSS -->
    <div class="card">
        <h2>注入点 3: DOM-based XSS (URL hash → innerHTML)</h2>
        <p>在 URL 后添加 #hash，例如: <code>#&lt;img src=x onerror=alert(1)&gt;</code></p>
        <div id="dom-container">等待 hash 输入...</div>
    </div>

    <!-- 危险：location.hash → innerHTML -->
    <script>
    (function() {
        var hash = location.hash.substring(1);
        if (hash) {
            document.getElementById('dom-container').innerHTML = decodeURIComponent(hash);
        }
    })();
    </script>
</body>
</html>
