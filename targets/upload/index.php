<?php
/**
 * 文件上传漏洞靶场
 *
 * 包含多种绕过场景：
 * 1. 无过滤直接上传
 * 2. 仅检查 Content-Type
 * 3. 黑名单扩展名
 */

$upload_dir = __DIR__ . '/uploads/';
if (!is_dir($upload_dir)) mkdir($upload_dir, 0755, true);

$message = '';
$uploaded_files = [];

// 获取已上传的文件
foreach (glob($upload_dir . '*') as $file) {
    $uploaded_files[] = [
        'name' => basename($file),
        'url' => '/uploads/' . basename($file),
        'size' => filesize($file),
    ];
}

// 处理上传
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $filename = $file['name'];
    $tmp_name = $file['tmp_name'];
    $file_type = $file['type'];

    // 安全等级选择
    $level = $_POST['level'] ?? 'none';
    $blocked = false;
    $reason = '';

    switch ($level) {
        case 'content_type':
            // 仅检查 Content-Type
            $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
            if (!in_array($file_type, $allowed_types)) {
                $blocked = true;
                $reason = "Content-Type '{$file_type}' 不允许 (仅允许 image/*)";
            }
            break;

        case 'extension_blacklist':
            // 扩展名黑名单
            $blacklist = ['php', 'php5', 'phtml', 'php7', 'asp', 'aspx', 'jsp'];
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            if (in_array($ext, $blacklist)) {
                $blocked = true;
                $reason = "扩展名 '{$ext}' 在黑名单中";
            }
            break;

        case 'magic_bytes':
            // 检查文件头魔数
            $handle = fopen($tmp_name, 'rb');
            $header = fread($handle, 8);
            fclose($handle);

            $allowed_headers = [
                'image/jpeg' => "\xff\xd8\xff",
                'image/png' => "\x89PNG",
                'image/gif' => "GIF89a",
            ];

            $valid_magic = false;
            foreach ($allowed_headers as $type => $magic) {
                if (strpos($header, $magic) === 0) {
                    $valid_magic = true;
                    break;
                }
            }

            if (!$valid_magic) {
                $blocked = true;
                $reason = "文件头魔数校验失败";
            }
            break;

        case 'none':
        default:
            // 无任何过滤
            break;
    }

    if (!$blocked) {
        $dest = $upload_dir . $filename;
        if (move_uploaded_file($tmp_name, $dest)) {
            $message = '<div style="color:green;background:#f0fff0;padding:10px;border-radius:5px;">
                ✅ 文件上传成功！<br>
                文件名: ' . htmlspecialchars($filename) . '<br>
                路径: <a href="/uploads/' . htmlspecialchars($filename) . '">/uploads/' . htmlspecialchars($filename) . '</a>
            </div>';
        } else {
            $message = '<div style="color:red">❌ 文件移动失败</div>';
        }
    } else {
        $message = '<div style="color:red;background:#fff0f0;padding:10px;border-radius:5px;">
            ❌ 文件被拦截<br>
            原因: ' . $reason . '
        </div>';
    }
}

// .htaccess 上传检测
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['htaccess_test'])) {
    $content = $_POST['htaccess_content'] ?? '';
    $result = file_put_contents($upload_dir . '.htaccess', $content);
    $message = $result ? '<div style="color:green">✅ .htaccess 写入成功</div>'
                        : '<div style="color:red">❌ .htaccess 写入失败</div>';
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>文件上传靶场 — VulnScanner Test</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .card { background: #16213e; padding: 20px; margin: 20px 0; border-radius: 8px; border: 1px solid #0f3460; }
        .card h2 { margin-top: 0; color: #53a8b6; }
        input, select, button { padding: 10px; border-radius: 4px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; width: 100%; margin: 5px 0; }
        button { background: #e94560; cursor: pointer; border: none; font-weight: bold; }
        select { cursor: pointer; }
        .file-list { list-style: none; padding: 0; }
        .file-list li { background: #0f3460; padding: 8px; margin: 5px 0; border-radius: 4px; font-family: monospace; }
        a { color: #53a8b6; word-break: break-all; }
        table { width: 100%; }
        td { padding: 5px; }
    </style>
</head>
<body>
    <h1>🧪 文件上传漏洞靶场</h1>
    <p>此靶场用于测试 VulnScanner 的文件上传漏洞检测能力</p>

    <?= $message ?>

    <!-- 文件上传表单 -->
    <div class="card">
        <h2>文件上传</h2>
        <form method="POST" enctype="multipart/form-data">
            <table>
                <tr>
                    <td>安全等级:</td>
                    <td>
                        <select name="level">
                            <option value="none">无过滤</option>
                            <option value="content_type">Content-Type 检查</option>
                            <option value="extension_blacklist">扩展名黑名单</option>
                            <option value="magic_bytes">魔数校验</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td>选择文件:</td>
                    <td><input type="file" name="file"></td>
                </tr>
            </table>
            <button type="submit">上传</button>
        </form>
    </div>

    <!-- 已上传文件列表 -->
    <div class="card">
        <h2>已上传文件</h2>
        <ul class="file-list">
        <?php foreach ($uploaded_files as $f): ?>
            <li>
                📄 <a href="<?= $f['url'] ?>" target="_blank"><?= htmlspecialchars($f['name']) ?></a>
                (<?= number_format($f['size']) ?> bytes)
            </li>
        <?php endforeach; ?>
        <?php if (empty($uploaded_files)): ?>
        <li style="color:#888">暂无上传文件</li>
        <?php endif; ?>
        </ul>
    </div>
</body>
</html>
