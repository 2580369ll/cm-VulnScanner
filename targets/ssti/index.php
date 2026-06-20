<?php
$name = $_GET['name'] ?? '';
$template = $_POST['template'] ?? '';
$message = $_GET['message'] ?? '';
$output = '';
if ($name) {
    $output = str_replace(['{{7*7}}','{{8*8}}','{{7*\'7\'}}','{{config}}','${7*7}','#{7*7}'], ['49','64','7777777','{"DEBUG":true,"SECRET_KEY":"ssti_test"}','49','49'], $name);
}
if ($template) {
    $output = str_replace('${7*7}', '49', $template);
}
if ($message) {
    $output = str_replace('${7*7}', '49', $message);
}
?><!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>SSTI 靶场</title>
<style>*{box-sizing:border-box}body{font-family:-apple-system,sans-serif;max-width:800px;margin:40px auto;padding:20px;background:#1a1a2e;color:#eee}h1{color:#e94560}.card{background:#16213e;padding:20px;margin:20px 0;border-radius:8px;border:1px solid #0f3460}h2{color:#53a8b6}input,button{padding:10px;border-radius:4px;border:1px solid #0f3460;background:#1a1a2e;color:#eee;width:100%;margin:5px 0}button{background:#e94560;cursor:pointer;border:none;font-weight:bold}.result{background:#0a0a1a;padding:15px;border-radius:4px}code{color:#53a8b6}</style></head><body>
<h1>SSTI 模板注入靶场</h1>
<div class="card"><h2>GET name (Twig/Jinja2)</h2><form method="GET"><input name="name" placeholder="{{7*7}}"><button>渲染</button></form></div>
<div class="card"><h2>POST template (Freemarker)</h2><form method="POST"><input name="template" placeholder='${7*7}'><button>渲染</button></form></div>
<div class="card"><h2>GET message (Mako)</h2><form method="GET"><input name="message" placeholder='${7*7}'><button>渲染</button></form></div>
<?php if($output):?><div class="card"><h2>结果:</h2><div class="result"><?=htmlspecialchars($output)?></div></div><?php endif?>
</body></html>
