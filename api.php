<?php
define('ADMIN_KEY', 'nizwuchi8');

error_reporting(0);

define('DATA_DIR',  __DIR__ . '/data');
define('DATA_FILE', DATA_DIR . '/messages.txt');
define('RATE_FILE', DATA_DIR . '/rate.tmp');
define('JF', defined('JSON_UNESCAPED_UNICODE') ? JSON_UNESCAPED_UNICODE : 0);
define('MAX_NOTES', 5000);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers', 'Content-Type');
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204); exit;
}

/* ---------- 应答 ---------- */
function ok($data = null, $code = 200) {
    http_response_code($code);
    $r = array('ok' => true);
    if ($data !== null) $r['data'] = $data;
    echo json_encode($r, JF);
    exit;
}
function fail($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(array('ok' => false, 'error' => $msg), JF);
    exit;
}

/* ---------- 初始化存储 ---------- */
if (!is_dir(DATA_DIR))   { @mkdir(DATA_DIR, 0755, true); }
if (!is_file(DATA_FILE)) { @file_put_contents(DATA_FILE, ''); }
if (!is_file(DATA_FILE) || !is_writable(DATA_FILE)) {
    fail('存储文件不可写：请在主机面板手动创建 data 目录并设为可写权限（755/775/777 视主机而定）', 500);
}

/* ---------- 文件读写（带锁，并发安全） ---------- */
function readFromHandle($h) {
    $list = array();
    while (($line = fgets($h, 65536)) !== false) {
        $line = trim($line);
        if ($line === '') continue;
        $n = json_decode($line, true);
        if (is_array($n) && isset($n['id'], $n['text'])) $list[] = $n;   /* 损坏行自动跳过 */
    }
    return $list;
}
function readAll() {
    $h = @fopen(DATA_FILE, 'r');
    if (!$h) return array();
    flock($h, LOCK_SH);
    $list = readFromHandle($h);
    flock($h, LOCK_UN);
    fclose($h);
    return $list;
}
function appendNote($note) {
    $json = json_encode($note, JF);
    if ($json === false) return false;
    return @file_put_contents(DATA_FILE, $json . "\n", FILE_APPEND | LOCK_EX) !== false;
}
function mutate($fn) {
    $h = @fopen(DATA_FILE, 'c+');
    if (!$h) { fail('无法打开存储文件', 500); }
    flock($h, LOCK_EX);
    $list = readFromHandle($h);
    $ret  = call_user_func($fn, $list);        /* 返回 array(新列表, 结果) */
    ftruncate($h, 0);
    rewind($h);
    foreach ($ret[0] as $n) { fwrite($h, json_encode($n, JF) . "\n"); }
    fflush($h);
    flock($h, LOCK_UN);
    fclose($h);
    return $ret[1];
}

/* ---------- 工具 ---------- */
function cleanText($s, $max) {
    $s = str_replace(array("\r\n", "\r"), "\n", (string)$s);
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $s);
    if (function_exists('mb_substr')) {
        $s = mb_substr($s, 0, $max, 'UTF-8');
    } else if (preg_match('/^(.{0,' . (int)$max . '})/us', $s, $m)) {
        $s = $m[1];
    }
    return trim($s);
}
function newId() {
    if (function_exists('random_bytes'))                { return bin2hex(random_bytes(16)); }
    if (function_exists('openssl_random_pseudo_bytes')) { return bin2hex(openssl_random_pseudo_bytes(16)); }
    return md5(uniqid('', true) . mt_rand());
}
function tooFast($ip) {
    $h = @fopen(RATE_FILE, 'c+');
    if (!$h) return false;
    flock($h, LOCK_EX);
    rewind($h);
    $raw  = trim((string)stream_get_contents($h));
    $now  = round(microtime(true) * 1000);
    $fast = false;
    if ($raw !== '' && strpos($raw, '|') !== false) {
        list($savedIp, $savedTs) = explode('|', $raw, 2);
        if ($savedIp === $ip && ($now - (int)$savedTs) < 1000) { $fast = true; }
    }
    if (!$fast) {
        ftruncate($h, 0); rewind($h);
        fwrite($h, $ip . '|' . $now);
        fflush($h);
    }
    flock($h, LOCK_UN);
    fclose($h);
    return $fast;
}

/* ---------- 权限：管理员口令（时间恒定比较） ---------- */
function safeEqual($a, $b) {
    if (function_exists('hash_equals')) return hash_equals((string)$a, (string)$b);
    $a = (string)$a; $b = (string)$b;
    if (strlen($a) !== strlen($b)) return false;
    $r = 0;
    for ($i = 0; $i < strlen($a); $i++) { $r |= ord($a[$i]) ^ ord($b[$i]); }
    return $r === 0;
}
function checkAdmin($token) {
    return is_string($token) && $token !== '' && safeEqual(ADMIN_KEY, $token);
}
function needAdmin($b) {   /* 取出 token，不是管理员直接 403 */
    $t = isset($b['token']) ? (string)$b['token'] : '';
    if (!checkAdmin($t)) fail('只有管理员可以执行此操作', 403);
}

/* ---------- 路由 ---------- */
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

if ($method === 'GET')     { ok(readAll()); }
if ($method !== 'POST')    { fail('不支持的请求方法', 405); }

$raw = file_get_contents('php://input');
if ($raw !== false && strlen($raw) > 16384) { fail('请求体过大', 413); }
$b = ($raw === false || $raw === '') ? array() : json_decode($raw, true);
if (!is_array($b)) { fail('请求不是合法 JSON', 400); }
$action = isset($b['action']) ? (string)$b['action'] : '';

/* --- 验证口令 --- */
if ($action === 'auth') {
    $t = isset($b['token']) ? (string)$b['token'] : '';
    ok(array('admin' => checkAdmin($t)));
}

/* --- 新增：任何人 --- */
if ($action === 'add') {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '?';
    if (tooFast($ip))                  { fail('贴得太快啦，歇一秒再发', 429); }
    if (count(readAll()) >= MAX_NOTES) { fail('墙已贴满（上限 ' . MAX_NOTES . ' 条）', 507); }
    $text = cleanText(isset($b['text']) ? $b['text'] : '', 300);
    if ($text === '')                  { fail('留言不能为空', 422); }
    $note = array(
        'id'     => newId(),
        'name'   => cleanText(isset($b['name']) ? $b['name'] : '', 12),
        'text'   => $text,
        'ts'     => (int)round(microtime(true) * 1000),
        'pinned' => false,
    );
    if (!appendNote($note)) { fail('写入存储文件失败，请检查 data 目录权限', 500); }
    ok($note, 201);
}

/* --- 置顶 / 取钉：仅管理员 --- */
if ($action === 'pin') {
    needAdmin($b);
    $id  = isset($b['id']) ? substr((string)$b['id'], 0, 64) : '';
    $pin = !empty($b['pinned']);
    $res = mutate(function ($list) use ($id, $pin) {
        foreach ($list as $i => $n) {
            if ($n['id'] === $id) {
                $n['pinned'] = $pin;
                $list[$i] = $n;
                return array($list, $n);
            }
        }
        return array($list, 'miss');
    });
    if ($res === 'miss') { fail('这张便签不存在，也许刚被撕掉了', 404); }
    ok($res);
}

/* --- 删除单条：仅管理员 --- */
if ($action === 'del') {
    needAdmin($b);
    $id = isset($b['id']) ? substr((string)$b['id'], 0, 64) : '';
    $res = mutate(function ($list) use ($id) {
        foreach ($list as $i => $n) {
            if ($n['id'] === $id) {
                array_splice($list, $i, 1);
                return array($list, true);
            }
        }
        return array($list, 'miss');
    });
    if ($res === 'miss') { fail('这张便签不存在，也许刚被撕掉了', 404); }
    ok();
}

/* --- 回复留言：仅管理员（空文本 = 移除回复） --- */
if ($action === 'reply') {
    needAdmin($b);
    $id   = isset($b['id']) ? substr((string)$b['id'], 0, 64) : '';
    $text = cleanText(isset($b['text']) ? $b['text'] : '', 300);
    $res = mutate(function ($list) use ($id, $text) {
        foreach ($list as $i => $n) {
            if ($n['id'] === $id) {
                if ($text === '') {
                    unset($n['reply'], $n['replyTs']);   /* 移除回复 */
                } else {
                    $n['reply']   = $text;               /* 新增或覆盖 */
                    $n['replyTs'] = (int)round(microtime(true) * 1000);
                }
                $list[$i] = $n;
                return array($list, $n);
            }
        }
        return array($list, 'miss');
    });
    if ($res === 'miss') { fail('这张便签不存在，也许刚被撕掉了', 404); }
    ok($res);
}

/* --- 清空：仅管理员 --- */
if ($action === 'clear') {
    needAdmin($b);
    mutate(function ($list) { return array(array(), true); });
    ok();
}

fail('接口不存在', 404);