<?php
/**
 * One-Time Secret API — Zero-Knowledge Backend
 * Server stores only ciphertext. Never sees plaintext or keys.
 */

// Show errors as JSON, not HTML
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    http_response_code(500);
    echo json_encode(['error' => $errstr, 'line' => $errline]);
    exit;
});

set_exception_handler(function($e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage(), 'line' => $e->getLine()]);
    exit;
});

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

$DB_FILE = __DIR__ . '/model.sqlite';
$MAX_SIZE = 102400; // 100KB
$EXPIRY = 86400;    // 24 hours
$RATE_LIMIT = 20;   // creates per IP per hour

function db() {
    global $DB_FILE;
    static $conn = null;
    if ($conn) return $conn;

    // Check directory is writable before trying to create DB
    $dir = dirname($DB_FILE);
    if (!is_writable($dir)) {
        throw new RuntimeException("Directory $dir is not writable by web server");
    }

    $conn = new SQLite3($DB_FILE);
    $conn->busyTimeout(2000);
    $conn->exec('PRAGMA journal_mode=WAL');
    $conn->exec('CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )');
    $conn->exec('CREATE TABLE IF NOT EXISTS rate_limits (
        ip TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )');
    return $conn;
}

function cleanup() {
    $cutoff = time() - $GLOBALS['EXPIRY'];
    $db = db();
    $db->exec("DELETE FROM secrets WHERE created_at < $cutoff");
    $db->exec("DELETE FROM rate_limits WHERE created_at < " . (time() - 3600));
}

function check_rate_limit($ip) {
    global $RATE_LIMIT;
    $db = db();
    $stmt = $db->prepare('SELECT COUNT(*) FROM rate_limits WHERE ip = :ip AND created_at > :since');
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $stmt->bindValue(':since', time() - 3600, SQLITE3_INTEGER);
    $count = $stmt->execute()->fetchArray()[0];
    return $count < $RATE_LIMIT;
}

function record_rate_limit($ip) {
    $db = db();
    $stmt = $db->prepare('INSERT INTO rate_limits (ip, created_at) VALUES (:ip, :time)');
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $stmt->bindValue(':time', time(), SQLITE3_INTEGER);
    $stmt->execute();
}

cleanup();

$method = $_SERVER['REQUEST_METHOD'];
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// GET — retrieve and delete
if ($method === 'GET' && isset($_GET['id'])) {
    $id = preg_replace('/[^a-f0-9]/', '', $_GET['id']);
    if (strlen($id) !== 32) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid id']);
        exit;
    }
    $db = db();
    $stmt = $db->prepare('SELECT ciphertext, iv FROM secrets WHERE id = :id');
    $stmt->bindValue(':id', $id, SQLITE3_TEXT);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'not found']);
        exit;
    }
    // Delete immediately
    $del = $db->prepare('DELETE FROM secrets WHERE id = :id');
    $del->bindValue(':id', $id, SQLITE3_TEXT);
    $del->execute();
    echo json_encode($row);
    exit;
}

// POST — store
if ($method === 'POST') {
    if (!check_rate_limit($ip)) {
        http_response_code(429);
        echo json_encode(['error' => 'rate limit exceeded, try again later']);
        exit;
    }
    $body = file_get_contents('php://input');
    if (strlen($body) > $MAX_SIZE) {
        http_response_code(413);
        echo json_encode(['error' => 'payload too large (max 100KB)']);
        exit;
    }
    $data = json_decode($body, true);
    if (!$data || empty($data['ciphertext']) || empty($data['iv'])) {
        http_response_code(400);
        echo json_encode(['error' => 'missing ciphertext or iv']);
        exit;
    }
    $id = bin2hex(random_bytes(16));
    $db = db();
    $stmt = $db->prepare('INSERT INTO secrets (id, ciphertext, iv, created_at) VALUES (:id, :ct, :iv, :time)');
    $stmt->bindValue(':id', $id, SQLITE3_TEXT);
    $stmt->bindValue(':ct', $data['ciphertext'], SQLITE3_TEXT);
    $stmt->bindValue(':iv', $data['iv'], SQLITE3_TEXT);
    $stmt->bindValue(':time', time(), SQLITE3_INTEGER);
    $stmt->execute();
    record_rate_limit($ip);
    echo json_encode(['id' => $id]);
    exit;
}

// DELETE — cancel
if ($method === 'DELETE' && isset($_GET['id'])) {
    $id = preg_replace('/[^a-f0-9]/', '', $_GET['id']);
    $db = db();
    $stmt = $db->prepare('DELETE FROM secrets WHERE id = :id');
    $stmt->bindValue(':id', $id, SQLITE3_TEXT);
    $stmt->execute();
    echo json_encode(['ok' => true]);
    exit;
}

http_response_code(405);
echo json_encode(['error' => 'method not allowed']);
