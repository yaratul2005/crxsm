<?php
/**
 * CRXSM API Gateway
 */

header('Content-Type: application/json; charset=utf-8');

// 1. Setup Autoloader for Vault Classes
spl_autoload_register(function ($class) {
    $prefix = 'Vault\\';
    $base_dir = dirname(__DIR__) . '/Vault/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});

use Vault\DB;
use Vault\Crypto;
use Vault\Audit;

// Helper to get custom headers
function getHeader(string $name): ?string {
    $normalized = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    if (isset($_SERVER[$normalized])) {
        return $_SERVER[$normalized];
    }
    if (function_exists('apache_request_headers')) {
        $headers = apache_request_headers();
        foreach ($headers as $k => $v) {
            if (strcasecmp($k, $name) === 0) {
                return $v;
            }
        }
    }
    return null;
}

// Helper to send error response
function sendError(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $message]);
    exit;
}

// 2. Load Config & System Master Key
$configPath = dirname(__DIR__) . '/Vault/config.php';
if (!file_exists($configPath)) {
    sendError(500, "Platform is not installed.");
}
$config = require($configPath);
$masterKey = $config['master_key'] ?? '';

// 3. Extract Headers
$clientId  = getHeader('X-CRXSM-Client-ID');
$signature = getHeader('X-CRXSM-Signature');
$timestamp = getHeader('X-CRXSM-Timestamp');
$nonce     = getHeader('X-CRXSM-Nonce');

if (!$clientId || !$signature || !$timestamp || !$nonce) {
    sendError(400, "Missing required authentication headers (X-CRXSM-Client-ID, X-CRXSM-Signature, X-CRXSM-Timestamp, X-CRXSM-Nonce).");
}

try {
    // 4. Fetch Software Details
    $software = DB::fetch("SELECT * FROM software WHERE client_id = :client_id", [':client_id' => $clientId]);
    if (!$software) {
        sendError(401, "Invalid Client ID.");
    }

    // 5. Rate Limiting Check (60 requests per minute per software)
    $currentWindow = floor(time() / 60);
    $rateLimit = DB::fetch(
        "SELECT * FROM api_rate_limits WHERE client_id = :client_id AND window_start = :window",
        [':client_id' => $clientId, ':window' => $currentWindow]
    );

    if ($rateLimit) {
        if ($rateLimit['request_count'] >= 60) {
            sendError(429, "Rate limit exceeded. Maximum 60 requests per minute.");
        }
        DB::execute(
            "UPDATE api_rate_limits SET request_count = request_count + 1 WHERE id = :id",
            [':id' => $rateLimit['id']]
        );
    } else {
        DB::execute(
            "INSERT INTO api_rate_limits (client_id, window_start, request_count) VALUES (:client_id, :window, 1)",
            [':client_id' => $clientId, ':window' => $currentWindow]
        );
    }

    // 6. Signature Freshness Check (5 minutes)
    if (abs(time() - (int)$timestamp) > 300) {
        sendError(400, "Request timestamp expired.");
    }

    // 7. Nonce Replay Protection
    $nonceExists = DB::fetch(
        "SELECT id FROM used_nonces WHERE client_id = :client_id AND nonce = :nonce",
        [':client_id' => $clientId, ':nonce' => $nonce]
    );
    if ($nonceExists) {
        sendError(400, "Duplicate nonce. Replay attack detected.");
    }

    // Save Nonce
    DB::execute(
        "INSERT INTO used_nonces (client_id, nonce) VALUES (:client_id, :nonce)",
        [':client_id' => $clientId, ':nonce' => $nonce]
    );

    // 8. Decrypt Client Secret using system master key
    $decryptedSecret = Crypto::decryptSecret($software['client_secret'], $masterKey);
    if (!$decryptedSecret) {
        sendError(500, "Security validation failure on host.");
    }

    // 9. Verify Signature
    $rawBody = file_get_contents('php://input');
    if (!Crypto::verifyApiSignature($rawBody, $signature, $decryptedSecret, $timestamp, $nonce)) {
        sendError(401, "Invalid request signature.");
    }

    // 10. Decrypt request body if JSON
    $requestData = json_decode($rawBody, true) ?? [];

    // 11. Route Request
    $action = $_GET['action'] ?? $requestData['action'] ?? '';
    
    switch ($action) {
        case 'validate':
            require __DIR__ . '/validate.php';
            break;
        case 'activate':
            require __DIR__ . '/activate.php';
            break;
        case 'deactivate':
            require __DIR__ . '/deactivate.php';
            break;
        case 'heartbeat':
            require __DIR__ . '/heartbeat.php';
            break;
        default:
            sendError(400, "Invalid action requested.");
    }

    // 12. Garbage Collect Used Nonces (1% probability)
    if (random_int(1, 100) === 1) {
        DB::execute("DELETE FROM used_nonces WHERE created_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
        DB::execute("DELETE FROM api_rate_limits WHERE window_start < :window", [':window' => $currentWindow - 5]);
    }

} catch (Exception $e) {
    sendError(500, "Internal server error: " . $e->getMessage());
}
