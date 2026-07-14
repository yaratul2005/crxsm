<?php
/**
 * CRXSM Automated Unit Test Runner
 */

header('Content-Type: text/plain; charset=utf-8');

echo "==================================================\n";
echo "       CRXSM AUTOMATED TEST SUITE RUNNER           \n";
echo "==================================================\n\n";

// 1. Setup Autoloader for Vault Classes
spl_autoload_register(function ($class) {
    $prefix = 'Vault\\';
    $base_dir = dirname(dirname(__DIR__)) . '/Vault/';
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
use Vault\Auth;
use Vault\Csrf;

$passes = 0;
$fails = 0;

function assertTest(string $name, bool $expression): void {
    global $passes, $fails;
    if ($expression) {
        echo "[ PASSED ] - $name\n";
        $passes++;
    } else {
        echo "[ FAILED ] - $name\n";
        $fails++;
    }
}

// ----------------------------------------------------
// TEST GROUP 1: Cryptography & Key Management
// ----------------------------------------------------
echo "--- Running Cryptography Tests ---\n";
try {
    // A. Keypair generation
    $keypair = Crypto::generateKeyPair();
    assertTest("Ed25519 Keypair generation has public key", !empty($keypair['public_key']));
    assertTest("Ed25519 Keypair generation has private key", !empty($keypair['private_key']));

    // B. License signing & validation
    $payload = [
        'license_id' => 999,
        'software_id' => 1,
        'user_id' => 5,
        'expires_at' => '2026-12-31'
    ];
    $token = Crypto::generateLicenseKey($payload, $keypair['private_key']);
    assertTest("License key token is generated (format: payload.sig)", strpos($token, '.') !== false);

    $verifiedPayload = Crypto::verifyLicenseKey($token, $keypair['public_key']);
    assertTest("Valid license key signature matches expected payload", $verifiedPayload !== false && $verifiedPayload['license_id'] === 999);

    // C. Tampered key checks
    $tamperedToken = $token . "a"; // append character to corrupt signature
    $tamperedVerification = Crypto::verifyLicenseKey($tamperedToken, $keypair['public_key']);
    assertTest("Tampered license key signature returns false", $tamperedVerification === false);

    // D. Credential Encryption at Rest (AES-256-CBC)
    $systemMasterKey = bin2hex(random_bytes(32));
    $rawSecret = "my_super_secret_api_key_12345!";
    $cipherText = Crypto::encryptSecret($rawSecret, $systemMasterKey);
    assertTest("Secret AES Encryption doesn't return empty", !empty($cipherText) && $cipherText !== $rawSecret);

    $decryptedText = Crypto::decryptSecret($cipherText, $systemMasterKey);
    assertTest("AES Decryption returns correct original plain secret", $decryptedText === $rawSecret);

    $decryptedWithWrongKey = Crypto::decryptSecret($cipherText, bin2hex(random_bytes(32)));
    assertTest("Decrypting AES with wrong master key fails/returns false", $decryptedWithWrongKey === false || $decryptedWithWrongKey === null);

} catch (Exception $e) {
    assertTest("Crypto tests raised unexpected exception: " . $e->getMessage(), false);
}

echo "\n";

// ----------------------------------------------------
// TEST GROUP 2: API HMAC Verification
// ----------------------------------------------------
echo "--- Running API HMAC Request Verification Tests ---\n";
try {
    $secret = "sw_secret_xyz123";
    $timestamp = (string)time();
    $nonce = bin2hex(random_bytes(8));
    $postBody = json_encode(['action' => 'activate', 'license_key' => 'token123']);

    // Generate valid client signature
    $dataToSign = $timestamp . '.' . $nonce . '.' . $postBody;
    $clientSignature = hash_hmac('sha256', $dataToSign, $secret);

    // Server verification
    $verified = Crypto::verifyApiSignature($postBody, $clientSignature, $secret, $timestamp, $nonce);
    assertTest("Valid API request HMAC signature verification succeeds", $verified === true);

    // Tampered body verification
    $tamperedBody = $postBody . " ";
    $verifiedTampered = Crypto::verifyApiSignature($tamperedBody, $clientSignature, $secret, $timestamp, $nonce);
    assertTest("Tampered request body is rejected", $verifiedTampered === false);

} catch (Exception $e) {
    assertTest("API HMAC tests raised exception: " . $e->getMessage(), false);
}

echo "\n";

// ----------------------------------------------------
// TEST GROUP 3: Database & ORM Integrations
// ----------------------------------------------------
echo "--- Running Database CRUD Tests ---\n";
try {
    $conn = DB::getConn();
    assertTest("PDO Connection is active and loaded", $conn instanceof PDO);

    // Insert dummy configuration setting
    $inserted = DB::execute(
        "INSERT INTO settings (setting_key, setting_value) VALUES (:key, :val)",
        [':key' => 'test_suite_key', ':val' => 'working']
    );
    assertTest("Database INSERT query execution succeeds", $inserted === true);

    $row = DB::fetch("SELECT setting_value FROM settings WHERE setting_key = 'test_suite_key'");
    assertTest("Database SELECT statement fetches inserted row values correctly", $row !== null && $row['setting_value'] === 'working');

    // Clean up
    DB::execute("DELETE FROM settings WHERE setting_key = 'test_suite_key'");
    $cleaned = DB::fetch("SELECT id FROM settings WHERE setting_key = 'test_suite_key'");
    assertTest("Database DELETE statement removes test row", $cleaned === null);

    // ----------------------------------------------------
    // TEST GROUP 4: CAPTCHA Service
    // ----------------------------------------------------
    echo "\n--- Running CAPTCHA Service Tests ---\n";
    // Force set settings for testing
    DB::execute("DELETE FROM settings WHERE setting_key = 'captcha_enabled'");
    DB::execute("INSERT INTO settings (setting_key, setting_value) VALUES ('captcha_enabled', '1')");
    DB::execute("DELETE FROM settings WHERE setting_key = 'captcha_provider'");
    DB::execute("INSERT INTO settings (setting_key, setting_value) VALUES ('captcha_provider', 'local')");

    assertTest("CAPTCHA Service correctly detects enabled status", \Vault\Captcha::isActive() === true);

    // Test math challenge generation
    $html = \Vault\Captcha::render();
    assertTest("Math CAPTCHA outputs challenge input markup", strpos($html, 'crxsm_captcha_answer') !== false);
    assertTest("Math CAPTCHA registers answer in session", isset($_SESSION['crxsm_captcha_answer']));

    // Verify correct submission
    $_POST['crxsm_captcha_answer'] = $_SESSION['crxsm_captcha_answer'];
    assertTest("CAPTCHA verifies correct mathematical answer", \Vault\Captcha::verify() === true);

    // Verify incorrect submission
    $_SESSION['crxsm_captcha_answer'] = 15;
    $_POST['crxsm_captcha_answer'] = 99;
    assertTest("CAPTCHA rejects incorrect mathematical answer", \Vault\Captcha::verify() === false);

    // Clean up
    DB::execute("DELETE FROM settings WHERE setting_key IN ('captcha_enabled', 'captcha_provider')");


    // ----------------------------------------------------
    // TEST GROUP 5: Support Tickets & Messages
    // ----------------------------------------------------
    echo "\n--- Running Support Tickets Tests ---\n";
    $token = 'tk_test_suite_12345';
    
    // Clean potential previous tests
    DB::execute("DELETE FROM support_tickets WHERE ticket_token = ?", [$token]);

    // Create ticket
    DB::execute("
        INSERT INTO support_tickets (ticket_token, name, email, subject, status)
        VALUES (?, 'Test User', 'test@test.com', 'Test Subject', 'open')
    ", [$token]);

    $ticket = DB::fetch("SELECT * FROM support_tickets WHERE ticket_token = ?", [$token]);
    assertTest("Support Ticket is inserted and retrievable via token", $ticket !== null && $ticket['subject'] === 'Test Subject');

    $ticketId = (int)$ticket['id'];

    // Insert Message
    DB::execute("
        INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message)
        VALUES (?, 'customer', 'Test User', 'Initial message details')
    ", [$ticketId]);

    $message = DB::fetch("SELECT * FROM ticket_messages WHERE ticket_id = ?", [$ticketId]);
    assertTest("Ticket messages are logged and linked to ticket ID", $message !== null && $message['message'] === 'Initial message details');

    // Admin Reply
    DB::execute("
        INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message)
        VALUES (?, 'admin', 'System Admin', 'Admin Response details')
    ", [$ticketId]);

    // Update status
    DB::execute("UPDATE support_tickets SET status = 'pending' WHERE id = ?", [$ticketId]);

    $updatedTicket = DB::fetch("SELECT status FROM support_tickets WHERE id = ?", [$ticketId]);
    assertTest("Support Ticket status updates succeed", $updatedTicket['status'] === 'pending');

    // Clean up (Foreign Key cascade deletes messages)
    DB::execute("DELETE FROM support_tickets WHERE id = ?", [$ticketId]);
    $deletedMessages = DB::fetchAll("SELECT id FROM ticket_messages WHERE ticket_id = ?", [$ticketId]);
    assertTest("Deleting Support Ticket cascades and deletes conversation messages", empty($deletedMessages));

} catch (Exception $e) {
    echo "[ WARNING ] - Database tests skipped because database is not installed or configured yet.\n";
    echo "              Detail: " . $e->getMessage() . "\n";
}

echo "\n";
echo "==================================================\n";
echo "SUMMARY: Passes: $passes | Fails: $fails\n";
echo "==================================================\n";

if ($fails > 0) {
    exit(1);
} else {
    exit(0);
}
