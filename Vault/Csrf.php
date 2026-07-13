<?php
namespace Vault;

class Csrf {
    
    /**
     * Get or generate a CSRF token.
     */
    public static function getToken(): string {
        Auth::startSession();
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    /**
     * Generate HTML hidden input field for form.
     */
    public static function getHiddenInput(): string {
        $token = htmlspecialchars(self::getToken(), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="csrf_token" value="' . $token . '">';
    }

    /**
     * Verify a submitted CSRF token.
     */
    public static function verifyToken(?string $token): bool {
        if ($token === null) {
            return false;
        }
        Auth::startSession();
        $stored = $_SESSION['csrf_token'] ?? '';
        if (empty($stored)) {
            return false;
        }
        return hash_equals($stored, $token);
    }

    /**
     * Verify request token from POST/JSON body and exit if invalid.
     */
    public static function verifyOrDie(): void {
        $token = $_POST['csrf_token'] ?? null;
        
        // Check request headers (for JS fetch/ajax calls)
        if ($token === null && isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            $token = $_SERVER['HTTP_X_CSRF_TOKEN'];
        }

        if (!self::verifyToken($token)) {
            http_response_code(403);
            die("CSRF verification failed.");
        }
    }
}
