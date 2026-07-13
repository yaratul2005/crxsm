<?php
namespace Vault;

class Auth {

    /**
     * Start the PHP session securely if not already started.
     */
    public static function startSession(): void {
        if (session_status() === PHP_SESSION_NONE) {
            // Determine if HTTPS is active
            $secure = isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] === 'on' || $_SERVER['HTTPS'] === 1);
            
            // If behind standard proxy
            if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
                $secure = true;
            }

            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'domain' => '',
                'secure' => $secure,
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
            session_start();
        }
    }

    /**
     * Log in a Customer.
     */
    public static function loginCustomer(int $userId, string $email, string $name): void {
        self::startSession();
        $_SESSION['crxsm_customer'] = [
            'id' => $userId,
            'email' => $email,
            'name' => $name
        ];
    }

    /**
     * Log in an Admin.
     */
    public static function loginAdmin(int $adminId, string $username, string $role): void {
        self::startSession();
        $_SESSION['crxsm_admin'] = [
            'id' => $adminId,
            'username' => $username,
            'role' => $role
        ];
    }

    /**
     * Log out a Customer.
     */
    public static function logoutCustomer(): void {
        self::startSession();
        unset($_SESSION['crxsm_customer']);
    }

    /**
     * Log out an Admin.
     */
    public static function logoutAdmin(): void {
        self::startSession();
        unset($_SESSION['crxsm_admin']);
    }

    /**
     * Check if a Customer is logged in.
     */
    public static function isCustomerLoggedIn(): bool {
        self::startSession();
        return isset($_SESSION['crxsm_customer']['id']);
    }

    /**
     * Check if an Admin is logged in.
     */
    public static function isAdminLoggedIn(): bool {
        self::startSession();
        return isset($_SESSION['crxsm_admin']['id']);
    }

    /**
     * Get details of the current logged-in Customer.
     */
    public static function getCurrentCustomer(): ?array {
        self::startSession();
        return $_SESSION['crxsm_customer'] ?? null;
    }

    /**
     * Get details of the current logged-in Admin.
     */
    public static function getCurrentAdmin(): ?array {
        self::startSession();
        return $_SESSION['crxsm_admin'] ?? null;
    }
}
