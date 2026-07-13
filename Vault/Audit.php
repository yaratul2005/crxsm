<?php
namespace Vault;

class Audit {
    
    /**
     * Get the real IP address of the client.
     */
    public static function getIpAddress(): string {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($parts[0]);
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Write an entry to the audit log.
     */
    public static function log(string $userType, ?int $userId, string $action, ?string $details = null): bool {
        $ip = self::getIpAddress();
        
        try {
            $sql = "INSERT INTO audit_log (user_type, user_id, action, ip_address, details) 
                    VALUES (:user_type, :user_id, :action, :ip_address, :details)";
            
            return DB::execute($sql, [
                ':user_type'  => $userType,
                ':user_id'    => $userId,
                ':action'     => $action,
                ':ip_address' => $ip,
                ':details'    => $details
            ]);
        } catch (\Exception $e) {
            // Silently fail or log to standard error log to prevent crashing the main thread
            error_log("Failed to write to audit log: " . $e->getMessage());
            return false;
        }
    }
}
