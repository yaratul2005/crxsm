<?php
namespace Vault;

use Exception;

class Storage {

    /**
     * Get the configured upload directory.
     * Fallback to Vault/uploads/ inside the project root and secure it.
     */
    public static function getUploadDir(): string {
        $configPath = dirname(__FILE__) . '/config.php';
        $uploadDir = null;

        if (file_exists($configPath)) {
            $config = require($configPath);
            $uploadDir = $config['storage']['upload_dir'] ?? null;
        }

        if (empty($uploadDir)) {
            // Default to Vault/uploads
            $uploadDir = dirname(__FILE__) . '/uploads';
        }

        if (!is_dir($uploadDir)) {
            if (!mkdir($uploadDir, 0755, true)) {
                throw new Exception("Failed to create upload directory: " . $uploadDir);
            }
        }

        // Write security files in the upload folder
        self::secureDirectory($uploadDir);

        return realpath($uploadDir);
    }

    /**
     * Secure the upload folder by creating htaccess and index.html files.
     */
    private static function secureDirectory(string $dir): void {
        // 1. Write .htaccess to disable all script execution
        $htaccessFile = $dir . '/.htaccess';
        if (!file_exists($htaccessFile)) {
            $htaccessContent = <<<EOT
# CRXSM Security - Disable execution of scripts
<Files *>
    SetHandler default-handler
</Files>
RemoveHandler .php .phtml .php3 .php4 .php5 .php6 .php7 .php8 .phps .pl .py .pyc .pyo .jsp .asp .aspx .shtml .sh .cgi
Options -ExecCGI -Indexes
EOT;
            @file_put_contents($htaccessFile, $htaccessContent);
        }

        // 2. Write index.html to prevent folder indexing listing fallback
        $indexFile = $dir . '/index.html';
        if (!file_exists($indexFile)) {
            @file_put_contents($indexFile, 'Access denied.');
        }
    }

    /**
     * Handle upload of a zip version file.
     * Returns the local file path on success.
     */
    public static function uploadVersionFile(array $fileVar, string $softwareSlug, string $version): string {
        if ($fileVar['error'] !== UPLOAD_ERR_OK) {
            throw new Exception("File upload failed with error code: " . $fileVar['error']);
        }

        $fileName = $fileVar['name'];
        $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        // Enforce strict file extension
        if ($ext !== 'zip') {
            throw new Exception("Invalid file type. Only .zip files are allowed.");
        }

        // Enforce safe size limits (e.g. 50MB max)
        $maxSize = 50 * 1024 * 1024; // 50MB
        if ($fileVar['size'] > $maxSize) {
            throw new Exception("File exceeds maximum upload size (50MB).");
        }

        $uploadDir = self::getUploadDir();
        
        // Formulate safe obfuscated filename
        $safeVersion = preg_replace('/[^a-zA-Z0-9.-]/', '', $version);
        $obfuscatedName = $softwareSlug . '_' . $safeVersion . '_' . bin2hex(random_bytes(16)) . '.zip';
        $destPath = $uploadDir . '/' . $obfuscatedName;

        if (!move_uploaded_file($fileVar['tmp_name'], $destPath)) {
            throw new Exception("Failed to save uploaded file.");
        }

        return $destPath;
    }

    /**
     * Securely stream a file to the browser.
     */
    public static function serveFile(string $filePath, string $originalName): void {
        if (!file_exists($filePath)) {
            http_response_code(404);
            die("Requested file not found.");
        }

        // Clear output buffers
        while (ob_get_level()) {
            ob_end_clean();
        }

        // Set headers for secure file stream download
        header('Content-Description: File Transfer');
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . basename($originalName) . '"');
        header('Content-Transfer-Encoding: binary');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        header('Content-Length: ' . filesize($filePath));

        readfile($filePath);
        exit;
    }
}
