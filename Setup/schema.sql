-- CRXSM Database Schema (MySQL)

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS `api_rate_limits`;
DROP TABLE IF EXISTS `audit_log`;
DROP TABLE IF EXISTS `settings`;
DROP TABLE IF EXISTS `pages`;
DROP TABLE IF EXISTS `posts`;
DROP TABLE IF EXISTS `used_nonces`;
DROP TABLE IF EXISTS `license_activations`;
DROP TABLE IF EXISTS `licenses`;
DROP TABLE IF EXISTS `software_versions`;
DROP TABLE IF EXISTS `software`;
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `admins`;
SET FOREIGN_KEY_CHECKS = 1;

-- 1. Admins Table
CREATE TABLE `admins` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(50) UNIQUE NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `email` VARCHAR(100) UNIQUE NOT NULL,
  `role` VARCHAR(20) DEFAULT 'admin',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Users (Customers) Table
CREATE TABLE `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `email` VARCHAR(100) UNIQUE NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `name` VARCHAR(100) NOT NULL,
  `status` ENUM('active', 'suspended') DEFAULT 'active',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Software Table
CREATE TABLE `software` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL,
  `slug` VARCHAR(100) UNIQUE NOT NULL,
  `description` TEXT NULL,
  `category` VARCHAR(50) NULL,
  `changelog` TEXT NULL,
  `public_key` TEXT NOT NULL, -- Ed25519 public key
  `private_key` TEXT NOT NULL, -- Ed25519 private key (AES encrypted with system master key)
  `client_id` VARCHAR(64) UNIQUE NOT NULL,
  `client_secret` VARCHAR(255) NOT NULL, -- AES encrypted client secret
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Software Versions Table
CREATE TABLE `software_versions` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `software_id` INT NOT NULL,
  `version` VARCHAR(30) NOT NULL,
  `changelog` TEXT NULL,
  `file_path` VARCHAR(255) NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`software_id`) REFERENCES `software`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Licenses Table
CREATE TABLE `licenses` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `software_id` INT NOT NULL,
  `user_id` INT NOT NULL,
  `license_key` TEXT NOT NULL, -- Signed license token: base64(payload).base64(signature)
  `activation_limit` INT DEFAULT 1,
  `status` ENUM('generated', 'activated', 'active', 'expired', 'revoked') DEFAULT 'generated',
  `expires_at` DATETIME NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (`software_id`) REFERENCES `software`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. License Activations Table
CREATE TABLE `license_activations` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `license_id` INT NOT NULL,
  `domain` VARCHAR(255) NOT NULL,
  `machine_id` VARCHAR(255) NOT NULL,
  `ip_address` VARCHAR(45) NOT NULL, -- Logged for anomalies only, not gated
  `last_active_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`license_id`) REFERENCES `licenses`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Used Nonces Table (Replay protection)
CREATE TABLE `used_nonces` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `nonce` VARCHAR(128) NOT NULL,
  `client_id` VARCHAR(64) NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `unique_client_nonce` (`client_id`, `nonce`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. CMS Posts Table
CREATE TABLE `posts` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `title` VARCHAR(255) NOT NULL,
  `slug` VARCHAR(255) UNIQUE NOT NULL,
  `content` LONGTEXT NOT NULL,
  `editor_mode` ENUM('markdown', 'canvas') DEFAULT 'markdown',
  `category` VARCHAR(100) NULL,
  `tags` VARCHAR(255) NULL,
  `featured_image` VARCHAR(255) NULL,
  `seo_title` VARCHAR(255) NULL,
  `seo_description` TEXT NULL,
  `status` ENUM('draft', 'published', 'scheduled') DEFAULT 'draft',
  `published_at` DATETIME NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. CMS Pages Table
CREATE TABLE `pages` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `title` VARCHAR(255) NOT NULL,
  `slug` VARCHAR(255) UNIQUE NOT NULL,
  `content` LONGTEXT NOT NULL,
  `editor_mode` ENUM('markdown', 'canvas') DEFAULT 'canvas',
  `seo_title` VARCHAR(255) NULL,
  `seo_description` TEXT NULL,
  `head_scripts` TEXT NULL, -- Per-page script injection
  `status` ENUM('draft', 'published') DEFAULT 'draft',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. Settings Table (General, SMTP, footer, head script config)
CREATE TABLE `settings` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `setting_key` VARCHAR(50) UNIQUE NOT NULL,
  `setting_value` LONGTEXT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 11. Audit Log Table
CREATE TABLE `audit_log` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_type` ENUM('admin', 'system', 'customer') NOT NULL,
  `user_id` INT NULL,
  `action` VARCHAR(100) NOT NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `details` TEXT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 12. API Rate Limits Table
CREATE TABLE `api_rate_limits` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `client_id` VARCHAR(64) NOT NULL,
  `request_count` INT DEFAULT 1,
  `window_start` INT NOT NULL, -- Unix timestamp of window start
  UNIQUE KEY `unique_client_window` (`client_id`, `window_start`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
