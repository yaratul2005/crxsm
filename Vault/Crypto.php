<?php
namespace Vault;

use Exception;

class Crypto {
    
    /**
     * Generate an Ed25519 keypair.
     * @return array [public_key_hex, private_key_hex]
     */
    public static function generateKeyPair(): array {
        if (!extension_loaded('sodium')) {
            throw new Exception("PHP sodium extension is not enabled.");
        }
        $keypair = sodium_crypto_sign_keypair();
        $pub = sodium_crypto_sign_publickey($keypair);
        $sec = sodium_crypto_sign_secretkey($keypair);
        return [
            'public_key'  => bin2hex($pub),
            'private_key' => bin2hex($sec)
        ];
    }

    /**
     * Base64URL encode string.
     */
    public static function base64UrlEncode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64URL decode string.
     */
    public static function base64UrlDecode(string $data): string {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Generate structured Ed25519-signed license key.
     * Token format: base64url(payload_json).base64url(signature)
     */
    public static function generateLicenseKey(array $payload, string $privateKeyHex): string {
        if (!extension_loaded('sodium')) {
            throw new Exception("PHP sodium extension is not enabled.");
        }
        $payloadJson = json_encode($payload);
        $privateKey = hex2bin($privateKeyHex);
        
        $signature = sodium_crypto_sign_detached($payloadJson, $privateKey);
        
        return self::base64UrlEncode($payloadJson) . '.' . self::base64UrlEncode($signature);
    }

    /**
     * Verify Ed25519 license key.
     * Returns payload array if valid, false otherwise.
     */
    public static function verifyLicenseKey(string $token, string $publicKeyHex) {
        if (!extension_loaded('sodium')) {
            throw new Exception("PHP sodium extension is not enabled.");
        }
        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return false;
        }

        $payloadJson = self::base64UrlDecode($parts[0]);
        $signature = self::base64UrlDecode($parts[1]);
        
        // Ensure signature is exactly 64 bytes (SODIUM_CRYPTO_SIGN_BYTES)
        if (strlen($signature) !== 64) {
            return false;
        }

        $publicKey = @hex2bin($publicKeyHex);
        // Ensure public key is exactly 32 bytes (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES)
        if (!$publicKey || strlen($publicKey) !== 32) {
            return false;
        }

        if (@sodium_crypto_sign_verify_detached($signature, $payloadJson, $publicKey)) {
            return json_decode($payloadJson, true);
        }
        return false;
    }

    /**
     * Encrypt a string using AES-256-CBC and master key.
     */
    public static function encryptSecret(string $plainText, string $masterKeyHex): string {
        $key = hex2bin($masterKeyHex);
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($plainText, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) {
            throw new Exception("Encryption failed.");
        }
        return base64_encode($iv . $cipher);
    }

    /**
     * Decrypt a string using AES-256-CBC and master key.
     */
    public static function decryptSecret(string $cipherText, string $masterKeyHex): string|false {
        $key = @hex2bin($masterKeyHex);
        if (!$key) {
            return false;
        }
        $data = base64_decode($cipherText);
        if (strlen($data) < 17) {
            return false;
        }
        $iv = substr($data, 0, 16);
        $cipher = substr($data, 16);
        return openssl_decrypt($cipher, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Verify HMAC signature of an API request.
     */
    public static function verifyApiSignature(string $data, string $signature, string $secretPlain, string $timestamp, string $nonce): bool {
        $computed = hash_hmac('sha256', $timestamp . '.' . $nonce . '.' . $data, $secretPlain);
        return hash_equals($computed, $signature);
    }
}
