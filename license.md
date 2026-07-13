# Software License Verification Integration Guide (CRXSM)

This document provides a step-by-step technical guide and copy-pasteable helper class for developers to implement secure license activation, heartbeat check-ins, and cryptographic signature validation inside client software (e.g., WordPress plugins, SaaS client libraries, or standalone desktop applications).

---

## 1. Cryptographic Architecture

CRXSM employs a dual-layered security architecture:
1. **Asymmetric Offline Verification (Ed25519)**: License keys are digitally signed tokens (`base64url(payload) . "." . base64url(signature)`). The client software uses a hardcoded **Ed25519 Public Key** to decrypt and verify the signature locally, confirming the key was issued by your CRXSM server without making any external HTTP requests.
2. **Authoritative Active Validation (HMAC-SHA256)**: Real-time checks (activation, deactivation, status updates) require querying the CRXSM `/Tunnel` API. Requests must be authenticated with four custom security headers containing a request signature computed with the software product's **Client Secret**.

---

## 2. API Communication Tunnel (`/Tunnel/index.php`)

All API requests are sent via HTTP POST to:
`https://<your-crxsm-domain>/Tunnel/index.php?action=<action>`

### Required Security Headers
Every request must include the following headers:
- `X-CRXSM-Client-ID`: The product's Client ID (e.g. `sw_542f42eee...`).
- `X-CRXSM-Timestamp`: Current UTC Unix timestamp.
- `X-CRXSM-Nonce`: A random single-use string (min 16 characters).
- `X-CRXSM-Signature`: Hex-encoded HMAC-SHA256 signature calculated as follows:

```php
$data_to_sign = $timestamp . '.' . $nonce . '.' . $raw_post_payload;
$signature = hash_hmac('sha256', $data_to_sign, $client_secret);
```

---

## 3. Drop-In PHP Integration Helper Class

The following PHP class can be copied directly into your WordPress plugin or PHP project. It implements all offline validation, header signatures, API requests, and caching.

```php
<?php
/**
 * CRXSM License Verification Client
 *
 * Safe to integrate into WordPress plugins or standalone PHP scripts.
 * Depends on the 'sodium' PHP extension (enabled by default in PHP 7.2+).
 */
class CRXSM_License_Client {

    private $api_url;
    private $client_id;
    private $client_secret;
    private $public_key;

    /**
     * Constructor
     *
     * @param string $api_url       Absolute URL to the Tunnel endpoint (e.g., 'https://great10.xyz/Tunnel/index.php')
     * @param string $client_id     Product Client ID (e.g., 'sw_542f42eee9271290367d2907fb8bc024')
     * @param string $client_secret Product Client Secret
     * @param string $public_key    Product Ed25519 Public Verification Key (hex string)
     */
    public function __construct(string $api_url, string $client_id, string $client_secret, string $public_key) {
        $this->api_url = rtrim($api_url, '/');
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->public_key = hex2bin($public_key);
    }

    /**
     * 1. Offline Signature Check (Fast, No HTTP Requests)
     * Confirms the license key is syntactically correct and signed by the CRXSM authority.
     *
     * @param string $license_key Raw license token
     * @return array|false The decoded license payload if authentic, false on tampering.
     */
    public function verify_signature_offline(string $license_key) {
        $parts = explode('.', trim($license_key));
        if (count($parts) !== 2) {
            return false;
        }

        $payload_json = $this->base64url_decode($parts[0]);
        $signature = $this->base64url_decode($parts[1]);

        if (!$payload_json || !$signature) {
            return false;
        }

        // Safeguards for Libsodium parameters (Ed25519 signature is 64 bytes, public key is 32 bytes)
        if (strlen($signature) !== 64 || strlen($this->public_key) !== 32) {
            return false;
        }

        if (!extension_loaded('sodium')) {
            // Fallback warning if libsodium is missing
            error_log('CRXSM Client: Sodium extension is not enabled in this PHP environment.');
            return false;
        }

        // Verify cryptographic signature
        $is_valid = sodium_crypto_sign_verify_detached($signature, $payload_json, $this->public_key);
        if (!$is_valid) {
            return false;
        }

        $payload = json_decode($payload_json, true);
        if (!is_array($payload)) {
            return false;
        }

        // Check expiration date locally
        if (isset($payload['expires_at'])) {
            $expiry_time = strtotime($payload['expires_at']);
            if ($expiry_time && time() > $expiry_time) {
                return false; // Expired locally
            }
        }

        return $payload;
    }

    /**
     * 2. Authoritative Online Activation
     * Binds this installation domain and machine ID to the license key.
     *
     * @param string $license_key License key token
     * @return array Response payload with ['success' => true/false]
     */
    public function activate_license(string $license_key): array {
        $payload = [
            'license_key' => $license_key,
            'domain'      => $this->get_domain(),
            'machine_id'  => $this->get_machine_id()
        ];

        return $this->send_request('activate', $payload);
    }

    /**
     * 3. Authoritative Online Deactivation
     * Frees up an activation slot.
     *
     * @param string $license_key License key token
     * @return array Response payload
     */
    public function deactivate_license(string $license_key): array {
        $payload = [
            'license_key' => $license_key,
            'domain'      => $this->get_domain(),
            'machine_id'  => $this->get_machine_id()
        ];

        return $this->send_request('deactivate', $payload);
    }

    /**
     * 4. Cached Authority Status Verification (Recommended)
     * Queries the server and caches the status locally for 12-24 hours to prevent slow page loads.
     *
     * @param string $license_key
     * @return bool True if license is fully active and authorized, false otherwise.
     */
    public function check_license_status_cached(string $license_key): bool {
        // Step A: Perform fast offline sanity check first
        $local_payload = $this->verify_signature_offline($license_key);
        if (!$local_payload) {
            return false; // Tampered or expired key
        }

        // Step B: Check local caching layer
        $cache_key = 'crxsm_lic_' . md5($license_key);
        $cached_status = $this->get_cache($cache_key);

        if ($cached_status === 'active') {
            return true;
        }

        // Step C: Cache expired. Trigger background / online verification
        $response = $this->send_request('heartbeat', [
            'license_key' => $license_key,
            'domain'      => $this->get_domain(),
            'machine_id'  => $this->get_machine_id()
        ]);

        if (!empty($response['success']) && ($response['status'] ?? '') === 'active') {
            // Cache active status for 12 hours (43200 seconds)
            $this->set_cache($cache_key, 'active', 43200);
            return true;
        }

        // Explicitly clear cache or mark invalid
        $this->delete_cache($cache_key);
        return false;
    }

    // ==========================================
    // Internal Helper Utility Methods
    // ==========================================

    /**
     * Authenticates and dispatches signed API request to CRXSM Tunnel
     */
    private function send_request(string $action, array $payload_data): array {
        $json_payload = json_encode($payload_data);
        $timestamp = time();
        $nonce = bin2hex(random_bytes(10)); // 20 character unique string

        // Build HMAC signature: timestamp + "." + nonce + "." + raw_body
        $data_to_sign = $timestamp . '.' . $nonce . '.' . $json_payload;
        $signature = hash_hmac('sha256', $data_to_sign, $this->client_secret);

        $headers = [
            'Content-Type: application/json',
            'X-CRXSM-Client-ID: ' . $this->client_id,
            'X-CRXSM-Timestamp: ' . $timestamp,
            'X-CRXSM-Nonce: ' . $nonce,
            'X-CRXSM-Signature: ' . $signature
        ];

        $target_url = $this->api_url . '?action=' . $action;

        // Dispatch using standard cURL (or wp_remote_post if integrating in WordPress)
        $ch = curl_init($target_url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json_payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code !== 200 || !$response) {
            return ['success' => false, 'error' => 'Unable to connect to license verification server.'];
        }

        $decoded = json_decode($response, true);
        return is_array($decoded) ? $decoded : ['success' => false, 'error' => 'Invalid API JSON response.'];
    }

    /**
     * Resolves the installation domain
     */
    private function get_domain(): string {
        if (function_exists('get_site_url')) {
            return parse_url(get_site_url(), PHP_URL_HOST) ?? 'localhost';
        }
        return $_SERVER['SERVER_NAME'] ?? 'localhost';
    }

    /**
     * Generates a persistent unique hardware/machine fingerprint
     */
    private function get_machine_id(): string {
        if (function_exists('get_option')) {
            // WordPress context: use combination of secure salt values and site URL
            $salt = defined('AUTH_KEY') ? AUTH_KEY : 'crxsm_default_salt';
            return hash('sha256', get_option('siteurl') . $salt);
        }
        // Standalone PHP context
        return hash('sha256', php_uname() . ($this->get_domain()));
    }

    /**
     * Caching Utilities (Automatically uses WP Transients inside WordPress)
     */
    private function get_cache(string $key) {
        if (function_exists('get_transient')) {
            return get_transient($key);
        }
        // Fallback: simple text file caching
        $file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $key;
        if (file_exists($file) && (time() - filemtime($file)) < 43200) {
            return file_get_contents($file);
        }
        return false;
    }

    private function set_cache(string $key, string $value, int $expiration) {
        if (function_exists('set_transient')) {
            set_transient($key, $value, $expiration);
            return;
        }
        $file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $key;
        file_put_contents($file, $value);
    }

    private function delete_cache(string $key) {
        if (function_exists('delete_transient')) {
            delete_transient($key);
            return;
        }
        $file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $key;
        if (file_exists($file)) {
            unlink($file);
        }
    }

    private function base64url_decode(string $data) {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $len = 4 - $remainder;
            $data .= str_repeat('=', $len);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
```

---

## 4. How to Use the Client Helper in Your Plugin

Here is how your plugin developer should instantiate and invoke the verification client.

### Step A: Initialize the Client
Define your product's configuration constants and instantiate the verification class.
```php
define('MY_PLUGIN_CLIENT_ID', 'sw_542f42eee9271290367d2907fb8bc024');
define('MY_PLUGIN_CLIENT_SECRET', '3c3561a18f4c3dfeca728df74c2e5150fbcc1282c6aab3b4');
define('MY_PLUGIN_PUBLIC_KEY', 'bf04ec5f8f8e5667b0c00f95c4355b847b76eb6f1ed9859eef4312bcc089fa60');
define('CRXSM_TUNNEL_URL', 'https://great10.xyz/Tunnel/index.php');

$verifier = new CRXSM_License_Client(
    CRXSM_TUNNEL_URL,
    MY_PLUGIN_CLIENT_ID,
    MY_PLUGIN_CLIENT_SECRET,
    MY_PLUGIN_PUBLIC_KEY
);
```

### Step B: Handle Initial License Activation
Run this once when the user inputs their license key in the plugin's settings panel.
```php
$license_key = $_POST['license_key'] ?? '';

// 1. Check local validity first
$is_valid_signature = $verifier->verify_signature_offline($license_key);
if (!$is_valid_signature) {
    die("Error: The license key signature is invalid or has expired.");
}

// 2. Perform authoritative remote activation
$response = $verifier->activate_license($license_key);
if ($response['success']) {
    // Save license key in options database
    update_option('my_plugin_license_key', $license_key);
    echo "Success: Plugin activated!";
} else {
    echo "Activation Failed: " . htmlspecialchars($response['error']);
}
```

### Step C: Restrict Features (Run During Page Load/Admin Bootup)
Invoke this method to lock or unlock premium components. Thanks to caching, this call is virtually instant and only queries your server once every 12 hours.
```php
$license_key = get_option('my_plugin_license_key');

if (empty($license_key) || !$verifier->check_license_status_cached($license_key)) {
    // Hide features, trigger dashboard notice
    add_action('admin_notices', function() {
        echo '<div class="notice notice-error"><p>Your <strong>Ratuls ACT</strong> license is expired or invalid. Please check settings.</p></div>';
    });
    // Return early/restrict execution
    return;
}
```

---

## 5. Developer Implementation Checklist
Before deploying the integrated client, verify that:
- [ ] **OpenSSL / Libsodium** is active on the host machine (`extension_loaded('sodium')` returns `true`).
- [ ] The **Public Key** matched is exactly the hex-encoded string found in the admin software panel.
- [ ] No remote requests are dispatched on every page load (verify that the transients/cache layer is active).
- [ ] Under settings saving, inputs are sanitized to strip unexpected spaces or linebreaks.
