<?php
namespace Vault;

use Exception;

class Captcha {

    /**
     * Checks if CAPTCHA protection is enabled in system settings.
     */
    public static function isActive(): bool {
        // Read directly from DB via query to avoid circular dependency
        try {
            $setting = DB::fetch("SELECT setting_value FROM settings WHERE setting_key = 'captcha_enabled'");
            return !empty($setting['setting_value']) && $setting['setting_value'] === '1';
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Renders the CAPTCHA markup (HTML & scripts) based on the configured provider.
     */
    public static function render(): string {
        if (!self::isActive()) {
            return '';
        }

        $provider = self::getSetting('captcha_provider', 'local');
        $siteKey = self::getSetting('captcha_site_key', '');

        switch ($provider) {
            case 'hcaptcha':
                if (empty($siteKey)) {
                    return '<p class="text-danger" style="font-size:0.8rem;">hCaptcha configuration error: Site Key is missing.</p>';
                }
                return '
                <div class="form-group captcha-container" style="margin: 1.5rem 0; display: flex; justify-content: center;">
                    <div class="h-captcha" data-sitekey="' . htmlspecialchars($siteKey) . '" data-theme="light"></div>
                </div>
                <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
                ';

            case 'recaptcha':
                if (empty($siteKey)) {
                    return '<p class="text-danger" style="font-size:0.8rem;">reCAPTCHA configuration error: Site Key is missing.</p>';
                }
                return '
                <div class="form-group captcha-container" style="margin: 1.5rem 0; display: flex; justify-content: center;">
                    <div class="g-recaptcha" data-sitekey="' . htmlspecialchars($siteKey) . '"></div>
                </div>
                <script src="https://www.google.com/recaptcha/api.js" async defer></script>
                ';

            case 'local':
            default:
                // Generate a simple secure math challenge
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }
                $num1 = rand(2, 9);
                $num2 = rand(2, 9);
                $_SESSION['crxsm_captcha_answer'] = $num1 + $num2;

                return '
                <div class="form-group" style="margin: 1.25rem 0;">
                    <label class="form-label" style="text-align:left; display:block; font-size:0.8rem; font-weight:600; color:var(--text-muted); margin-bottom:0.5rem; text-transform:uppercase;">
                        Security Question: What is ' . $num1 . ' + ' . $num2 . '?
                    </label>
                    <input type="number" name="crxsm_captcha_answer" required class="form-control" placeholder="Enter your answer" autocomplete="off" style="width:100%; padding:0.8rem 1.2rem; background:rgba(15,23,42,0.015); border:1px solid rgba(15,23,42,0.1); border-radius:10px; color:var(--text-color);">
                </div>
                ';
        }
    }

    /**
     * Verifies the submitted CAPTCHA answer.
     *
     * @return bool True if verification passes, false otherwise.
     */
    public static function verify(): bool {
        if (!self::isActive()) {
            return true;
        }

        $provider = self::getSetting('captcha_provider', 'local');
        $secretKey = self::getSetting('captcha_secret_key', '');

        switch ($provider) {
            case 'hcaptcha':
                $response = $_POST['h-captcha-response'] ?? '';
                if (empty($response)) {
                    return false;
                }
                return self::verifyRemote('https://hcaptcha.com/siteverify', $secretKey, $response);

            case 'recaptcha':
                $response = $_POST['g-recaptcha-response'] ?? '';
                if (empty($response)) {
                    return false;
                }
                return self::verifyRemote('https://www.google.com/recaptcha/api/siteverify', $secretKey, $response);

            case 'local':
            default:
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }
                $expected = $_SESSION['crxsm_captcha_answer'] ?? null;
                $actual = $_POST['crxsm_captcha_answer'] ?? null;

                // Clear session answer to prevent reuse
                unset($_SESSION['crxsm_captcha_answer']);

                if ($expected === null || $actual === null) {
                    return false;
                }
                return (int)$expected === (int)$actual;
        }
    }

    /**
     * Connects to third-party endpoints to verify the response.
     */
    private static function verifyRemote(string $url, string $secret, string $response): bool {
        if (empty($secret)) {
            error_log("CRXSM CAPTCHA Error: Secret Key is not configured in settings.");
            return false;
        }

        $postFields = [
            'secret'   => $secret,
            'response' => $response,
            'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
        ];

        try {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postFields));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            
            $apiResponse = curl_exec($ch);
            curl_close($ch);

            if (!$apiResponse) {
                return false;
            }

            $result = json_decode($apiResponse, true);
            return !empty($result['success']);
        } catch (Exception $e) {
            error_log("CRXSM CAPTCHA API Error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Helper to read settings values.
     */
    private static function getSetting(string $key, string $default = ''): string {
        try {
            $setting = DB::fetch("SELECT setting_value FROM settings WHERE setting_key = :key", [':key' => $key]);
            return $setting ? $setting['setting_value'] : $default;
        } catch (Exception $e) {
            return $default;
        }
    }
}
