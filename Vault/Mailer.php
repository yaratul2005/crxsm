<?php
namespace Vault;

use Exception;

class Mailer {

    /**
     * Send an email using database-configured SMTP settings or fallback to mail().
     */
    public static function send(string $to, string $subject, string $bodyHtml, string $bodyText = ''): bool {
        // Fetch SMTP settings
        $settings = self::getSmtpSettings();

        $host = $settings['smtp_host'] ?? '';
        $port = (int)($settings['smtp_port'] ?? 587);
        $user = $settings['smtp_user'] ?? '';
        $pass = $settings['smtp_pass'] ?? '';
        $enc  = $settings['smtp_enc'] ?? 'tls'; // 'tls', 'ssl', 'none'
        $fromEmail = $settings['smtp_from_email'] ?? 'noreply@crxsm.local';
        $fromName  = $settings['smtp_from_name'] ?? 'CRXSM Platform';

        if (empty($host)) {
            // Fallback to PHP native mail()
            return self::sendNativeMail($to, $subject, $bodyHtml, $fromEmail, $fromName);
        }

        try {
            return self::sendSmtpSocket($to, $subject, $bodyHtml, $bodyText, $host, $port, $enc, $user, $pass, $fromEmail, $fromName);
        } catch (Exception $e) {
            error_log("SMTP send failed: " . $e->getMessage() . ". Falling back to native mail().");
            return self::sendNativeMail($to, $subject, $bodyHtml, $fromEmail, $fromName);
        }
    }

    /**
     * Fetch settings from the database.
     */
    private static function getSmtpSettings(): array {
        $keys = ['smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_enc', 'smtp_from_email', 'smtp_from_name'];
        $settings = [];
        foreach ($keys as $key) {
            $settings[$key] = '';
        }

        try {
            $rows = DB::fetchAll("SELECT setting_key, setting_value FROM settings WHERE setting_key LIKE 'smtp_%'");
            foreach ($rows as $row) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
        } catch (Exception $e) {
            // Settings table might not exist yet during setup
        }

        return $settings;
    }

    /**
     * Native PHP mail() sender.
     */
    private static function sendNativeMail(string $to, string $subject, string $bodyHtml, string $fromEmail, string $fromName): bool {
        $boundary = md5(uniqid(time()));
        
        $headers = "From: " . mime_header_encode($fromName) . " <" . $fromEmail . ">\r\n";
        $headers .= "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n";

        // Body message
        $msg = "--$boundary\r\n";
        $msg .= "Content-Type: text/plain; charset=UTF-8\r\n";
        $msg .= "Content-Transfer-Encoding: 7bit\r\n\r\n";
        $msg .= strip_tags(str_replace('<br>', "\r\n", $bodyHtml)) . "\r\n\r\n";
        
        $msg .= "--$boundary\r\n";
        $msg .= "Content-Type: text/html; charset=UTF-8\r\n";
        $msg .= "Content-Transfer-Encoding: 7bit\r\n\r\n";
        $msg .= $bodyHtml . "\r\n\r\n";
        $msg .= "--$boundary--";

        return mail($to, $subject, $msg, $headers);
    }

    /**
     * Socket-based SMTP client.
     */
    private static function sendSmtpSocket(
        string $to, string $subject, string $bodyHtml, string $bodyText,
        string $host, int $port, string $enc, string $user, string $pass,
        string $fromEmail, string $fromName
    ): bool {
        $prefix = '';
        if (strtolower($enc) === 'ssl') {
            $prefix = 'ssl://';
        }

        $socket = @fsockopen($prefix . $host, $port, $errno, $errstr, 15);
        if (!$socket) {
            throw new Exception("Could not connect to SMTP server: $errstr ($errno)");
        }

        self::readResponse($socket, 220);

        $localDomain = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';
        self::writeSocket($socket, "EHLO $localDomain");
        self::readResponse($socket, 250);

        if (strtolower($enc) === 'tls') {
            self::writeSocket($socket, "STARTTLS");
            self::readResponse($socket, 220);
            
            // Upgrade connection to encrypted socket
            if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new Exception("TLS encryption handshake failed.");
            }
            
            // Say hello again after secure upgrade
            self::writeSocket($socket, "EHLO $localDomain");
            self::readResponse($socket, 250);
        }

        // Authentication if user specified
        if (!empty($user)) {
            self::writeSocket($socket, "AUTH LOGIN");
            self::readResponse($socket, 334);

            self::writeSocket($socket, base64_encode($user));
            self::readResponse($socket, 334);

            self::writeSocket($socket, base64_encode($pass));
            self::readResponse($socket, 235);
        }

        // Mail From
        self::writeSocket($socket, "MAIL FROM:<$fromEmail>");
        self::readResponse($socket, 250);

        // Recipient
        self::writeSocket($socket, "RCPT TO:<$to>");
        self::readResponse($socket, 250);

        // Data
        self::writeSocket($socket, "DATA");
        self::readResponse($socket, 354);

        // Generate email content headers
        $boundary = md5(uniqid(time()));
        $headers = [
            "MIME-Version: 1.0",
            "To: <$to>",
            "From: " . mime_header_encode($fromName) . " <$fromEmail>",
            "Subject: " . mime_header_encode($subject),
            "Date: " . date('r'),
            "Content-Type: multipart/alternative; boundary=\"$boundary\"",
            "Message-ID: <" . uniqid() . "@" . $localDomain . ">",
            "\r\n"
        ];

        // Format email body
        $body = [];
        $body[] = "--$boundary";
        $body[] = "Content-Type: text/plain; charset=UTF-8";
        $body[] = "Content-Transfer-Encoding: base64\r\n";
        
        $plain = empty($bodyText) ? strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\r\n", $bodyHtml)) : $bodyText;
        $body[] = chunk_split(base64_encode($plain));

        $body[] = "--$boundary";
        $body[] = "Content-Type: text/html; charset=UTF-8";
        $body[] = "Content-Transfer-Encoding: base64\r\n";
        $body[] = chunk_split(base64_encode($bodyHtml));
        
        $body[] = "--$boundary--";
        $body[] = "."; // end of message SMTP command

        $emailData = implode("\r\n", $headers) . implode("\r\n", $body);

        self::writeSocket($socket, $emailData);
        self::readResponse($socket, 250);

        self::writeSocket($socket, "QUIT");
        fclose($socket);

        return true;
    }

    private static function writeSocket($socket, string $data): void {
        fwrite($socket, $data . "\r\n");
    }

    private static function readResponse($socket, int $expectedCode): void {
        $response = "";
        while ($line = fgets($socket, 512)) {
            $response .= $line;
            if (substr($line, 3, 1) === ' ') {
                break;
            }
        }
        $code = (int)substr($response, 0, 3);
        if ($code !== $expectedCode) {
            throw new Exception("SMTP transaction failed. Expected code $expectedCode, got response: $response");
        }
    }
}

/**
 * Helper to encode headers for unicode subjects/names
 */
function mime_header_encode(string $string): string {
    if (preg_match('/[^\x20-\x7E]/', $string)) {
        return '=?UTF-8?B?' . base64_encode($string) . '?=';
    }
    return $string;
}
