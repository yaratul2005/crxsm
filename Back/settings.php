<?php
/**
 * CRXSM Admin View - Platform Settings & Database Tools
 */

if (!defined('CRXSM_ACCESS')) {
    http_response_code(403);
    die("Direct access not allowed.");
}

use Vault\DB;
use Vault\Csrf;
use Vault\Mailer;
use Vault\Audit;

$action = $_GET['action'] ?? 'settings';
$flashSuccess = '';
$flashError = '';

// Handle POST submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Csrf::verifyOrDie();
    
    $postAction = $_POST['action'] ?? '';

    if ($postAction === 'save_settings') {
        $keys = [
            'site_name', 'site_description', 'site_head_scripts',
            'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_enc',
            'smtp_from_email', 'smtp_from_name', 'footer_zone_1',
            'captcha_enabled', 'captcha_provider', 'captcha_site_key', 'captcha_secret_key'
        ];

        foreach ($keys as $key) {
            $val = $_POST[$key] ?? '';
            // Insert or update
            $exists = DB::fetch("SELECT id FROM settings WHERE setting_key = :key", [':key' => $key]);
            if ($exists) {
                DB::execute("UPDATE settings SET setting_value = :val WHERE setting_key = :key", [':val' => $val, ':key' => $key]);
            } else {
                DB::execute("INSERT INTO settings (setting_key, setting_value) VALUES (:key, :val)", [':key' => $key, ':val' => $val]);
            }
        }

        // Save Footer Zone 2 Links JSON
        $linksLabels = $_POST['f2_labels'] ?? [];
        $linksUrls = $_POST['f2_urls'] ?? [];
        $footerLinks = [];
        for ($i = 0; $i < count($linksLabels); $i++) {
            if (!empty($linksLabels[$i])) {
                $footerLinks[] = [
                    'label' => trim($linksLabels[$i]),
                    'url'   => trim($linksUrls[$i])
                ];
            }
        }
        $footerLinksJson = json_encode($footerLinks);
        DB::execute("UPDATE settings SET setting_value = ? WHERE setting_key = 'footer_zone_2'", [$footerLinksJson]);

        // Save Footer Zone 3 Socials JSON
        $socialNames = $_POST['f3_names'] ?? [];
        $socialUrls = $_POST['f3_urls'] ?? [];
        $footerSocials = [];
        for ($i = 0; $i < count($socialNames); $i++) {
            if (!empty($socialNames[$i])) {
                $footerSocials[] = [
                    'name' => trim($socialNames[$i]),
                    'url'  => trim($socialUrls[$i])
                ];
            }
        }
        $footerZone3Config = json_encode([
            'logo'    => trim($_POST['f3_logo'] ?? ''),
            'socials' => $footerSocials
        ]);
        DB::execute("UPDATE settings SET setting_value = ? WHERE setting_key = 'footer_zone_3'", [$footerZone3Config]);

        Audit::log('admin', $admin['id'], 'update_settings', "Updated general system, SMTP, and footer settings");
        $flashSuccess = "Settings updated successfully.";
    }

    if ($postAction === 'test_smtp') {
        $testEmail = trim($_POST['test_email'] ?? '');
        if (empty($testEmail) || !filter_var($testEmail, FILTER_VALIDATE_EMAIL)) {
            $flashError = "Please specify a valid recipient email address.";
        } else {
            // Save SMTP values to DB temporarily so Mailer reads them
            $keys = ['smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_enc', 'smtp_from_email', 'smtp_from_name'];
            foreach ($keys as $key) {
                $val = $_POST[$key] ?? '';
                DB::execute("UPDATE settings SET setting_value = :val WHERE setting_key = :key", [':val' => $val, ':key' => $key]);
            }

            // Trigger SMTP send
            $subject = "CRXSM SMTP Connection Test";
            $message = "<h3>SMTP Connected Successfully!</h3><p>If you received this email, CRXSM can successfully send messages through your configured mail server.</p>";
            
            $sent = Mailer::send($testEmail, $subject, $message);
            if ($sent) {
                Audit::log('admin', $admin['id'], 'test_smtp_success', "Sent test SMTP email to {$testEmail}");
                $flashSuccess = "SMTP test email sent successfully! Check your inbox.";
            } else {
                Audit::log('admin', $admin['id'], 'test_smtp_failure', "SMTP test send failed to {$testEmail}");
                $flashError = "Failed to send SMTP email. Please review your settings and server errors.";
            }
        }
    }
}

// Handle Database Backup Export (Runs outside main HTML template because it triggers a download)
if (isset($_GET['action']) && $_GET['action'] === 'db_backup') {
    // Generate SQL dump in pure PHP
    try {
        $tables = ['admins', 'users', 'software', 'software_versions', 'licenses', 'license_activations', 'used_nonces', 'posts', 'pages', 'settings', 'audit_log', 'api_rate_limits'];
        
        $sqlDump = "-- CRXSM Database Backup SQL Dump\n";
        $sqlDump .= "-- Generated: " . date('Y-m-d H:i:s') . "\n";
        $sqlDump .= "-- Host: MySQL Database Server\n\n";
        $sqlDump .= "SET FOREIGN_KEY_CHECKS = 0;\n\n";

        foreach ($tables as $table) {
            $sqlDump .= "-- Dump of table: {$table}\n";
            $sqlDump .= "DROP TABLE IF EXISTS `{$table}`;\n";

            // Fetch CREATE TABLE statement
            $rowCreate = DB::fetch("SHOW CREATE TABLE `{$table}`");
            $sqlDump .= $rowCreate['Create Table'] . ";\n\n";

            // Fetch table rows
            $rows = DB::fetchAll("SELECT * FROM `{$table}`");
            foreach ($rows as $row) {
                $cols = array_keys($row);
                $escapedVals = [];
                foreach ($row as $val) {
                    if ($val === null) {
                        $escapedVals[] = 'NULL';
                    } else {
                        // Standard PDO escaping
                        $escapedVals[] = DB::getConn()->quote($val);
                    }
                }
                
                $sqlDump .= "INSERT INTO `{$table}` (`" . implode("`, `", $cols) . "`) VALUES (" . implode(", ", $escapedVals) . ");\n";
            }
            $sqlDump .= "\n";
        }
        $sqlDump .= "SET FOREIGN_KEY_CHECKS = 1;\n";

        Audit::log('admin', $admin['id'], 'export_db_backup', "Exported SQL database backup file");

        // Clear output buffer and stream download
        while (ob_get_level()) {
            ob_end_clean();
        }
        header('Content-Type: application/sql');
        header('Content-Disposition: attachment; filename="crxsm_backup_' . date('Ymd_His') . '.sql"');
        header('Content-Length: ' . strlen($sqlDump));
        echo $sqlDump;
        exit;

    } catch (Exception $e) {
        $flashError = "Database dump failed: " . $e->getMessage();
    }
}

// Read current settings
$siteName = getSettingVal('site_name', 'CRXSM Platform');
$siteDesc = getSettingVal('site_description', '');
$siteHeadScripts = getSettingVal('site_head_scripts', '');

$smtpHost = getSettingVal('smtp_host', '');
$smtpPort = getSettingVal('smtp_port', '587');
$smtpUser = getSettingVal('smtp_user', '');
$smtpPass = getSettingVal('smtp_pass', '');
$smtpEnc  = getSettingVal('smtp_enc', 'tls');
$smtpFromEmail = getSettingVal('smtp_from_email', '');
$smtpFromName  = getSettingVal('smtp_from_name', '');

$footerZone1 = getSettingVal('footer_zone_1', '');
$footerLinks = json_decode(getSettingVal('footer_zone_2', '[]'), true) ?: [];
$footerZone3Config = json_decode(getSettingVal('footer_zone_3', '{"logo":"","socials":[]}'), true) ?: [];
$footerLogo = $footerZone3Config['logo'] ?? '';
$footerSocials = $footerZone3Config['socials'] ?? [];

$captchaEnabled = getSettingVal('captcha_enabled', '0');
$captchaProvider = getSettingVal('captcha_provider', 'local');
$captchaSiteKey = getSettingVal('captcha_site_key', '');
$captchaSecretKey = getSettingVal('captcha_secret_key', '');
?>

<?php if (!empty($flashSuccess)): ?>
    <div style="background:#d1fae5; color:#065f46; border:1px solid #a7f3d0; padding:1rem; border-radius:8px; margin-bottom:1.5rem;">
        <?php echo htmlspecialchars($flashSuccess); ?>
    </div>
<?php endif; ?>

<?php if (!empty($flashError)): ?>
    <div style="background:#fee2e2; color:#991b1b; border:1px solid #fca5a5; padding:1rem; border-radius:8px; margin-bottom:1.5rem;">
        <?php echo htmlspecialchars($flashError); ?>
    </div>
<?php endif; ?>

<div class="dashboard-grid">
    <!-- LEFT COLUMN: MAIN CONFIGURATIONS -->
    <div class="grid-card" style="grid-column: span 1;">
        <form action="index.php?view=settings" method="post" id="settings-form">
            <?php echo Csrf::getHiddenInput(); ?>
            <input type="hidden" name="action" value="save_settings">

            <!-- 1. General Config -->
            <h3 style="margin-bottom:1rem;">General Brand Metadata</h3>
            <div class="form-group">
                <label class="form-label">Platform Name</label>
                <input type="text" name="site_name" class="form-control" value="<?php echo htmlspecialchars($siteName); ?>" required>
            </div>
            <div class="form-group">
                <label class="form-label">Platform Description</label>
                <input type="text" name="site_description" class="form-control" value="<?php echo htmlspecialchars($siteDesc); ?>">
            </div>

            <hr style="border:none; border-top:1px solid var(--border-color); margin:2rem 0;">

            <!-- 2. SMTP Config -->
            <h3 style="margin-bottom:1rem;">Mail Server (SMTP) Settings</h3>
            <div class="form-group">
                <label class="form-label">SMTP Host</label>
                <input type="text" name="smtp_host" class="form-control" value="<?php echo htmlspecialchars($smtpHost); ?>" placeholder="mail.yourserver.com">
                <span class="text-muted" style="font-size:0.75rem;">Leave empty to fall back to native PHP mail() configuration.</span>
            </div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1rem;">
                <div class="form-group">
                    <label class="form-label">SMTP Port</label>
                    <input type="number" name="smtp_port" class="form-control" value="<?php echo htmlspecialchars($smtpPort); ?>">
                </div>
                <div class="form-group">
                    <label class="form-label">Encryption Type</label>
                    <select name="smtp_enc" class="form-control">
                        <option value="tls" <?php echo $smtpEnc === 'tls' ? 'selected' : ''; ?>>TLS (Port 587)</option>
                        <option value="ssl" <?php echo $smtpEnc === 'ssl' ? 'selected' : ''; ?>>SSL (Port 465)</option>
                        <option value="none" <?php echo $smtpEnc === 'none' ? 'selected' : ''; ?>>None</option>
                    </select>
                </div>
            </div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1rem;">
                <div class="form-group">
                    <label class="form-label">SMTP Username</label>
                    <input type="text" name="smtp_user" class="form-control" value="<?php echo htmlspecialchars($smtpUser); ?>">
                </div>
                <div class="form-group">
                    <label class="form-label">SMTP Password</label>
                    <input type="password" name="smtp_pass" class="form-control" value="<?php echo htmlspecialchars($smtpPass); ?>">
                </div>
            </div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1rem;">
                <div class="form-group">
                    <label class="form-label">Sender Email Address</label>
                    <input type="email" name="smtp_from_email" class="form-control" value="<?php echo htmlspecialchars($smtpFromEmail); ?>" placeholder="licensing@yourdomain.com">
                </div>
                <div class="form-group">
                    <label class="form-label">Sender Name</label>
                    <input type="text" name="smtp_from_name" class="form-control" value="<?php echo htmlspecialchars($smtpFromName); ?>" placeholder="CRXSM Hub">
                </div>
            </div>

            <hr style="border:none; border-top:1px solid var(--border-color); margin:2rem 0;">

            <!-- 3. Footer Config -->
            <h3 style="margin-bottom:1rem;">Footer Customization (3 Zones)</h3>
            <div class="form-group">
                <label class="form-label">Zone 1: Freeform text block (HTML allowed)</label>
                <textarea name="footer_zone_1" class="form-control" rows="3"><?php echo htmlspecialchars($footerZone1); ?></textarea>
            </div>
            
            <!-- Zone 2 Links -->
            <div style="margin-bottom:1.5rem;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                    <label class="form-label" style="margin:0;">Zone 2: Navigation Links</label>
                    <button type="button" class="btn-sm btn-success" onclick="addFooterLinkRow()">+ Add Link</button>
                </div>
                <div id="footer-links-container" style="display:flex; flex-direction:column; gap:0.5rem;">
                    <?php foreach ($footerLinks as $fl): ?>
                        <div style="display:flex; gap:0.5rem; align-items:center;">
                            <input type="text" name="f2_labels[]" class="form-control" placeholder="Label" value="<?php echo htmlspecialchars($fl['label']); ?>" style="flex:1;">
                            <input type="text" name="f2_urls[]" class="form-control" placeholder="URL" value="<?php echo htmlspecialchars($fl['url']); ?>" style="flex:2;">
                            <button type="button" class="btn-sm btn-danger" onclick="this.parentElement.remove()">Remove</button>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Zone 3 Socials -->
            <div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                    <label class="form-label" style="margin:0;">Zone 3: Logo & Social Links</label>
                    <button type="button" class="btn-sm btn-success" onclick="addSocialLinkRow()">+ Add Social</button>
                </div>
                <div class="form-group">
                    <label class="form-label" style="font-size:0.75rem;">Logo Image URL (Optional)</label>
                    <input type="text" name="f3_logo" class="form-control" value="<?php echo htmlspecialchars($footerLogo); ?>" placeholder="/assets/logo.png">
                </div>
                <div id="footer-socials-container" style="display:flex; flex-direction:column; gap:0.5rem;">
                    <?php foreach ($footerSocials as $fs): ?>
                        <div style="display:flex; gap:0.5rem; align-items:center;">
                            <input type="text" name="f3_names[]" class="form-control" placeholder="Social Platform (e.g. GitHub)" value="<?php echo htmlspecialchars($fs['name']); ?>" style="flex:1;">
                            <input type="text" name="f3_urls[]" class="form-control" placeholder="Profile URL" value="<?php echo htmlspecialchars($fs['url']); ?>" style="flex:2;">
                            <button type="button" class="btn-sm btn-danger" onclick="this.parentElement.remove()">Remove</button>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <hr style="border:none; border-top:1px solid var(--border-color); margin:2rem 0;">

            <!-- 4. Global Scripts -->
            <h3 style="margin-bottom:1rem;">Site-wide Script Injection</h3>
            <div class="form-group">
                <label class="form-label">Header Scripts (Search Console, GA4 tags, Pixel)</label>
                <textarea name="site_head_scripts" class="form-control" rows="5" style="font-family:monospace; font-size:0.8rem;" placeholder="<script>...</script>"><?php echo htmlspecialchars($siteHeadScripts); ?></textarea>
                <span class="text-muted" style="font-size:0.75rem;">Injected site-wide inside the head tag of every front-end page.</span>
            </div>

            <hr style="border:none; border-top:1px solid var(--border-color); margin:2rem 0;">

            <!-- 5. CAPTCHA Settings -->
            <h3 style="margin-bottom:1rem;">Anti-Spam / CAPTCHA Protection</h3>
            <div class="form-group">
                <label class="form-label">Enable CAPTCHA Protection</label>
                <select name="captcha_enabled" class="form-control">
                    <option value="0" <?php echo $captchaEnabled === '0' ? 'selected' : ''; ?>>Disabled</option>
                    <option value="1" <?php echo $captchaEnabled === '1' ? 'selected' : ''; ?>>Enabled</option>
                </select>
                <span class="text-muted" style="font-size:0.75rem;">Enforces CAPTCHA checks on public forms (trial claims, login, registration, support tickets).</span>
            </div>
            <div class="form-group">
                <label class="form-label">CAPTCHA Provider</label>
                <select name="captcha_provider" class="form-control" id="captcha-provider-select" onchange="toggleCaptchaFields()">
                    <option value="local" <?php echo $captchaProvider === 'local' ? 'selected' : ''; ?>>Local Mathematical Challenge (Zero-config)</option>
                    <option value="hcaptcha" <?php echo $captchaProvider === 'hcaptcha' ? 'selected' : ''; ?>>hCaptcha</option>
                    <option value="recaptcha" <?php echo $captchaProvider === 'recaptcha' ? 'selected' : ''; ?>>Google reCAPTCHA v2</option>
                </select>
            </div>
            <div id="captcha-api-fields" style="display: <?php echo ($captchaProvider === 'hcaptcha' || $captchaProvider === 'recaptcha') ? 'block' : 'none'; ?>;">
                <div class="form-group">
                    <label class="form-label">Site Key</label>
                    <input type="text" name="captcha_site_key" class="form-control" value="<?php echo htmlspecialchars($captchaSiteKey); ?>" placeholder="e.g. 10000000-ffff-2222-...">
                </div>
                <div class="form-group">
                    <label class="form-label">Secret Key</label>
                    <input type="password" name="captcha_secret_key" class="form-control" value="<?php echo htmlspecialchars($captchaSecretKey); ?>" placeholder="e.g. 0x0000000000000000000000000000000000000000">
                </div>
            </div>
            
            <script>
            function toggleCaptchaFields() {
                var select = document.getElementById('captcha-provider-select');
                var fields = document.getElementById('captcha-api-fields');
                if (select.value === 'local') {
                    fields.style.display = 'none';
                } else {
                    fields.style.display = 'block';
                }
            }
            </script>

            <button type="submit" class="btn-sm btn-primary" style="padding:0.75rem 1.5rem; margin-top:1rem;">Save All Configurations</button>
        </form>
    </div>

    <!-- RIGHT COLUMN: UTILITY TOOLS & SMTP TEST -->
    <div style="display:flex; flex-direction:column; gap:2rem;">
        <!-- SMTP Test Send card -->
        <div class="grid-card">
            <h3>Test SMTP Configuration</h3>
            <span class="text-muted" style="font-size:0.8rem; display:block; margin:0.5rem 0 1.5rem 0;">Sends a test email to verify connection. The values below are matched with the left panel.</span>
            
            <form action="index.php?view=settings" method="post" id="smtp-test-form">
                <?php echo Csrf::getHiddenInput(); ?>
                <input type="hidden" name="action" value="test_smtp">

                <!-- Bind values dynamically from left panel using JS before submission -->
                <input type="hidden" name="smtp_host" id="test-smtp-host">
                <input type="hidden" name="smtp_port" id="test-smtp-port">
                <input type="hidden" name="smtp_user" id="test-smtp-user">
                <input type="hidden" name="smtp_pass" id="test-smtp-pass">
                <input type="hidden" name="smtp_enc" id="test-smtp-enc">
                <input type="hidden" name="smtp_from_email" id="test-smtp-from-email">
                <input type="hidden" name="smtp_from_name" id="test-smtp-from-name">

                <div class="form-group">
                    <label class="form-label">Recipient Email Address</label>
                    <input type="email" name="test_email" class="form-control" required placeholder="e.g. youraddress@email.com" value="<?php echo htmlspecialchars($admin['email']); ?>">
                </div>

                <button type="submit" class="btn-sm btn-primary" style="width:100%;">Trigger Send Test Email</button>
            </form>
        </div>

        <!-- Database Tools -->
        <div class="grid-card">
            <h3>Database & System Backup</h3>
            <span class="text-muted" style="font-size:0.8rem; display:block; margin:0.5rem 0 1.5rem 0;">Download a complete SQL file dump of all CRXSM data tables.</span>
            
            <div style="display:flex; flex-direction:column; gap:1rem;">
                <a href="index.php?view=settings&action=db_backup" class="btn-sm btn-primary" style="text-align:center; text-decoration:none;">Download Database SQL Dump</a>
                
                <div style="background:#f8fafc; border:1px solid var(--border-color); border-radius:8px; padding:1rem; font-size:0.85rem; margin-top:1rem;">
                    <strong>System Info</strong>
                    <div style="margin-top:0.5rem; display:flex; flex-direction:column; gap:0.25rem; color:var(--text-muted);">
                        <span>MySQL Server: <?php echo htmlspecialchars(DB::getConn()->getAttribute(PDO::ATTR_SERVER_VERSION)); ?></span>
                        <span>PHP Version: <?php echo PHP_VERSION; ?></span>
                        <span>Max Upload: <?php echo ini_get('upload_max_filesize'); ?></span>
                        <span>Timezone: <?php echo date_default_timezone_get(); ?></span>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    // Bind SMTP values dynamically on submission to SMTP test form
    document.getElementById('smtp-test-form').addEventListener('submit', function(e) {
        const settingsForm = document.getElementById('settings-form');
        document.getElementById('test-smtp-host').value = settingsForm.querySelector('[name=smtp_host]').value;
        document.getElementById('test-smtp-port').value = settingsForm.querySelector('[name=smtp_port]').value;
        document.getElementById('test-smtp-user').value = settingsForm.querySelector('[name=smtp_user]').value;
        document.getElementById('test-smtp-pass').value = settingsForm.querySelector('[name=smtp_pass]').value;
        document.getElementById('test-smtp-enc').value = settingsForm.querySelector('[name=smtp_enc]').value;
        document.getElementById('test-smtp-from-email').value = settingsForm.querySelector('[name=smtp_from_email]').value;
        document.getElementById('test-smtp-from-name').value = settingsForm.querySelector('[name=smtp_from_name]').value;
    });

    function addFooterLinkRow() {
        const container = document.getElementById('footer-links-container');
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.gap = '0.5rem';
        row.style.alignItems = 'center';
        row.innerHTML = `
            <input type="text" name="f2_labels[]" class="form-control" placeholder="Label" style="flex:1;">
            <input type="text" name="f2_urls[]" class="form-control" placeholder="URL" style="flex:2;">
            <button type="button" class="btn-sm btn-danger" onclick="this.parentElement.remove()">Remove</button>
        `;
        container.appendChild(row);
    }

    function addSocialLinkRow() {
        const container = document.getElementById('footer-socials-container');
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.gap = '0.5rem';
        row.style.alignItems = 'center';
        row.innerHTML = `
            <input type="text" name="f3_names[]" class="form-control" placeholder="Social Platform (e.g. Twitter)" style="flex:1;">
            <input type="text" name="f3_urls[]" class="form-control" placeholder="Profile URL" style="flex:2;">
            <button type="button" class="btn-sm btn-danger" onclick="this.parentElement.remove()">Remove</button>
        `;
        container.appendChild(row);
    }
</script>
