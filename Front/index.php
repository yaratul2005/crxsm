<?php
/**
 * CRXSM Front Router & Public Site
 */
define('CRXSM_ACCESS', true);

// 1. Setup Autoloader
spl_autoload_register(function ($class) {
    $prefix = 'Vault\\';
    $base_dir = dirname(__DIR__) . '/Vault/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});

use Vault\DB;
use Vault\Auth;
use Vault\Crypto;
use Vault\Csrf;
use Vault\Storage;
use Vault\Audit;

// Start session
Auth::startSession();

// Load Config
$configPath = dirname(__DIR__) . '/Vault/config.php';
if (!file_exists($configPath)) {
    die("CRXSM is not installed. Please run <a href='/Setup/index.php'>the installer</a>.");
}
$config = require($configPath);
$baseUrl = rtrim($config['base_url'], '/');

// Parse requested relative path
$baseUrlPath = parse_url($baseUrl, PHP_URL_PATH) ?? '';
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '';

if (!empty($baseUrlPath) && strpos($requestUri, $baseUrlPath) === 0) {
    $requestUri = substr($requestUri, strlen($baseUrlPath));
}
$path = trim($requestUri, '/');

// Helper to get settings
function getSetting(string $key, string $default = ''): string {
    try {
        $row = DB::fetch("SELECT setting_value FROM settings WHERE setting_key = :key", [':key' => $key]);
        return $row['setting_value'] ?? $default;
    } catch (Exception $e) {
        return $default;
    }
}

// Fetch site metadata
$siteName = getSetting('site_name', 'CRXSM Platform');
$siteDesc = getSetting('site_description', 'Software Licensing Hub');
$siteHeadScripts = getSetting('site_head_scripts', '');

// Fetch footer info
$footerZone1 = getSetting('footer_zone_1', '');
$footerZone2Json = getSetting('footer_zone_2', '[]');
$footerZone3Json = getSetting('footer_zone_3', '{"logo":"","socials":[]}');

$footerZone2 = json_decode($footerZone2Json, true) ?: [];
$footerZone3 = json_decode($footerZone3Json, true) ?: [];

// Router Logic
$pageTitle = $siteName;
$pageDescription = $siteDesc;
$pageHeadScripts = '';
$routeContent = '';

// Auth Actions
if ($path === 'login') {
    if (Auth::isCustomerLoggedIn()) {
        header("Location: $baseUrl/dashboard");
        exit;
    }
    $pageTitle = "Login - " . $siteName;
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        Csrf::verifyOrDie();
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        
        $user = DB::fetch("SELECT * FROM users WHERE email = :email", [':email' => $email]);
        if ($user && password_verify($password, $user['password'])) {
            if ($user['status'] === 'suspended') {
                $error = "Your account has been suspended.";
            } else {
                Auth::loginCustomer((int)$user['id'], $user['email'], $user['name']);
                Audit::log('customer', (int)$user['id'], 'login', "Customer logged in");
                header("Location: $baseUrl/dashboard");
                exit;
            }
        } else {
            $error = "Invalid email or password.";
        }
    }
    
    ob_start();
    ?>
    <div class="auth-card">
        <h2>Customer Login</h2>
        <?php if (isset($error)): ?><div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
        <form action="<?php echo $baseUrl; ?>/login" method="post">
            <?php echo Csrf::getHiddenInput(); ?>
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" required placeholder="name@example.com">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
        <p class="auth-switch">Don't have an account? <a href="<?php echo $baseUrl; ?>/register">Register here</a></p>
    </div>
    <?php
    $routeContent = ob_get_clean();

} elseif ($path === 'register') {
    if (Auth::isCustomerLoggedIn()) {
        header("Location: $baseUrl/dashboard");
        exit;
    }
    $pageTitle = "Create Account - " . $siteName;
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        Csrf::verifyOrDie();
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $password_conf = $_POST['password_confirm'] ?? '';
        
        if (strlen($name) < 2) {
            $error = "Please enter your name.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Please enter a valid email address.";
        } elseif (strlen($password) < 8) {
            $error = "Password must be at least 8 characters.";
        } elseif ($password !== $password_conf) {
            $error = "Passwords do not match.";
        } else {
            // Check existing
            $existing = DB::fetch("SELECT id FROM users WHERE email = :email", [':email' => $email]);
            if ($existing) {
                $error = "An account with this email already exists.";
            } else {
                $hashed = password_hash($password, PASSWORD_BCRYPT);
                DB::execute(
                    "INSERT INTO users (name, email, password, status) VALUES (:name, :email, :password, 'active')",
                    [':name' => $name, ':email' => $email, ':password' => $hashed]
                );
                $newId = (int)DB::lastInsertId();
                Auth::loginCustomer($newId, $email, $name);
                Audit::log('customer', $newId, 'registered', "New customer registered");
                header("Location: $baseUrl/dashboard");
                exit;
            }
        }
    }
    
    ob_start();
    ?>
    <div class="auth-card">
        <h2>Register Account</h2>
        <?php if (isset($error)): ?><div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
        <form action="<?php echo $baseUrl; ?>/register" method="post">
            <?php echo Csrf::getHiddenInput(); ?>
            <div class="form-group">
                <label>Your Name</label>
                <input type="text" name="name" required placeholder="e.g. John Doe" value="<?php echo htmlspecialchars($_POST['name'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" required placeholder="name@example.com" value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="Minimum 8 characters">
            </div>
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="password_confirm" required>
            </div>
            <button type="submit" class="btn">Register</button>
        </form>
        <p class="auth-switch">Already have an account? <a href="<?php echo $baseUrl; ?>/login">Login here</a></p>
    </div>
    <?php
    $routeContent = ob_get_clean();

} elseif ($path === 'logout') {
    Auth::logoutCustomer();
    header("Location: $baseUrl");
    exit;

} elseif ($path === 'dashboard') {
    if (!Auth::isCustomerLoggedIn()) {
        header("Location: $baseUrl/login");
        exit;
    }
    $pageTitle = "Dashboard - " . $siteName;
    
    // Process dashboard logic in separate dashboard page
    ob_start();
    require __DIR__ . '/dashboard.php';
    $routeContent = ob_get_clean();

} elseif ($path === 'claim-trial') {
    // POST request to trigger trial verification mail
    $error = null;
    $success = null;
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        Csrf::verifyOrDie();
        $email = trim($_POST['email'] ?? '');
        $name = trim($_POST['name'] ?? '');

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Please enter a valid email address.";
        } elseif (empty($name)) {
            $error = "Please enter your name.";
        } else {
            // Generate signed verification token valid for 2 hours
            $expires = time() + 7200;
            $token = hash_hmac('sha256', $email . '.' . $expires, $masterKey);
            
            $verifyLink = $baseUrl . '/verify-trial?email=' . urlencode($email) . '&name=' . urlencode($name) . '&expires=' . $expires . '&token=' . $token;
            
            $subject = "Verify Your Email - Ratuls ACT";
            $message = "<h3>Welcome to Ratuls ACT!</h3>" .
                       "<p>Hello " . htmlspecialchars($name) . ",</p>" .
                       "<p>You are one click away from claiming your 1-Year Free Trial License for <strong>Ratuls ACT (Ratul Ads Conversion Tracker)</strong>.</p>" .
                       "<p>Please click the button below to verify your email and issue your license key:</p>" .
                       "<p><a href='{$verifyLink}' style='display:inline-block; padding:10px 20px; background:#6366f1; color:#fff; text-decoration:none; border-radius:6px; font-weight:bold;'>Verify Email & Claim Trial</a></p>" .
                       "<p><small>This link is valid for 2 hours.</small></p>";
                       
            if (\Vault\Mailer::send($email, $subject, $message)) {
                $success = "Verification email sent successfully! Please check your inbox (and spam folder) to complete your activation.";
            } else {
                $error = "Failed to send verification email. Please check SMTP configuration or contact the administrator.";
            }
        }
    }
    
    // Display result page
    $pageTitle = "Claim Trial - " . $siteName;
    ob_start();
    ?>
    <div class="auth-card" style="max-width:550px; text-align:center;">
        <h2>Free Trial Verification</h2>
        <?php if ($error !== null): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <a href="<?php echo $baseUrl; ?>" class="btn" style="margin-top:1rem;">Back to Home</a>
        <?php elseif ($success !== null): ?>
            <div class="success-illustration" style="margin: 1.5rem 0;">
                <div class="success-icon" style="border-color:var(--success); color:var(--success); font-size: 3rem; width: 60px; height: 60px; border-radius: 50%; border: 2px solid; display: inline-flex; align-items: center; justify-content: center;">&checkmark;</div>
            </div>
            <div style="color:var(--text-muted); line-height:1.6; margin-bottom:1.5rem; font-size:0.95rem;">
                <?php echo htmlspecialchars($success); ?>
            </div>
            <a href="<?php echo $baseUrl; ?>" class="btn">Back to Home</a>
        <?php endif; ?>
    </div>
    <?php
    $routeContent = ob_get_clean();

} elseif ($path === 'verify-trial') {
    // GET verification link
    $email = $_GET['email'] ?? '';
    $name = $_GET['name'] ?? '';
    $expires = (int)($_GET['expires'] ?? 0);
    $token = $_GET['token'] ?? '';

    $error = '';
    $success = '';

    // Verify token
    $expected = hash_hmac('sha256', $email . '.' . $expires, $masterKey);
    if (time() > $expires) {
        $error = "The verification link has expired. Please go back to the homepage and submit again.";
    } elseif (!hash_equals($expected, $token)) {
        $error = "Invalid verification signature. Request tampering detected.";
    } else {
        try {
            // Find or create customer
            $user = DB::fetch("SELECT id, name FROM users WHERE email = :email", [':email' => $email]);
            if (!$user) {
                // Auto-register customer
                $randomPass = bin2hex(random_bytes(6));
                $hashed = password_hash($randomPass, PASSWORD_BCRYPT);
                DB::execute(
                    "INSERT INTO users (name, email, password, status) VALUES (:name, :email, :password, 'active')",
                    [':name' => $name, ':email' => $email, ':password' => $hashed]
                );
                $userId = (int)DB::lastInsertId();
                Audit::log('customer', $userId, 'auto_register', "Auto-registered via trial request");
                $newRegistration = true;
            } else {
                $userId = (int)$user['id'];
                $newRegistration = false;
            }

            // Find Software product for Client ID: sw_542f42eee9271290367d2907fb8bc024
            $softwareClientId = 'sw_542f42eee9271290367d2907fb8bc024';
            $sw = DB::fetch("SELECT * FROM software WHERE client_id = :client_id", [':client_id' => $softwareClientId]);

            if (!$sw) {
                $error = "The product 'Ratuls ACT' is not currently registered in the database registry. Please contact admin.";
            } else {
                // Check if user already holds a license for this software
                $existingLicense = DB::fetch(
                    "SELECT id, license_key FROM licenses WHERE user_id = :user_id AND software_id = :sw_id",
                    [':user_id' => $userId, ':sw_id' => $sw['id']]
                );

                if ($existingLicense) {
                    $licenseKey = $existingLicense['license_key'];
                    $success = "You already hold an active license key for this product. You have been logged in.";
                } else {
                    // Decrypt private key
                    $decryptedPrivateKey = Crypto::decryptSecret($sw['private_key'], $masterKey);

                    // Create 1-year license (Expires in 1 year)
                    $expiresAt = date('Y-m-d H:i:s', strtotime('+1 year'));

                    // Placeholder record
                    DB::execute(
                        "INSERT INTO licenses (software_id, user_id, license_key, activation_limit, status, expires_at) 
                         VALUES (:sw_id, :user_id, '', 5, 'active', :expires_at)",
                        [
                            ':sw_id'      => $sw['id'],
                            ':user_id'    => $userId,
                            ':expires_at' => $expiresAt
                        ]
                    );
                    $newLicId = (int)DB::lastInsertId();

                    // Signed license token payload
                    $licPayload = [
                        'license_id'  => $newLicId,
                        'software_id' => (int)$sw['id'],
                        'user_id'     => $userId,
                        'expires_at'  => $expiresAt
                    ];

                    $licenseKey = Crypto::generateLicenseKey($licPayload, $decryptedPrivateKey);

                    // Update key
                    DB::execute("UPDATE licenses SET license_key = :key WHERE id = :id", [':key' => $licenseKey, ':id' => $newLicId]);
                    
                    Audit::log('system', null, 'auto_issue_trial', "Issued 1-Year Trial License ID {$newLicId} to {$email}");

                    // Send email containing license details
                    $subject = "Your Ratuls ACT License Key & Download Link";
                    $downloadUrl = $baseUrl . '/dashboard';
                    
                    $message = "<h3>Your Free Trial License is Ready!</h3>" .
                               "<p>Hello " . htmlspecialchars($name) . ",</p>" .
                               "<p>Thank you for verifying your email. Your 1-Year Free Trial License for <strong>Ratuls ACT (Ratul Ads Conversion Tracker)</strong> has been issued successfully.</p>" .
                               "<p><strong>License Key:</strong></p>" .
                               "<pre style='background:#f1f5f9; padding:10px; border-radius:6px; font-family:monospace; border:1px solid #cbd5e1; word-break:break-all;'>{$licenseKey}</pre>" .
                               "<p><strong>Ed25519 Public Verification Key:</strong></p>" .
                               "<pre style='background:#f1f5f9; padding:10px; border-radius:6px; font-family:monospace; border:1px solid #cbd5e1; word-break:break-all;'>{$sw['public_key']}</pre>" .
                               "<p>To download the plugin, log into your customer dashboard:</p>" .
                               "<p><a href='{$downloadUrl}' style='display:inline-block; padding:10px 20px; background:#6366f1; color:#fff; text-decoration:none; border-radius:6px; font-weight:bold;'>Go to Dashboard & Download</a></p>";
                    
                    if (isset($randomPass)) {
                        $message .= "<p>We have auto-registered an account for you. Use these details to log in:<br>" .
                                    "<strong>Email:</strong> {$email}<br>" .
                                    "<strong>Temporary Password:</strong> {$randomPass}</p>" .
                                    "<p>You can change this password at any time in your dashboard profile settings.</p>";
                    }

                    \Vault\Mailer::send($email, $subject, $message);
                    $success = "Email verified successfully! Your 1-Year Free Trial License key has been issued and sent to your email address.";
                }

                // Log customer in automatically
                Auth::loginCustomer($userId, $email, $name);
            }
        } catch (Exception $e) {
            $error = "System error during validation: " . $e->getMessage();
        }
    }

    $pageTitle = "Email Verified - " . $siteName;
    ob_start();
    ?>
    <div class="auth-card" style="max-width:550px; text-align:center;">
        <h2>Verification Result</h2>
        <?php if (!empty($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <a href="<?php echo $baseUrl; ?>" class="btn">Back to Home</a>
        <?php else: ?>
            <div class="success-illustration" style="margin: 1.5rem 0;">
                <div class="success-icon" style="border-color:var(--success); color:var(--success); font-size: 3rem; width: 60px; height: 60px; border-radius: 50%; border: 2px solid; display: inline-flex; align-items: center; justify-content: center;">&checkmark;</div>
            </div>
            <h3 style="color:var(--success); margin-bottom:1rem;">Verified successfully!</h3>
            <div style="color:var(--text-muted); line-height:1.6; margin-bottom:2rem; font-size:0.95rem;">
                <?php echo htmlspecialchars($success); ?>
            </div>
            <a href="<?php echo $baseUrl; ?>/dashboard" class="btn">Go to Dashboard</a>
        <?php endif; ?>
    </div>
    <?php
    $routeContent = ob_get_clean();

} elseif (strpos($path, 'download/') === 0) {
    if (!Auth::isCustomerLoggedIn()) {
        header("Location: $baseUrl/login");
        exit;
    }
    $versionId = (int)substr($path, 9);
    
    // Verify customer owns a license for the software this version belongs to
    $customer = Auth::getCurrentCustomer();
    $version = DB::fetch(
        "SELECT sv.*, s.slug as software_slug FROM software_versions sv 
         JOIN software s ON sv.software_id = s.id 
         WHERE sv.id = :id", 
        [':id' => $versionId]
    );

    if ($version) {
        // Find if user has an active/non-revoked license for this software
        $license = DB::fetch(
            "SELECT id FROM licenses 
             WHERE user_id = :user_id AND software_id = :software_id 
             AND status NOT IN ('revoked', 'expired')",
            [':user_id' => $customer['id'], ':software_id' => $version['software_id']]
        );

        if ($license) {
            Audit::log('customer', $customer['id'], 'download_software', "Downloaded version ID {$versionId} for slug {$version['software_slug']}");
            Storage::serveFile($version['file_path'], $version['software_slug'] . '_v' . $version['version'] . '.zip');
            exit;
        }
    }
    
    http_response_code(403);
    die("Access denied. You do not hold an active license for this software product.");

} else {
    // CMS Pages / Posts Routing
    $slug = empty($path) ? 'home' : $path;

    // 1. Try to find a CMS Page
    $page = DB::fetch("SELECT * FROM pages WHERE slug = :slug AND status = 'published'", [':slug' => $slug]);
    if ($page) {
        $pageTitle = $page['title'] . " - " . $siteName;
        $pageDescription = $page['seo_description'] ?: $siteDesc;
        $pageHeadScripts = $page['head_scripts'] ?: '';
        
        // Check if layout was built with Canvas or Markdown
        if ($page['editor_mode'] === 'canvas') {
            // Layout parser for canvas JSON will be implemented here
            $blocks = json_decode($page['content'], true) ?: [];
            ob_start();
            echo "<div class='canvas-page-render'>";
            foreach ($blocks as $block) {
                $type = $block['type'] ?? 'text';
                $title = htmlspecialchars($block['title'] ?? '', ENT_QUOTES, 'UTF-8');
                $text = htmlspecialchars($block['text'] ?? '', ENT_QUOTES, 'UTF-8');
                $ctaUrl = htmlspecialchars($block['cta_url'] ?? '', ENT_QUOTES, 'UTF-8');
                $ctaText = htmlspecialchars($block['cta_text'] ?? '', ENT_QUOTES, 'UTF-8');

                if ($type === 'hero') {
                    echo "<section class='block-hero'>";
                    echo "<h1>" . $title . "</h1>";
                    echo "<p>" . nl2br($text) . "</p>";
                    if (!empty($ctaUrl)) {
                        echo "<a href='{$ctaUrl}' class='btn'>{$ctaText}</a>";
                    }
                    echo "</section>";
                } elseif ($type === 'features') {
                    echo "<section class='block-features'>";
                    echo "<h2>" . $title . "</h2>";
                    echo "<div class='features-grid'>";
                    $items = $block['items'] ?? [];
                    foreach ($items as $item) {
                        $itName = htmlspecialchars($item['name'] ?? '', ENT_QUOTES, 'UTF-8');
                        $itDesc = htmlspecialchars($item['desc'] ?? '', ENT_QUOTES, 'UTF-8');
                        echo "<div class='feature-card'>";
                        echo "<h3>{$itName}</h3>";
                        echo "<p>{$itDesc}</p>";
                        echo "</div>";
                    }
                    echo "</div>";
                    echo "</section>";
                } elseif ($type === 'cta') {
                    echo "<section class='block-cta'>";
                    echo "<h2>" . $title . "</h2>";
                    echo "<p>" . nl2br($text) . "</p>";
                    echo "<a href='{$ctaUrl}' class='btn'>{$ctaText}</a>";
                    echo "</section>";
                } else {
                    // Plain Text Block
                    echo "<section class='block-text'>";
                    echo "<h2>" . $title . "</h2>";
                    echo "<p>" . nl2br($text) . "</p>";
                    echo "</section>";
                }
            }
            echo "</div>";
            $routeContent = ob_get_clean();
        } else {
            // Markdown rendering
            $routeContent = "<div class='markdown-page-render'>" . nl2br(htmlspecialchars($page['content'])) . "</div>";
        }
    } else {
        // 2. Try to find a CMS Post (if slug starts with "posts/")
        $postSlug = $path;
        if (strpos($path, 'posts/') === 0) {
            $postSlug = substr($path, 6);
        }
        
        $post = DB::fetch("SELECT * FROM posts WHERE slug = :slug AND status = 'published'", [':slug' => $postSlug]);
        if ($post) {
            $pageTitle = $post['title'] . " - " . $siteName;
            $pageDescription = $post['seo_description'] ?: $siteDesc;
            
            ob_start();
            ?>
            <article class="single-post">
                <?php if ($post['featured_image']): ?>
                    <img src="<?php echo htmlspecialchars($post['featured_image']); ?>" class="post-banner" alt="">
                <?php endif; ?>
                <h1 class="post-title"><?php echo htmlspecialchars($post['title']); ?></h1>
                <div class="post-meta">Published on <?php echo date('M d, Y', strtotime($post['published_at'] ?? $post['created_at'])); ?></div>
                <div class="post-body">
                    <?php echo nl2br(htmlspecialchars($post['content'])); ?>
                </div>
            </article>
            <?php
            $routeContent = ob_get_clean();
        } else {
            // 3. Fallback: Default Front Page if empty path & no home page exists
            if (empty($path)) {
                $pageTitle = "Ratuls ACT - Self-Hosted Ads Conversion Tracker";
                $pageDescription = "Defeat Safari ITP & ad-blockers with a professional, first-party server-side Conversion API (CAPI) WordPress plugin by Yaser Ahmmed Ratul.";
                ob_start();
                ?>
                <!-- Decorative Glow Backgrounds -->
                <div class="glow-orb orb-1"></div>
                <div class="glow-orb orb-2"></div>
                <div class="grid-overlay"></div>

                <!-- Hero Section -->
                <div class="landing-hero">
                    <div class="hero-left">
                        <span class="badge-tag"><span class="badge-dot"></span> Professional WordPress CAPI</span>
                        <h1>Defeat Safari ITP & Reclaim 100% of Your Ad Conversions</h1>
                        <p>
                            Don't waste money on server-side tracking containers. <strong>Ratuls ACT</strong> (Ratul Ads Conversion Tracker) runs natively on your WordPress server as a self-hosted, First-Party CAPI Gateway to boost Event Match Quality (EMQ) automatically.
                        </p>
                        
                        <div class="features-bullets">
                            <div class="bullet"><span class="bullet-check">&checkmark;</span> <strong>Safari ITP Bypass:</strong> PHP set-cookie extends click IDs from 7 days to 2 years</div>
                            <div class="bullet"><span class="bullet-check">&checkmark;</span> <strong>Ad-Blocker Resilience:</strong> Proxies events through a local REST endpoint</div>
                            <div class="bullet"><span class="bullet-check">&checkmark;</span> <strong>Advanced Deduplication:</strong> Seeds browser & server event IDs 1-to-1</div>
                        </div>

                        <div style="margin-top: 2rem; display: flex; gap: 1rem; flex-wrap: wrap;">
                            <a href="#trial-section" class="btn" style="max-width: 240px; box-shadow: 0 0 20px rgba(99, 102, 241, 0.4);">Claim Free Trial Key</a>
                            <a href="https://github.com/yaratul2005/ServerTrack" target="_blank" rel="noopener noreferrer" class="btn btn-secondary" style="max-width: 200px;">GitHub Repo</a>
                        </div>
                    </div>

                    <div class="hero-right">
                        <div class="code-window">
                            <div class="code-window-header">
                                <span class="dot red"></span>
                                <span class="dot yellow"></span>
                                <span class="dot green"></span>
                                <span class="title">class-ratuls-act.php</span>
                            </div>
                            <pre class="code-window-body"><code><span class="keyword">class</span> <span class="classname">RatulsACT_Tracker</span> {
  <span class="keyword">private</span> <span class="variable">$first_party</span> = <span class="keyword">true</span>;
  <span class="keyword">private</span> <span class="variable">$cookie_lifespan</span> = <span class="string">'2_years'</span>;

  <span class="keyword">public</span> <span class="keyword">function</span> <span class="classname">dispatch_to_capi</span>(<span class="variable">$event</span>) {
    <span class="keyword">return</span> <span class="variable">$this</span>->enrich_payload(<span class="variable">$event</span>)
      ->stitch_identity()
      ->deduplicate_events()
      ->push_async();
  }
}
<span class="comment">// Self-hosted $0 monthly tracking gateway</span></code></pre>
                        </div>
                    </div>
                </div>

                <!-- Product Features Grid -->
                <div class="landing-features">
                    <span class="badge-tag" style="margin: 0 auto 1rem auto; display: table;">Robust Architecture</span>
                    <h2>Advanced Server-Side Tracking Mechanics</h2>
                    <p style="text-align:center; color:var(--text-muted); max-width:600px; margin: 0.5rem auto 3rem auto;">
                        Designed to bypass browser privacy rules, extend cookie lifespans, and deliver high Event Match Quality (EMQ) directly to Meta, TikTok, and Google.
                    </p>
                    
                    <div class="features-grid">
                        <div class="feature-card glow-base">
                            <div class="feat-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 11l2 2 4-4"/></svg>
                            </div>
                            <h3>ITP Bypass (2-Year Cookies)</h3>
                            <p>Generates secure first-party HTTP headers via PHP, extending click identifiers (fbclid, gclid) from the JS-capped 7 days to a full 2 years.</p>
                        </div>
                        <div class="feature-card glow-base">
                            <div class="feat-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                            </div>
                            <h3>Ad-blocker Resiliency</h3>
                            <p>Bypasses browser blockers entirely by proxying tracking events through local WordPress REST endpoints.</p>
                        </div>
                        <div class="feature-card glow-base">
                            <div class="feat-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                            </div>
                            <h3>Deep Identity Stitching</h3>
                            <p>Bundles MaxMind GeoIP resolution, true client IP detection across proxies, and user-agent matching to boost match quality.</p>
                        </div>
                        <div class="feature-card glow-base">
                            <div class="feat-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 3h5v5M8 21H3v-5M12 3a9 9 0 0 1 9 9M12 21a9 9 0 0 1-9-9"/></svg>
                            </div>
                            <h3>Perfect Deduplication</h3>
                            <p>Aligns browser pixel event ID seeds with server-side Graph API triggers to avoid double-counting conversion events.</p>
                        </div>
                        <div class="feature-card glow-base">
                            <div class="feat-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                            </div>
                            <h3>Multi-Pixel Engines</h3>
                            <p>Fires WooCommerce events concurrently to multiple Meta Graph pixel accounts, TikTok Events API v2, and Google Ads Enhanced conversions.</p>
                        </div>
                        <div class="feature-card glow-base">
                            <div class="feat-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                            </div>
                            <h3>Diagnostics Debug Console</h3>
                            <p>Features live Server-Sent Events (SSE) diagnostic streams, local SQL logs, and a background retry queue with exponential back-off.</p>
                        </div>
                    </div>
                </div>

                <!-- Meet The Creator Section -->
                <div class="creator-section">
                    <div class="creator-container">
                        <div class="creator-photo">
                            <div class="photo-glow-border">
                                <img src="https://yaratul.com/media/yar.jpeg" alt="Yaser Ahmmed Ratul">
                            </div>
                        </div>
                        <div class="creator-details">
                            <span class="badge-tag">Meet the Inventor</span>
                            <h2>Yaser Ahmmed Ratul</h2>
                            <p class="creator-subtitle">Full-Stack Developer, DevOps & SEO Specialist</p>
                            <div class="creator-bio">
                                <p>
                                    "I invented this tracking system to replace expensive third-party container services that charge digital marketers $20-$120 a month for simple data loopbacks. Ratuls ACT runs directly on your own WordPress hosting server, giving you full data control with zero monthly cost."
                                </p>
                                <p style="margin-top: 1rem; color: var(--text-color);">
                                    Yaser is a Google-Certified AI Professional, WordPress Core Optimizer, and DevOps Engineer based in Cumilla, Bangladesh. He built this system to democratize high-match-quality tracking for digital marketers worldwide.
                                </p>
                            </div>
                            <div style="margin-top: 1.5rem;">
                                <a href="https://yaratul.com" target="_blank" rel="noopener noreferrer" class="btn btn-secondary" style="max-width: 220px; display: inline-flex; align-items: center; gap: 0.5rem;">
                                    Visit Official Portfolio
                                    <span style="font-size: 0.8rem;">&#8599;</span>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Price Comparison Section -->
                <div class="landing-comparison">
                    <h2 style="text-align:center; margin-bottom:1rem;">Stop Overpaying for Cloud Servers</h2>
                    <p style="text-align:center; color:var(--text-muted); margin-bottom:3rem;">Why pay monthly fees to third-party containers when you can host it yourself?</p>
                    
                    <div style="overflow-x:auto;">
                        <table class="compare-table">
                            <thead>
                                <tr>
                                    <th>Tracking Tool</th>
                                    <th>Host Location</th>
                                    <th>Pricing Model</th>
                                    <th>Your Cost</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>Stape.io / GTM Containers</td>
                                    <td>Third-Party Cloud Servers</td>
                                    <td>Monthly Subscription (by volume)</td>
                                    <td style="color:var(--danger); font-weight:600;">$20 - $120 / mo</td>
                                </tr>
                                <tr>
                                    <td>Google Cloud Platform Tag Manager</td>
                                    <td>Google Cloud Run instances</td>
                                    <td>Standard GCP Resource Consumption</td>
                                    <td style="color:var(--danger); font-weight:600;">$30 - $150 / mo</td>
                                </tr>
                                <tr class="active-row">
                                    <td><strong>Ratuls ACT (Self-Hosted)</strong></td>
                                    <td><strong>Local WordPress Server</strong></td>
                                    <td><strong>100% Self-Hosted Open-Source</strong></td>
                                    <td style="color:var(--success); font-weight:800; font-size:1.15rem;">$0 / Forever Free</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Lead Trial Capture Form Section -->
                <div id="trial-section" style="padding: 6rem 0 2rem 0; text-align: center; max-width: 600px; margin: 0 auto;">
                    <span class="badge-tag" style="margin-bottom: 1rem;">Instant Onboarding</span>
                    <h2>Claim Your 1-Year Free License Key</h2>
                    <p style="color: var(--text-muted); margin: 0.5rem 0 2.5rem 0; font-size: 0.95rem;">
                        Verify your email address to automatically register a customer dashboard account and receive your signed Ed25519 license token.
                    </p>
                    
                    <div class="trial-card glow-base" style="margin-top: 1rem;">
                        <form action="<?php echo $baseUrl; ?>/claim-trial" method="post">
                            <?php echo Csrf::getHiddenInput(); ?>
                            <div class="form-group">
                                <label class="form-label">Your Name</label>
                                <input type="text" name="name" required placeholder="e.g. Yaser Ratul">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Email Address</label>
                                <input type="email" name="email" required placeholder="e.g. owner@yaratul.com">
                            </div>
                            <button type="submit" class="btn" style="padding: 1rem; font-size: 1rem; margin-top: 1rem; font-weight: 700; box-shadow: 0 4px 20px rgba(99,102,241,0.3);">
                                Send Verification Link
                            </button>
                        </form>
                        <span style="font-size:0.75rem; color:var(--text-muted); display:block; margin-top:1.25rem;">
                            *No credit card required. Free updates and secure zip file downloads included.
                        </span>
                    </div>
                </div>
                <?php
                $routeContent = ob_get_clean();
            } else {
                // 4. Return 404
                http_response_code(404);
                $pageTitle = "Page Not Found - " . $siteName;
                $routeContent = "<div class='error-container'><h1>404</h1><p>The page you are looking for does not exist.</p><a href='$baseUrl' class='btn' style='max-width:200px; margin-top:2rem;'>Go Home</a></div>";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle); ?></title>
    <meta name="description" content="<?php echo htmlspecialchars($pageDescription); ?>">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.4);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --success: #10b981;
            --danger: #ef4444;
            --glow: rgba(99, 102, 241, 0.1);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.06) 0px, transparent 50%);
            color: var(--text-color);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Header Navigation */
        header.site-nav {
            border-bottom: 1px solid var(--border-color);
            background: rgba(11, 15, 25, 0.8);
            backdrop-filter: blur(16px);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 1.25rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .nav-logo {
            font-size: 1.6rem;
            font-weight: 700;
            color: #fff;
            text-decoration: none;
            letter-spacing: -0.5px;
        }

        .nav-logo span {
            color: var(--primary);
        }

        .nav-links {
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }

        .nav-links a {
            color: var(--text-muted);
            text-decoration: none;
            font-size: 0.95rem;
            font-weight: 500;
            transition: color 0.2s;
        }

        .nav-links a:hover {
            color: #fff;
        }

        .nav-links a.btn-nav {
            padding: 0.5rem 1.2rem;
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 8px;
            color: var(--primary);
        }

        .nav-links a.btn-nav:hover {
            background: var(--primary);
            color: #fff;
        }

        /* Main Container */
        main.main-content {
            flex: 1;
            max-width: 1200px;
            width: 100%;
            margin: 0 auto;
            padding: 4rem 2rem;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        @media (max-width: 768px) {
            .nav-container {
                flex-direction: column;
                gap: 1rem;
                padding: 1rem;
            }
            .nav-links {
                gap: 1.25rem;
                flex-wrap: wrap;
                justify-content: center;
                width: 100%;
            }
            main.main-content {
                padding: 2rem 1rem;
            }
            .auth-card {
                padding: 2rem 1.5rem;
            }
        }

        /* Glassmorphic Form Card */
        .auth-card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 3rem 2.5rem;
            max-width: 480px;
            width: 100%;
            margin: 0 auto;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }

        .auth-card h2 {
            font-size: 1.6rem;
            font-weight: 600;
            margin-bottom: 2rem;
            text-align: center;
        }

        .auth-switch {
            text-align: center;
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-top: 1.5rem;
        }

        .auth-switch a {
            color: var(--primary);
            text-decoration: none;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        input {
            width: 100%;
            padding: 0.8rem 1.2rem;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 10px;
            color: #fff;
            font-family: inherit;
            font-size: 0.95rem;
            transition: all 0.2s;
        }

        input:focus {
            outline: none;
            border-color: var(--primary);
            background: rgba(255, 255, 255, 0.05);
            box-shadow: 0 0 0 4px var(--glow);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 0.8rem 1.5rem;
            background: var(--primary);
            border: none;
            border-radius: 10px;
            color: #fff;
            font-family: inherit;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s, transform 0.1s;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.15);
            text-decoration: none;
        }

        .btn:hover {
            background-color: var(--primary-hover);
        }

        .btn:active {
            transform: scale(0.98);
        }

        .alert {
            padding: 0.8rem 1.2rem;
            border-radius: 8px;
            font-size: 0.9rem;
            margin-bottom: 1.5rem;
        }

        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #fca5a5;
        }

        /* Single Post Styling */
        .single-post {
            max-width: 800px;
            margin: 0 auto;
        }

        .post-banner {
            width: 100%;
            height: 350px;
            object-fit: cover;
            border-radius: 16px;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }

        .post-title {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.75rem;
        }

        .post-meta {
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-bottom: 2.5rem;
        }

        .post-body {
            font-size: 1.1rem;
            line-height: 1.8;
            color: #d1d5db;
        }

        /* Canvas rendering styles */
        .canvas-page-render {
            display: flex;
            flex-direction: column;
            gap: 5rem;
        }

        .block-hero {
            text-align: center;
            padding: 6rem 2rem;
            max-width: 800px;
            margin: 0 auto;
        }

        .block-hero h1 {
            font-size: 3.5rem;
            font-weight: 800;
            line-height: 1.2;
            margin-bottom: 1.5rem;
            background: linear-gradient(135deg, #fff 40%, #a5b4fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .block-hero p {
            font-size: 1.25rem;
            color: var(--text-muted);
            margin-bottom: 2.5rem;
            line-height: 1.6;
        }

        .block-hero .btn {
            max-width: 250px;
        }

        .block-features {
            padding: 2rem 0;
        }

        .block-features h2 {
            font-size: 2rem;
            text-align: center;
            margin-bottom: 3rem;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
        }

        .feature-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
        }

        .feature-card h3 {
            font-size: 1.25rem;
            margin-bottom: 0.75rem;
        }

        .feature-card p {
            color: var(--text-muted);
            line-height: 1.5;
            font-size: 0.95rem;
        }

        .block-cta {
            text-align: center;
            background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(139,92,246,0.05));
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 20px;
            padding: 4rem 2rem;
            max-width: 900px;
            margin: 0 auto;
        }

        .block-cta h2 {
            font-size: 2rem;
            margin-bottom: 1rem;
        }

        .block-cta p {
            color: var(--text-muted);
            margin-bottom: 2rem;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }

        .block-cta .btn {
            max-width: 220px;
        }

        .block-text {
            max-width: 800px;
            margin: 0 auto;
            line-height: 1.7;
        }

        .block-text h2 {
            margin-bottom: 1.25rem;
        }

        .error-container {
            text-align: center;
            padding: 6rem 0;
        }

        .error-container h1 {
            font-size: 6rem;
            font-weight: 800;
            color: var(--primary);
        }

        /* Footer */
        footer.site-footer {
            border-top: 1px solid var(--border-color);
            background: rgba(11, 15, 25, 0.9);
            padding: 4rem 2rem 2rem 2rem;
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        .footer-container {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 2fr 1fr 1fr;
            gap: 4rem;
            margin-bottom: 3rem;
        }

        @media (max-width: 768px) {
            .footer-container {
                grid-template-columns: 1fr;
                gap: 2.5rem;
            }
        }

        .footer-logo {
            font-size: 1.4rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 1rem;
        }

        .footer-logo span {
            color: var(--primary);
        }

        .footer-col h4 {
            color: #fff;
            margin-bottom: 1.25rem;
            font-weight: 600;
        }

        .footer-links {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .footer-links a {
            color: var(--text-muted);
            text-decoration: none;
            transition: color 0.2s;
        }

        .footer-links a:hover {
            color: #fff;
        }

        .social-links {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }

        .social-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 36px;
            height: 36px;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            text-decoration: none;
            transition: all 0.2s;
        }

        .social-icon:hover {
            background: var(--primary);
            color: #fff;
            border-color: var(--primary);
        }

        .footer-bottom {
            max-width: 1200px;
            margin: 0 auto;
            border-top: 1px solid var(--border-color);
            padding-top: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        /* Decorative Background elements */
        .glow-orb {
            position: absolute;
            width: 350px;
            height: 350px;
            border-radius: 50%;
            filter: blur(80px);
            z-index: -2;
            pointer-events: none;
            opacity: 0.15;
            animation: float-orb 15s infinite alternate ease-in-out;
        }
        .orb-1 {
            background: #6366f1;
            top: 15%;
            left: -10%;
        }
        .orb-2 {
            background: #8b5cf6;
            bottom: 20%;
            right: -10%;
            animation-delay: -5s;
        }
        @keyframes float-orb {
            0% { transform: translateY(0) scale(1); }
            50% { transform: translateY(-40px) scale(1.1); }
            100% { transform: translateY(0) scale(1); }
        }
        .grid-overlay {
            position: absolute;
            inset: 0;
            background-image: 
                linear-gradient(rgba(255, 255, 255, 0.007) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.007) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: -1;
        }

        /* Landing Page Marketing Styles */
        .landing-hero {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 4rem;
            padding: 6rem 0;
            max-width: 1200px;
            margin: 0 auto;
            position: relative;
        }
        @media (max-width: 968px) {
            .landing-hero {
                flex-direction: column;
                text-align: center;
                gap: 3rem;
                padding: 3rem 1rem;
            }
        }
        .hero-left {
            flex: 1.2;
        }
        .hero-left h1 {
            font-size: 3.5rem;
            font-weight: 800;
            line-height: 1.15;
            margin: 1.2rem 0 1.5rem 0;
            background: linear-gradient(135deg, #fff 40%, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.02em;
        }
        @media (max-width: 768px) {
            .hero-left h1 {
                font-size: 2.5rem;
            }
        }
        .hero-left p {
            font-size: 1.2rem;
            line-height: 1.7;
            color: var(--text-muted);
            margin-bottom: 2.2rem;
        }
        .badge-tag {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(99, 102, 241, 0.12);
            color: #a5b4fc;
            padding: 0.4rem 1rem;
            border-radius: 50px;
            font-size: 0.8rem;
            font-weight: 600;
            border: 1px solid rgba(99, 102, 241, 0.2);
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }
        .badge-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px var(--success);
        }
        .features-bullets {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        @media (max-width: 968px) {
            .features-bullets {
                align-items: center;
            }
        }
        .bullet {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1rem;
            color: var(--text-color);
        }
        .bullet-check {
            color: var(--success);
            font-weight: bold;
            background: rgba(16, 185, 129, 0.1);
            width: 22px;
            height: 22px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        .hero-right {
            flex: 0.8;
            width: 100%;
            max-width: 480px;
        }

        /* Glassmorphic Code Window */
        .code-window {
            background: rgba(17, 24, 39, 0.55);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            backdrop-filter: blur(24px);
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.4);
            overflow: hidden;
            text-align: left;
            transition: transform 0.3s;
        }
        .code-window:hover {
            transform: translateY(-5px);
        }
        .code-window-header {
            background: rgba(255, 255, 255, 0.02);
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .code-window-header .dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
        }
        .code-window-header .dot.red { background: #ef4444; }
        .code-window-header .dot.yellow { background: #f59e0b; }
        .code-window-header .dot.green { background: #10b981; }
        .code-window-header .title {
            margin-left: auto;
            font-size: 0.75rem;
            font-family: monospace;
            color: var(--text-muted);
        }
        .code-window-body {
            padding: 1.5rem;
            font-family: monospace;
            font-size: 0.85rem;
            line-height: 1.6;
            margin: 0;
            overflow-x: auto;
        }
        .code-window-body .keyword { color: #f43f5e; }
        .code-window-body .classname { color: #38bdf8; }
        .code-window-body .variable { color: #a5b4fc; }
        .code-window-body .string { color: #10b981; }
        .code-window-body .comment { color: #6b7280; font-style: italic; }

        /* Feature Section & Cards */
        .landing-features {
            padding: 6rem 0;
            max-width: 1200px;
            margin: 0 auto;
        }
        .landing-features h2 {
            font-size: 2.5rem;
            font-weight: 800;
            text-align: center;
            margin: 1rem 0;
            background: linear-gradient(135deg, #fff, #9ca3af);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .glow-base {
            position: relative;
            z-index: 1;
        }
        .glow-base::before {
            content: '';
            position: absolute;
            inset: -1px;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.3), rgba(139, 92, 246, 0.1));
            border-radius: 16px;
            z-index: -1;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .glow-base:hover::before {
            opacity: 1;
        }
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }
        .feature-card {
            background: rgba(17, 24, 39, 0.45);
            border: 1px solid rgba(255, 255, 255, 0.06);
            backdrop-filter: blur(12px);
            border-radius: 16px;
            padding: 2.5rem 2rem;
            transition: transform 0.3s, border-color 0.3s;
        }
        .feature-card:hover {
            transform: translateY(-5px);
            border-color: rgba(99, 102, 241, 0.2);
        }
        .feat-icon {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.08);
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #a5b4fc;
        }
        .feature-card h3 {
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
        }
        .feature-card p {
            color: var(--text-muted);
            line-height: 1.6;
            font-size: 0.95rem;
        }

        /* Creator Section Bio */
        .creator-section {
            padding: 6rem 0;
            max-width: 1200px;
            margin: 0 auto;
            border-top: 1px solid rgba(255,255,255,0.04);
        }
        .creator-container {
            display: flex;
            align-items: center;
            gap: 5rem;
            background: rgba(17, 24, 39, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 24px;
            padding: 4rem;
            backdrop-filter: blur(12px);
        }
        @media (max-width: 968px) {
            .creator-container {
                flex-direction: column;
                padding: 2.5rem;
                gap: 3rem;
                text-align: center;
            }
        }
        .creator-photo {
            flex: 0.8;
            display: flex;
            justify-content: center;
        }
        .photo-glow-border {
            position: relative;
            padding: 6px;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.5), rgba(139, 92, 246, 0.2));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .creator-photo img {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            object-fit: cover;
            border: 4px solid var(--bg-color);
        }
        .creator-details {
            flex: 1.2;
        }
        .creator-details h2 {
            font-size: 2.2rem;
            font-weight: 800;
            margin-top: 0.75rem;
        }
        .creator-subtitle {
            color: #a5b4fc;
            font-weight: 500;
            margin-bottom: 1.5rem;
            font-size: 1.05rem;
        }
        .creator-bio {
            line-height: 1.7;
            color: var(--text-muted);
            font-size: 1rem;
        }
        .creator-bio p {
            font-style: italic;
        }

        /* Pricing & Compare Tables */
        .landing-comparison {
            max-width: 1200px;
            margin: 6rem auto;
            padding: 0 1rem;
        }
        .landing-comparison h2 {
            font-size: 2.5rem;
            font-weight: 800;
        }
        .compare-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 3rem;
            background: rgba(17, 24, 39, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            overflow: hidden;
            text-align: left;
        }
        .compare-table th, .compare-table td {
            padding: 1.5rem 2rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            font-size: 0.95rem;
        }
        .compare-table th {
            background: rgba(255, 255, 255, 0.02);
            color: #fff;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .compare-table tr:last-child td {
            border-bottom: none;
        }
        .compare-table tr.active-row {
            background: rgba(99, 102, 241, 0.06);
        }
        .compare-table tr.active-row td {
            border-bottom: 1px solid rgba(99, 102, 241, 0.15);
            color: #fff;
        }
        @media (max-width: 768px) {
            .compare-table th, .compare-table td {
                padding: 1rem 1.2rem;
                font-size: 0.85rem;
            }
        }

        /* Trial Form styling updates */
        .trial-card {
            background: rgba(17, 24, 39, 0.55);
            border: 1px solid rgba(255, 255, 255, 0.07);
            border-radius: 20px;
            padding: 3rem;
            box-shadow: 0 20px 45px rgba(0, 0, 0, 0.35);
            backdrop-filter: blur(24px);
        }
        .trial-card form {
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }
        .trial-card .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            text-align: left;
        }
        .trial-card .form-label {
            font-weight: 500;
            color: var(--text-color);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
    </style>
    <!-- Site wide custom tracking scripts -->
    <?php echo $siteHeadScripts; ?>
    <!-- Per page custom scripts -->
    <?php echo $pageHeadScripts; ?>
</head>
<body>

<header class="site-nav">
    <div class="nav-container">
        <a href="<?php echo $baseUrl; ?>" class="nav-logo"><?php echo htmlspecialchars($siteName); ?></a>
        <nav class="nav-links">
            <a href="<?php echo $baseUrl; ?>">Home</a>
            <?php if (Auth::isCustomerLoggedIn()): ?>
                <a href="<?php echo $baseUrl; ?>/dashboard">Dashboard</a>
                <a href="<?php echo $baseUrl; ?>/logout" class="btn-nav">Logout</a>
            <?php else: ?>
                <a href="<?php echo $baseUrl; ?>/login">Login</a>
                <a href="<?php echo $baseUrl; ?>/register" class="btn-nav">Register</a>
            <?php endif; ?>
        </nav>
    </div>
</header>

<main class="main-content">
    <?php echo $routeContent; ?>
</main>

<footer class="site-footer">
    <div class="footer-container">
        <div class="footer-col">
            <div class="footer-logo"><?php echo htmlspecialchars($siteName); ?></div>
            <div class="footer-text">
                <?php echo $footerZone1; ?>
            </div>
        </div>
        <div class="footer-col">
            <h4>Quick Links</h4>
            <ul class="footer-links">
                <?php foreach ($footerZone2 as $link): ?>
                    <li><a href="<?php echo htmlspecialchars($link['url']); ?>"><?php echo htmlspecialchars($link['label']); ?></a></li>
                <?php endforeach; ?>
                <?php if (empty($footerZone2)): ?>
                    <li><a href="<?php echo $baseUrl; ?>">Home</a></li>
                    <li><a href="<?php echo $baseUrl; ?>/login">Customer Login</a></li>
                <?php endif; ?>
            </ul>
        </div>
        <div class="footer-col">
            <h4>Follow Us</h4>
            <p>Connect with our product updates.</p>
            <div class="social-links">
                <?php 
                $socials = $footerZone3['socials'] ?? [];
                foreach ($socials as $soc): 
                    $label = htmlspecialchars($soc['name'] ?? 'Social');
                    $url = htmlspecialchars($soc['url'] ?? '#');
                ?>
                    <a href="<?php echo $url; ?>" class="social-icon" title="<?php echo $label; ?>" target="_blank">
                        <!-- Simple character-based fallback for icon if class/fontawesome is not loaded -->
                        <?php echo substr($label, 0, 1); ?>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
    <div class="footer-bottom">
        <p>&copy; <?php echo date('Y'); ?> <?php echo htmlspecialchars($siteName); ?>. Powered by CRXSM.</p>
    </div>
</footer>

</body>
</html>
