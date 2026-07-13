<?php
/**
 * CRXSM Front Router & Public Site
 */

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
                $pageTitle = $siteName;
                ob_start();
                ?>
                <div class="block-hero">
                    <h1>Centrally Manage Your Licenses</h1>
                    <p>Issue, track, and validate license keys securely with Ed25519 cryptography.</p>
                    <div style="display:flex; justify-content:center; gap: 1rem; margin-top:2rem;">
                        <a href="<?php echo $baseUrl; ?>/login" class="btn">Customer Dashboard</a>
                        <a href="<?php echo $baseUrl; ?>/Setup/index.php" class="btn" style="background:rgba(255,255,255,0.05); border:1px solid var(--border-color); box-shadow:none;">Run Setup</a>
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
    </style>
    <!-- Site wide custom tracking scripts -->
    <?php echo $siteHeadScripts; ?>
    <!-- Per page custom scripts -->
    <?php echo $pageHeadScripts; ?>
</head>
<body>

<header class="site-nav">
    <div class="nav-container">
        <a href="<?php echo $baseUrl; ?>" class="nav-logo">CR<span>XSM</span></a>
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
            <div class="footer-logo">CR<span>XSM</span></div>
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
