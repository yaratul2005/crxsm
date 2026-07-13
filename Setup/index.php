<?php
/**
 * CRXSM Installation Wizard
 */

// Define workspace layout
$vaultDir = dirname(__DIR__) . '/Vault';
$configFile = $vaultDir . '/config.php';

// Block execution if config file already exists
if (file_exists($configFile)) {
    die("CRXSM is already installed. To run the installer again, delete the Vault/config.php file first.");
}

// Auto-detect base URL
$protocol = isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] === 'on' || $_SERVER['HTTPS'] === 1) ? 'https' : 'http';
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $protocol = 'https';
}
$hostName = $_SERVER['HTTP_HOST'] ?? 'localhost';
$reqUri = $_SERVER['REQUEST_URI'] ?? '/';
$basePath = substr($reqUri, 0, strpos($reqUri, '/Setup'));
$autoBaseUrl = rtrim($protocol . "://" . $hostName . $basePath, '/');

$step = isset($_REQUEST['step']) ? (int)$_REQUEST['step'] : 1;
$errors = [];
$requirements = [];

// Step 1: Requirements Check
if ($step === 1) {
    $requirements['php_version'] = [
        'name' => 'PHP Version >= 8.1',
        'passed' => version_compare(PHP_VERSION, '8.1.0', '>='),
        'desc' => 'Current version: ' . PHP_VERSION
    ];
    $requirements['pdo_mysql'] = [
        'name' => 'PDO MySQL Extension',
        'passed' => extension_loaded('pdo_mysql'),
        'desc' => 'Required for database connections.'
    ];
    $requirements['sodium'] = [
        'name' => 'Sodium Extension',
        'passed' => extension_loaded('sodium'),
        'desc' => 'Required for asymmetric license key signature operations.'
    ];
    $requirements['openssl'] = [
        'name' => 'OpenSSL Extension',
        'passed' => extension_loaded('openssl'),
        'desc' => 'Required for encrypting stored credentials.'
    ];
    $requirements['vault_writable'] = [
        'name' => 'Vault Directory Writable',
        'passed' => is_writable($vaultDir),
        'desc' => 'Needed to save Vault/config.php.'
    ];

    $allPassed = true;
    foreach ($requirements as $req) {
        if (!$req['passed']) {
            $allPassed = false;
        }
    }
}

// Step 2 & 3: DB connection check and validation
$db_host = $_POST['db_host'] ?? 'localhost';
$db_name = $_POST['db_name'] ?? 'crxsm';
$db_user = $_POST['db_user'] ?? 'root';
$db_pass = $_POST['db_pass'] ?? '';
$base_url = $_POST['base_url'] ?? $autoBaseUrl;

if ($step === 3 && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate database connection
    try {
        $dsn = "mysql:host=$db_host;dbname=$db_name;charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ];
        $testPdo = new PDO($dsn, $db_user, $db_pass, $options);
    } catch (PDOException $e) {
        $errors[] = "Failed to connect to database: " . $e->getMessage();
        $step = 2; // fall back to database screen
    }
}

// Step 4: Installation execution
if ($step === 4 && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $admin_user = trim($_POST['admin_user'] ?? '');
    $admin_email = trim($_POST['admin_email'] ?? '');
    $admin_pass = $_POST['admin_pass'] ?? '';
    $admin_pass_conf = $_POST['admin_pass_conf'] ?? '';

    // Validations
    if (empty($admin_user) || strlen($admin_user) < 3) {
        $errors[] = "Admin username must be at least 3 characters.";
    }
    if (!filter_var($admin_email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Please provide a valid email address.";
    }
    if (empty($admin_pass) || strlen($admin_pass) < 8) {
        $errors[] = "Admin password must be at least 8 characters.";
    }
    if ($admin_pass !== $admin_pass_conf) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        try {
            // Establish PDO connection
            $dsn = "mysql:host=$db_host;dbname=$db_name;charset=utf8mb4";
            $pdo = new PDO($dsn, $db_user, $db_pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
            ]);

            // Read schema file
            $schemaFile = __DIR__ . '/schema.sql';
            if (!file_exists($schemaFile)) {
                throw new Exception("Database schema file (Setup/schema.sql) is missing.");
            }
            $schemaSql = file_get_contents($schemaFile);

            // Execute schema (splitting by semicolons is basic, but schema.sql is clean)
            // Using a simple regex split for SQL statement parsing
            $statements = array_filter(array_map('trim', explode(';', $schemaSql)));
            foreach ($statements as $sql) {
                if (!empty($sql)) {
                    $pdo->exec($sql);
                }
            }

            // Create admin user
            $hashedPass = password_hash($admin_pass, PASSWORD_BCRYPT);
            $stmt = $pdo->prepare("INSERT INTO admins (username, email, password, role) VALUES (?, ?, ?, 'admin')");
            $stmt->execute([$admin_user, $admin_email, $hashedPass]);

            // Generate System Master Key
            $systemMasterKey = bin2hex(random_bytes(32));

            // Write config.php
            $configContent = "<?php\n" .
                             "// CRXSM Configuration File\n" .
                             "return [\n" .
                             "    'db' => [\n" .
                             "        'host' => '" . addslashes($db_host) . "',\n" .
                             "        'name' => '" . addslashes($db_name) . "',\n" .
                             "        'user' => '" . addslashes($db_user) . "',\n" .
                             "        'pass' => '" . addslashes($db_pass) . "',\n" .
                             "        'port' => '3306'\n" .
                             "    ],\n" .
                             "    'master_key' => '" . $systemMasterKey . "',\n" .
                             "    'base_url'   => '" . addslashes(rtrim($base_url, '/')) . "',\n" .
                             "    'storage'    => [\n" .
                             "        'upload_dir' => '' // Leave blank for default (Vault/uploads)\n" .
                             "    ]\n" .
                             "];\n";

            if (file_put_contents($configFile, $configContent) === false) {
                throw new Exception("Unable to write configuration file to " . $configFile);
            }

            // Insert basic default settings
            $defaultSettings = [
                'site_name' => 'CRXSM Platform',
                'site_description' => 'Software Licensing & Brand Control Platform',
                'site_head_scripts' => '',
                'footer_zone_1' => '<p>&copy; ' . date('Y') . ' CRXSM. All rights reserved.</p>',
                'footer_zone_2' => '[]', // Auto page links serialized array
                'footer_zone_3' => '{"logo":"","socials":[]}', // Social items serialized
                'smtp_host' => '',
                'smtp_port' => '587',
                'smtp_user' => '',
                'smtp_pass' => '',
                'smtp_enc'  => 'tls',
                'smtp_from_email' => $admin_email,
                'smtp_from_name' => 'CRXSM Licensing'
            ];

            $stmtSetting = $pdo->prepare("INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)");
            foreach ($defaultSettings as $key => $val) {
                $stmtSetting->execute([$key, $val]);
            }

            // Add Audit log entry
            $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $stmtAudit = $pdo->prepare("INSERT INTO audit_log (user_type, user_id, action, ip_address, details) VALUES ('system', NULL, 'installed', ?, 'CRXSM Platform installed successfully')");
            $stmtAudit->execute([$ip]);

        } catch (Exception $e) {
            $errors[] = "Installation failed: " . $e->getMessage();
            $step = 3; // return to admin creation page
        }
    } else {
        $step = 3;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CRXSM Setup Wizard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --success: #10b981;
            --danger: #ef4444;
            --glow: rgba(99, 102, 241, 0.15);
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
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.1) 0px, transparent 50%);
            color: var(--text-color);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem 1rem;
        }

        .container {
            width: 100%;
            max-width: 580px;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            padding: 3rem 2.5rem;
            box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.5);
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), #a78bfa);
        }

        .header {
            text-align: center;
            margin-bottom: 2.5rem;
        }

        .logo {
            font-size: 2.5rem;
            font-weight: 700;
            letter-spacing: -1px;
            background: linear-gradient(135deg, #fff 30%, var(--text-muted));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        .logo span {
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 0.95rem;
        }

        h2 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .progress-bar {
            display: flex;
            justify-content: space-between;
            margin-bottom: 2.5rem;
            position: relative;
        }

        .progress-bar::before {
            content: '';
            position: absolute;
            top: 15px;
            left: 5px;
            right: 5px;
            height: 2px;
            background: rgba(255, 255, 255, 0.05);
            z-index: 1;
        }

        .progress-step {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: #1f2937;
            border: 2px solid rgba(255, 255, 255, 0.05);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-muted);
            position: relative;
            z-index: 2;
            transition: all 0.3s ease;
        }

        .progress-step.active {
            background: var(--primary);
            border-color: var(--primary);
            color: #fff;
            box-shadow: 0 0 15px rgba(99, 102, 241, 0.4);
        }

        .progress-step.completed {
            background: var(--success);
            border-color: var(--success);
            color: #fff;
        }

        /* Form Controls */
        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        input {
            width: 100%;
            padding: 0.9rem 1.2rem;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            color: #fff;
            font-family: inherit;
            font-size: 0.95rem;
            transition: all 0.2s ease;
        }

        input:focus {
            outline: none;
            border-color: var(--primary);
            background: rgba(255, 255, 255, 0.05);
            box-shadow: 0 0 0 4px var(--glow);
        }

        /* Requirements List */
        .req-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .req-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem 1.25rem;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 14px;
        }

        .req-info {
            display: flex;
            flex-direction: column;
            gap: 0.2rem;
        }

        .req-name {
            font-weight: 500;
            font-size: 0.95rem;
        }

        .req-desc {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .badge {
            padding: 0.35rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-success {
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
        }

        .badge-danger {
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
        }

        /* Error/Alert box */
        .alert {
            padding: 1rem 1.25rem;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 12px;
            color: #fca5a5;
            font-size: 0.9rem;
            margin-bottom: 1.5rem;
            line-height: 1.4;
        }

        .alert ul {
            padding-left: 1.2rem;
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 1rem 2rem;
            background: linear-gradient(135deg, var(--primary) 0%, #8b5cf6 100%);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-family: inherit;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
            text-decoration: none;
        }

        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.35);
        }

        .btn:active {
            transform: translateY(1px);
        }

        .btn:disabled {
            background: #1f2937;
            color: var(--text-muted);
            box-shadow: none;
            cursor: not-allowed;
            transform: none;
        }

        .success-illustration {
            text-align: center;
            margin: 2rem 0;
        }

        .success-icon {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: rgba(16, 185, 129, 0.1);
            border: 2px solid var(--success);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: var(--success);
            font-size: 3rem;
            margin-bottom: 1.5rem;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
            70% { box-shadow: 0 0 0 15px rgba(16, 185, 129, 0); }
            100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        .success-text {
            color: var(--text-muted);
            font-size: 0.95rem;
            line-height: 1.6;
            margin-bottom: 2rem;
        }
    </style>
</head>
<body>

<div class="container">
    <div class="card">
        <div class="header">
            <div class="logo">CR<span>XSM</span></div>
            <div class="subtitle">Platform Installation Wizard</div>
        </div>

        <?php if ($step <= 4): ?>
            <div class="progress-bar">
                <div class="progress-step <?php echo $step === 1 ? 'active' : ($step > 1 ? 'completed' : ''); ?>">1</div>
                <div class="progress-step <?php echo $step === 2 ? 'active' : ($step > 2 ? 'completed' : ''); ?>">2</div>
                <div class="progress-step <?php echo $step === 3 ? 'active' : ($step > 3 ? 'completed' : ''); ?>">3</div>
                <div class="progress-step <?php echo $step === 4 ? 'active' : ''; ?>">4</div>
            </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <div class="alert">
                <strong>Correct the following errors:</strong>
                <ul style="margin-top: 0.5rem;">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <!-- STEP 1: Requirements Check -->
        <?php if ($step === 1): ?>
            <h2>Requirements Check</h2>
            <div class="req-list">
                <?php foreach ($requirements as $req): ?>
                    <div class="req-item">
                        <div class="req-info">
                            <span class="req-name"><?php echo htmlspecialchars($req['name']); ?></span>
                            <span class="req-desc"><?php echo htmlspecialchars($req['desc']); ?></span>
                        </div>
                        <span class="badge <?php echo $req['passed'] ? 'badge-success' : 'badge-danger'; ?>">
                            <?php echo $req['passed'] ? 'Passed' : 'Failed'; ?>
                        </span>
                    </div>
                <?php endforeach; ?>
            </div>
            
            <?php if ($allPassed): ?>
                <a href="?step=2" class="btn">Next: Configure Database</a>
            <?php else: ?>
                <button class="btn" disabled>Please resolve issues to proceed</button>
            <?php endif; ?>
        <?php endif; ?>

        <!-- STEP 2: Database Settings -->
        <?php if ($step === 2): ?>
            <h2>Database Configuration</h2>
            <form action="?step=3" method="post">
                <div class="form-group">
                    <label>Database Host</label>
                    <input type="text" name="db_host" value="<?php echo htmlspecialchars($db_host); ?>" required>
                </div>
                <div class="form-group">
                    <label>Database Name</label>
                    <input type="text" name="db_name" value="<?php echo htmlspecialchars($db_name); ?>" required>
                </div>
                <div class="form-group">
                    <label>Database User</label>
                    <input type="text" name="db_user" value="<?php echo htmlspecialchars($db_user); ?>" required>
                </div>
                <div class="form-group">
                    <label>Database Password</label>
                    <input type="password" name="db_pass" value="<?php echo htmlspecialchars($db_pass); ?>">
                </div>
                <div class="form-group">
                    <label>Base Application URL</label>
                    <input type="url" name="base_url" value="<?php echo htmlspecialchars($base_url); ?>" required>
                </div>
                <button type="submit" class="btn">Next: Configure Admin Account</button>
            </form>
        <?php endif; ?>

        <!-- STEP 3: Admin Configuration -->
        <?php if ($step === 3): ?>
            <h2>Create Admin Account</h2>
            <form action="?step=4" method="post">
                <!-- Keep DB credentials in post request -->
                <input type="hidden" name="db_host" value="<?php echo htmlspecialchars($db_host); ?>">
                <input type="hidden" name="db_name" value="<?php echo htmlspecialchars($db_name); ?>">
                <input type="hidden" name="db_user" value="<?php echo htmlspecialchars($db_user); ?>">
                <input type="hidden" name="db_pass" value="<?php echo htmlspecialchars($db_pass); ?>">
                <input type="hidden" name="base_url" value="<?php echo htmlspecialchars($base_url); ?>">

                <div class="form-group">
                    <label>Admin Username</label>
                    <input type="text" name="admin_user" value="<?php echo htmlspecialchars($_POST['admin_user'] ?? ''); ?>" required placeholder="e.g. ratul">
                </div>
                <div class="form-group">
                    <label>Admin Email</label>
                    <input type="email" name="admin_email" value="<?php echo htmlspecialchars($_POST['admin_email'] ?? ''); ?>" required placeholder="e.g. ratul@example.com">
                </div>
                <div class="form-group">
                    <label>Admin Password</label>
                    <input type="password" name="admin_pass" required placeholder="Minimum 8 characters">
                </div>
                <div class="form-group">
                    <label>Confirm Password</label>
                    <input type="password" name="admin_pass_conf" required>
                </div>
                <button type="submit" class="btn">Finalize & Install</button>
            </form>
        <?php endif; ?>

        <!-- STEP 5: Success Screen -->
        <?php if ($step === 4 && empty($errors)): ?>
            <div class="success-illustration">
                <div class="success-icon">&checkmark;</div>
                <h2>Installation Complete!</h2>
                <p class="success-text">
                    CRXSM Platform has been installed successfully.<br>
                    Database schema was initialized and admin credentials were created.<br>
                    <strong>Vault/config.php</strong> was created successfully.
                </p>
                <a href="../Back/index.php" class="btn">Go to Admin Command Center</a>
            </div>
        <?php endif; ?>

    </div>
</div>

</body>
</html>
