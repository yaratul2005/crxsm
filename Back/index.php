<?php
/**
 * CRXSM Admin Command Center Gateway
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
use Vault\Audit;

// Start session
Auth::startSession();

// Load Config
$configPath = dirname(__DIR__) . '/Vault/config.php';
if (!file_exists($configPath)) {
    die("CRXSM is not installed. Please run <a href='../Setup/index.php'>the installer</a>.");
}
$config = require($configPath);
$baseUrl = rtrim($config['base_url'], '/');
$masterKey = $config['master_key'] ?? '';

// Helper to get setting
function getSettingVal(string $key, string $default = ''): string {
    try {
        $row = DB::fetch("SELECT setting_value FROM settings WHERE setting_key = :key", [':key' => $key]);
        return $row['setting_value'] ?? $default;
    } catch (Exception $e) {
        return $default;
    }
}

// 2. Handle Login if not logged in
if (!Auth::isAdminLoggedIn()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        Csrf::verifyOrDie();
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        $admin = DB::fetch("SELECT * FROM admins WHERE username = :username", [':username' => $username]);
        if ($admin && password_verify($password, $admin['password'])) {
            Auth::loginAdmin((int)$admin['id'], $admin['username'], $admin['role']);
            Audit::log('admin', (int)$admin['id'], 'login', "Admin logged in");
            header("Location: index.php");
            exit;
        } else {
            $error = "Invalid username or password.";
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Login - CRXSM</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-color: #0f172a;
                --card-bg: #1e293b;
                --border-color: #334155;
                --text-color: #f1f5f9;
                --text-muted: #94a3b8;
                --primary: #3b82f6;
                --primary-hover: #2563eb;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: 'Outfit', sans-serif;
                background-color: var(--bg-color);
                color: var(--text-color);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 1rem;
            }
            .login-card {
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 2.5rem;
                max-width: 420px;
                width: 100%;
                box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);
            }
            .logo {
                font-size: 2rem;
                font-weight: 700;
                text-align: center;
                margin-bottom: 2rem;
                letter-spacing: -0.5px;
            }
            .logo span { color: var(--primary); }
            .form-group { margin-bottom: 1.5rem; }
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
                padding: 0.8rem 1rem;
                background: #0f172a;
                border: 1px solid var(--border-color);
                border-radius: 8px;
                color: #fff;
                font-family: inherit;
            }
            input:focus {
                outline: none;
                border-color: var(--primary);
            }
            .btn {
                width: 100%;
                padding: 0.8rem;
                background: var(--primary);
                border: none;
                border-radius: 8px;
                color: #fff;
                font-weight: 600;
                cursor: pointer;
                transition: background-color 0.2s;
            }
            .btn:hover { background-color: var(--primary-hover); }
            .alert {
                background: rgba(239, 68, 68, 0.15);
                border: 1px solid rgba(239, 68, 68, 0.3);
                color: #fca5a5;
                padding: 0.75rem 1rem;
                border-radius: 8px;
                margin-bottom: 1.5rem;
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="logo">CR<span>XSM</span> Back</div>
            <?php if (isset($error)): ?><div class="alert"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
            <form action="index.php" method="post">
                <?php echo Csrf::getHiddenInput(); ?>
                <div class="form-group">
                    <label>Admin Username</label>
                    <input type="text" name="username" required autofocus>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit" class="btn">Sign In</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// 3. Admin is logged in. Router for Views
$admin = Auth::getCurrentAdmin();
$view = $_GET['view'] ?? 'dashboard';

// Process View Content
$viewContent = '';
$viewTitle = 'Dashboard';

switch ($view) {
    case 'dashboard':
        $viewTitle = 'Dashboard Overview';
        ob_start();
        // Dynamic stats calculations
        $totalSoftware = DB::fetch("SELECT COUNT(*) as cnt FROM software")['cnt'] ?? 0;
        $totalLicenses = DB::fetch("SELECT COUNT(*) as cnt FROM licenses")['cnt'] ?? 0;
        $totalActivations = DB::fetch("SELECT COUNT(*) as cnt FROM license_activations")['cnt'] ?? 0;
        $totalCustomers = DB::fetch("SELECT COUNT(*) as cnt FROM users")['cnt'] ?? 0;
        
        $recentLogs = DB::fetchAll("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 6");
        $expiringLicenses = DB::fetchAll(
            "SELECT l.*, s.name as software_name, u.email as user_email 
             FROM licenses l 
             JOIN software s ON l.software_id = s.id 
             JOIN users u ON l.user_id = u.id 
             WHERE l.expires_at IS NOT NULL AND l.expires_at > NOW() 
             ORDER BY l.expires_at ASC LIMIT 5"
        );
        ?>
        <div class="stats-row">
            <div class="stat-card">
                <span class="stat-label">Software Products</span>
                <span class="stat-value"><?php echo $totalSoftware; ?></span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Active Licenses</span>
                <span class="stat-value"><?php echo $totalLicenses; ?></span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Total Activations</span>
                <span class="stat-value"><?php echo $totalActivations; ?></span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Registered Customers</span>
                <span class="stat-value"><?php echo $totalCustomers; ?></span>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="grid-card">
                <h3>Expiring Licenses (Soonest First)</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Software</th>
                            <th>Customer</th>
                            <th>Expiry</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($expiringLicenses as $lic): ?>
                            <tr>
                                <td><strong><?php echo htmlspecialchars($lic['software_name']); ?></strong></td>
                                <td><?php echo htmlspecialchars($lic['user_email']); ?></td>
                                <td><?php echo date('M d, Y', strtotime($lic['expires_at'])); ?></td>
                                <td><span class="badge badge-success"><?php echo $lic['status']; ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($expiringLicenses)): ?>
                            <tr><td colspan="4" class="text-center text-muted">No licenses expiring soon.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div class="grid-card">
                <h3>Recent System Activity</h3>
                <div class="audit-list">
                    <?php foreach ($recentLogs as $log): ?>
                        <div class="audit-item">
                            <span class="audit-time"><?php echo date('H:i M d', strtotime($log['created_at'])); ?></span>
                            <div class="audit-details">
                                <strong><?php echo htmlspecialchars($log['action']); ?></strong>
                                <span><?php echo htmlspecialchars($log['details'] ?? ''); ?></span>
                            </div>
                            <span class="audit-actor"><?php echo $log['user_type']; ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
        <?php
        $viewContent = ob_get_clean();
        break;

    case 'software':
        $viewTitle = 'Software & Versions Registry';
        ob_start();
        require __DIR__ . '/software.php';
        $viewContent = ob_get_clean();
        break;

    case 'licenses':
        $viewTitle = 'License Keys Manager';
        ob_start();
        require __DIR__ . '/licenses.php';
        $viewContent = ob_get_clean();
        break;

    case 'cms':
        $viewTitle = 'CMS Page & Post Builder';
        ob_start();
        require __DIR__ . '/cms.php';
        $viewContent = ob_get_clean();
        break;

    case 'settings':
        $viewTitle = 'Platform Settings & SMTP Configuration';
        ob_start();
        require __DIR__ . '/settings.php';
        $viewContent = ob_get_clean();
        break;

    case 'customers':
        $viewTitle = 'Customer Accounts';
        ob_start();
        // Customers view
        $users = DB::fetchAll("SELECT * FROM users ORDER BY created_at DESC");
        
        // Handle suspension toggle
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_status') {
            Csrf::verifyOrDie();
            $userId = (int)$_POST['user_id'];
            $newStatus = $_POST['status'] === 'active' ? 'suspended' : 'active';
            DB::execute("UPDATE users SET status = ? WHERE id = ?", [$newStatus, $userId]);
            Audit::log('admin', $admin['id'], 'toggle_customer_status', "Set customer ID {$userId} to {$newStatus}");
            header("Location: index.php?view=customers");
            exit;
        }
        ?>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Status</th>
                    <th>Registered</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $u): ?>
                    <tr>
                        <td><strong><?php echo htmlspecialchars($u['name']); ?></strong></td>
                        <td><?php echo htmlspecialchars($u['email']); ?></td>
                        <td><span class="badge <?php echo $u['status'] === 'active' ? 'badge-success' : 'badge-danger'; ?>"><?php echo $u['status']; ?></span></td>
                        <td><?php echo date('M d, Y', strtotime($u['created_at'])); ?></td>
                        <td>
                            <form action="index.php?view=customers" method="post" style="display:inline;">
                                <?php echo Csrf::getHiddenInput(); ?>
                                <input type="hidden" name="action" value="toggle_status">
                                <input type="hidden" name="user_id" value="<?php echo $u['id']; ?>">
                                <input type="hidden" name="status" value="<?php echo $u['status']; ?>">
                                <button type="submit" class="btn-sm <?php echo $u['status'] === 'active' ? 'btn-danger' : 'btn-success'; ?>">
                                    <?php echo $u['status'] === 'active' ? 'Suspend' : 'Activate'; ?>
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
        $viewContent = ob_get_clean();
        break;

    case 'audit_log':
        $viewTitle = 'System Audit Logs';
        ob_start();
        $logs = DB::fetchAll("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100");
        ?>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Actor Type</th>
                    <th>Actor ID</th>
                    <th>Action</th>
                    <th>IP Address</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                    <tr>
                        <td><?php echo date('Y-m-d H:i:s', strtotime($log['created_at'])); ?></td>
                        <td><?php echo htmlspecialchars($log['user_type']); ?></td>
                        <td><?php echo $log['user_id'] ? (int)$log['user_id'] : '—'; ?></td>
                        <td><strong><?php echo htmlspecialchars($log['action']); ?></strong></td>
                        <td><code><?php echo htmlspecialchars($log['ip_address']); ?></code></td>
                        <td><?php echo htmlspecialchars($log['details'] ?? ''); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
        $viewContent = ob_get_clean();
        break;

    case 'logout':
        Auth::logoutAdmin();
        header("Location: index.php");
        exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $viewTitle; ?> - CRXSM Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #f8fafc;
            --sidebar-bg: #0f172a;
            --card-bg: #ffffff;
            --border-color: #e2e8f0;
            --text-color: #334155;
            --text-muted: #64748b;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --success: #10b981;
            --danger: #ef4444;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar Navigation */
        aside.sidebar {
            width: 260px;
            background: var(--sidebar-bg);
            color: #fff;
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
        }

        .sidebar-header {
            padding: 2rem;
            font-size: 1.8rem;
            font-weight: 700;
            border-bottom: 1px solid #1e293b;
            letter-spacing: -0.5px;
        }

        .sidebar-header span { color: var(--primary); }

        .sidebar-menu {
            list-style: none;
            padding: 1.5rem 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            flex: 1;
        }

        .sidebar-menu a {
            display: flex;
            align-items: center;
            padding: 0.8rem 1rem;
            color: #94a3b8;
            text-decoration: none;
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 500;
            transition: all 0.2s;
        }

        .sidebar-menu a:hover, .sidebar-menu li.active a {
            background: #1e293b;
            color: #fff;
        }

        .sidebar-footer {
            padding: 1.5rem;
            border-top: 1px solid #1e293b;
            font-size: 0.85rem;
            color: #64748b;
        }

        /* Main Workspace */
        .workspace {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }

        header.topbar {
            background: #fff;
            border-bottom: 1px solid var(--border-color);
            padding: 1.25rem 3rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .topbar-title {
            font-size: 1.4rem;
            font-weight: 600;
        }

        .topbar-admin {
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        .content-area {
            padding: 3rem;
            max-width: 1400px;
            width: 100%;
            margin: 0 auto;
        }

        /* Dashboard specific utilitarian layout */
        .stats-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }

        .stat-card {
            background: #fff;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }

        .stat-label {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .stat-value {
            font-size: 1.8rem;
            font-weight: 700;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1.5fr 1fr;
            gap: 2rem;
        }

        @media (max-width: 992px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        .grid-card {
            background: #fff;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }

        .grid-card h3 {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.75rem;
        }

        /* Standardized Utilitarian Data Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            margin-bottom: 1.5rem;
        }

        .data-table th, .data-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
        }

        .data-table th {
            background: #f8fafc;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
        }

        .data-table tr:hover { background: #f8fafc; }

        .text-center { text-align: center; }
        .text-muted { color: var(--text-muted); }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .badge-success { background: #d1fae5; color: #065f46; }
        .badge-danger { background: #fee2e2; color: #991b1b; }

        /* Form styling */
        .form-group {
            margin-bottom: 1.25rem;
        }

        label.form-label {
            display: block;
            margin-bottom: 0.4rem;
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-color);
        }

        input.form-control, textarea.form-control, select.form-control {
            width: 100%;
            padding: 0.6rem 0.8rem;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-family: inherit;
            font-size: 0.9rem;
            background: #fff;
        }

        input.form-control:focus, textarea.form-control:focus, select.form-control:focus {
            outline: none;
            border-color: var(--primary);
        }

        .btn-sm {
            padding: 0.35rem 0.7rem;
            font-size: 0.8rem;
            border-radius: 4px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            color: #fff;
        }

        .btn-success { background: var(--success); }
        .btn-danger { background: var(--danger); }
        .btn-primary { background: var(--primary); }

        .btn-success:hover { background: #059669; }
        .btn-danger:hover { background: #dc2626; }
        .btn-primary:hover { background: var(--primary-hover); }

        .audit-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .audit-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem;
            background: #f8fafc;
            border-radius: 8px;
            font-size: 0.85rem;
        }

        .audit-time { color: var(--text-muted); font-size: 0.8rem; }
        .audit-details { flex: 1; padding: 0 1rem; display: flex; flex-direction: column; }
        .audit-actor {
            background: #e2e8f0;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
    </style>
</head>
<body>

<aside class="sidebar">
    <div class="sidebar-header">CR<span>XSM</span> Admin</div>
    <ul class="sidebar-menu">
        <li class="<?php echo $view === 'dashboard' ? 'active' : ''; ?>"><a href="index.php?view=dashboard">Dashboard</a></li>
        <li class="<?php echo $view === 'software' ? 'active' : ''; ?>"><a href="index.php?view=software">Software registry</a></li>
        <li class="<?php echo $view === 'licenses' ? 'active' : ''; ?>"><a href="index.php?view=licenses">Licenses engine</a></li>
        <li class="<?php echo $view === 'cms' ? 'active' : ''; ?>"><a href="index.php?view=cms">CMS Builder</a></li>
        <li class="<?php echo $view === 'customers' ? 'active' : ''; ?>"><a href="index.php?view=customers">Customers list</a></li>
        <li class="<?php echo $view === 'settings' ? 'active' : ''; ?>"><a href="index.php?view=settings">Settings & SMTP</a></li>
        <li class="<?php echo $view === 'audit_log' ? 'active' : ''; ?>"><a href="index.php?view=audit_log">Audit logs</a></li>
        <li style="margin-top: auto;"><a href="index.php?view=logout" style="color: #f87171;">Logout</a></li>
    </ul>
    <div class="sidebar-footer">v1.0.0 &copy; Ratul</div>
</aside>

<div class="workspace">
    <header class="topbar">
        <div class="topbar-title"><?php echo $viewTitle; ?></div>
        <div class="topbar-admin">Logged in as: <strong><?php echo htmlspecialchars($admin['username']); ?></strong></div>
    </header>

    <main class="content-area">
        <?php echo $viewContent; ?>
    </main>
</div>

</body>
</html>
