<?php
/**
 * CRXSM Customer Dashboard View
 */

if (!defined('Vault\DB')) {
    http_response_code(403);
    die("Direct access not allowed.");
}

use Vault\DB;
use Vault\Auth;
use Vault\Csrf;
use Vault\Audit;

$customer = Auth::getCurrentCustomer();
$customerId = $customer['id'];
$successMsg = '';
$errorMsg = '';

// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Csrf::verifyOrDie();
    
    $action = $_POST['action'] ?? '';
    
    // 1. Deactivate an installation domain/machine
    if ($action === 'deactivate') {
        $activationId = (int)($_POST['activation_id'] ?? 0);
        $licenseId = (int)($_POST['license_id'] ?? 0);
        
        // Confirm this customer owns the license
        $licenseCheck = DB::fetch(
            "SELECT id FROM licenses WHERE id = :lic_id AND user_id = :user_id",
            [':lic_id' => $licenseId, ':user_id' => $customerId]
        );
        
        if ($licenseCheck) {
            // Delete activation
            $stmt = DB::query(
                "DELETE FROM license_activations WHERE id = :id AND license_id = :lic_id",
                [':id' => $activationId, ':lic_id' => $licenseId]
            );
            if ($stmt->rowCount() > 0) {
                Audit::log('customer', $customerId, 'customer_deactivated_domain', "Deactivated slot ID {$activationId} on License ID {$licenseId}");
                $successMsg = "Installation successfully deactivated. Slot freed.";
            } else {
                $errorMsg = "Activation record not found.";
            }
        } else {
            $errorMsg = "Unauthorized action.";
        }
    }
    
    // 2. Change password
    if ($action === 'change_password') {
        $oldPass = $_POST['old_password'] ?? '';
        $newPass = $_POST['new_password'] ?? '';
        $newPassConf = $_POST['new_password_confirm'] ?? '';
        
        $user = DB::fetch("SELECT password FROM users WHERE id = :id", [':id' => $customerId]);
        
        if ($user && password_verify($oldPass, $user['password'])) {
            if (strlen($newPass) < 8) {
                $errorMsg = "New password must be at least 8 characters.";
            } elseif ($newPass !== $newPassConf) {
                $errorMsg = "New passwords do not match.";
            } else {
                $hashed = password_hash($newPass, PASSWORD_BCRYPT);
                DB::execute("UPDATE users SET password = :pass WHERE id = :id", [':pass' => $hashed, ':id' => $customerId]);
                Audit::log('customer', $customerId, 'password_changed', "Password updated by customer");
                $successMsg = "Password updated successfully.";
            }
        } else {
            $errorMsg = "Incorrect current password.";
        }
    }
}

// Fetch Customer's Licenses
$licenses = DB::fetchAll(
    "SELECT l.*, s.name as software_name, s.slug as software_slug, s.public_key 
     FROM licenses l 
     JOIN software s ON l.software_id = s.id 
     WHERE l.user_id = :user_id",
    [':user_id' => $customerId]
);
?>

<div class="dashboard-wrapper">
    <div class="dashboard-header">
        <h1>Welcome, <?php echo htmlspecialchars($customer['name']); ?></h1>
        <p>Manage your active licenses, product files, and account settings.</p>
    </div>

    <?php if (!empty($successMsg)): ?>
        <div class="alert alert-success" style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: var(--success); padding:1rem; border-radius:10px; margin-bottom: 2rem;">
            <?php echo htmlspecialchars($successMsg); ?>
        </div>
    <?php endif; ?>
    <?php if (!empty($errorMsg)): ?>
        <div class="alert alert-danger" style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: var(--danger); padding:1rem; border-radius:10px; margin-bottom: 2rem;">
            <?php echo htmlspecialchars($errorMsg); ?>
        </div>
    <?php endif; ?>

    <div class="dashboard-grid">
        <!-- LEFT: LICENSES & DOWNLOADS -->
        <div class="main-column">
            <h2>Your Licenses</h2>
            
            <?php if (empty($licenses)): ?>
                <div class="empty-state">
                    <p>You do not have any active licenses registered under this account.</p>
                </div>
            <?php else: ?>
                <div class="licenses-list">
                    <?php foreach ($licenses as $lic): 
                        $licId = (int)$lic['id'];
                        // Fetch activations
                        $activations = DB::fetchAll("SELECT * FROM license_activations WHERE license_id = :id", [':id' => $licId]);
                        $actCount = count($activations);
                        // Fetch versions available for download
                        $versions = DB::fetchAll("SELECT * FROM software_versions WHERE software_id = :id ORDER BY created_at DESC", [':id' => $lic['software_id']]);
                    ?>
                        <div class="license-card">
                            <div class="lic-card-header">
                                <h3><?php echo htmlspecialchars($lic['software_name']); ?></h3>
                                <span class="lic-status status-<?php echo $lic['status']; ?>"><?php echo htmlspecialchars($lic['status']); ?></span>
                            </div>
                            
                            <div class="lic-details">
                                <div class="detail-row">
                                    <strong>License Key:</strong>
                                    <div class="key-container">
                                        <code id="key-<?php echo $licId; ?>"><?php echo htmlspecialchars($lic['license_key']); ?></code>
                                        <button onclick="navigator.clipboard.writeText('<?php echo htmlspecialchars($lic['license_key']); ?>'); alert('Key copied to clipboard!');" class="btn-copy">Copy</button>
                                    </div>
                                </div>
                                <div class="detail-row">
                                    <strong>Public Verification Key (for offline plugins):</strong>
                                    <div class="key-container">
                                        <code><?php echo htmlspecialchars($lic['public_key']); ?></code>
                                        <button onclick="navigator.clipboard.writeText('<?php echo htmlspecialchars($lic['public_key']); ?>'); alert('Public key copied!');" class="btn-copy">Copy</button>
                                    </div>
                                </div>
                                <div class="detail-row">
                                    <strong>Limits:</strong>
                                    <span><?php echo $actCount; ?> / <?php echo (int)$lic['activation_limit']; ?> activations used</span>
                                </div>
                                <div class="detail-row">
                                    <strong>Expires:</strong>
                                    <span><?php echo $lic['expires_at'] ? date('M d, Y', strtotime($lic['expires_at'])) : 'Lifetime (No Expiry)'; ?></span>
                                </div>
                            </div>

                            <!-- Activations management -->
                            <div class="activations-section">
                                <h4>Active Installations</h4>
                                <?php if (empty($activations)): ?>
                                    <p class="no-activations">This license is currently not activated on any domain/machine.</p>
                                <?php else: ?>
                                    <table class="activations-table">
                                        <thead>
                                            <tr>
                                                <th>Domain</th>
                                                <th>Machine ID</th>
                                                <th>Last Active</th>
                                                <th>Action</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($activations as $act): ?>
                                                <tr>
                                                    <td><code><?php echo htmlspecialchars($act['domain']); ?></code></td>
                                                    <td><span class="machine-id-badge" title="<?php echo htmlspecialchars($act['machine_id']); ?>"><?php echo htmlspecialchars(substr($act['machine_id'], 0, 10)); ?>...</span></td>
                                                    <td><?php echo date('M d, H:i', strtotime($act['last_active_at'])); ?></td>
                                                    <td>
                                                        <form action="<?php echo $baseUrl; ?>/dashboard" method="post" onsubmit="return confirm('Deactivating this slot will disable licensing on the remote site. Proceed?');" style="display:inline;">
                                                            <?php echo Csrf::getHiddenInput(); ?>
                                                            <input type="hidden" name="action" value="deactivate">
                                                            <input type="hidden" name="license_id" value="<?php echo $licId; ?>">
                                                            <input type="hidden" name="activation_id" value="<?php echo (int)$act['id']; ?>">
                                                            <button type="submit" class="btn-deactivate">Release Slot</button>
                                                        </form>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                <?php endif; ?>
                            </div>

                            <!-- Downloads list -->
                            <div class="downloads-section">
                                <h4>Available Downloads</h4>
                                <?php if (empty($versions)): ?>
                                    <p class="no-activations">No files uploaded for this software yet.</p>
                                <?php else: ?>
                                    <ul class="version-list">
                                        <?php foreach ($versions as $ver): ?>
                                            <li>
                                                <div class="version-info">
                                                    <strong>v<?php echo htmlspecialchars($ver['version']); ?></strong>
                                                    <span class="version-date">Uploaded: <?php echo date('M d, Y', strtotime($ver['created_at'])); ?></span>
                                                </div>
                                                <a href="<?php echo $baseUrl; ?>/download/<?php echo (int)$ver['id']; ?>" class="btn-download">Download .zip</a>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- RIGHT: SIDEBAR PROFILE -->
        <div class="sidebar-column">
            <div class="sidebar-card">
                <h3>Account Information</h3>
                <div class="profile-details">
                    <p><strong>Name:</strong> <?php echo htmlspecialchars($customer['name']); ?></p>
                    <p><strong>Email:</strong> <?php echo htmlspecialchars($customer['email']); ?></p>
                </div>
            </div>

            <div class="sidebar-card">
                <h3>Change Password</h3>
                <form action="<?php echo $baseUrl; ?>/dashboard" method="post">
                    <?php echo Csrf::getHiddenInput(); ?>
                    <input type="hidden" name="action" value="change_password">
                    <div class="form-group">
                        <label>Current Password</label>
                        <input type="password" name="old_password" required>
                    </div>
                    <div class="form-group">
                        <label>New Password</label>
                        <input type="password" name="new_password" required placeholder="Min 8 characters">
                    </div>
                    <div class="form-group">
                        <label>Confirm New Password</label>
                        <input type="password" name="new_password_confirm" required>
                    </div>
                    <button type="submit" class="btn">Update Password</button>
                </form>
            </div>
        </div>
    </div>
</div>

<style>
    .dashboard-wrapper {
        width: 100%;
    }
    
    .dashboard-header {
        margin-bottom: 3rem;
    }

    .dashboard-header h1 {
        font-size: 2.2rem;
        margin-bottom: 0.5rem;
    }

    .dashboard-header p {
        color: var(--text-muted);
    }

    .dashboard-grid {
        display: grid;
        grid-template-columns: 2.5fr 1fr;
        gap: 3rem;
        align-items: start;
    }

    @media (max-width: 992px) {
        .dashboard-grid {
            grid-template-columns: 1fr;
            gap: 2rem;
        }
    }

    .main-column h2 {
        font-size: 1.5rem;
        margin-bottom: 1.5rem;
    }

    .licenses-list {
        display: flex;
        flex-direction: column;
        gap: 2rem;
    }

    .license-card {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 16px;
        padding: 2.5rem;
        backdrop-filter: blur(12px);
    }

    .lic-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1.5rem;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 1rem;
    }

    .lic-card-header h3 {
        font-size: 1.4rem;
        font-weight: 600;
    }

    .lic-status {
        padding: 0.25rem 0.75rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    .status-active, .status-activated {
        background: rgba(16, 185, 129, 0.15);
        color: var(--success);
    }

    .status-generated {
        background: rgba(99, 102, 241, 0.15);
        color: var(--primary);
    }

    .status-expired {
        background: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
    }

    .status-revoked {
        background: rgba(239, 68, 68, 0.15);
        color: var(--danger);
    }

    .lic-details {
        display: flex;
        flex-direction: column;
        gap: 1rem;
        margin-bottom: 2rem;
    }

    .detail-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.95rem;
        gap: 1rem;
    }

    @media (max-width: 768px) {
        .detail-row {
            flex-direction: column;
            align-items: flex-start;
            gap: 0.4rem;
        }
    }

    .detail-row strong {
        color: var(--text-muted);
        min-width: 150px;
    }

    .key-container {
        display: flex;
        align-items: center;
        background: rgba(0, 0, 0, 0.2);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 0.4rem 0.8rem;
        max-width: 100%;
        overflow: hidden;
    }

    .key-container code {
        font-family: monospace;
        font-size: 0.9rem;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        color: #e5e7eb;
        max-width: 250px;
    }

    .btn-copy {
        background: none;
        border: none;
        color: var(--primary);
        font-weight: 600;
        cursor: pointer;
        padding-left: 0.8rem;
        font-size: 0.85rem;
    }

    .btn-copy:hover {
        color: var(--primary-hover);
    }

    /* Activations */
    .activations-section {
        margin-top: 2rem;
        border-top: 1px solid var(--border-color);
        padding-top: 1.5rem;
    }

    .activations-section h4, .downloads-section h4 {
        font-size: 1.1rem;
        margin-bottom: 1rem;
        color: #fff;
    }

    .no-activations {
        color: var(--text-muted);
        font-size: 0.9rem;
        font-style: italic;
    }

    .activations-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.9rem;
    }

    .activations-table th, .activations-table td {
        padding: 0.75rem 1rem;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
    }

    .activations-table th {
        color: var(--text-muted);
        font-weight: 500;
    }

    .activations-table td code {
        color: #a5b4fc;
    }

    .machine-id-badge {
        background: rgba(255, 255, 255, 0.05);
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
    }

    .btn-deactivate {
        background: none;
        border: 1px solid rgba(239, 68, 68, 0.2);
        color: var(--danger);
        padding: 0.3rem 0.6rem;
        border-radius: 6px;
        font-size: 0.8rem;
        cursor: pointer;
        transition: background-color 0.2s;
    }

    .btn-deactivate:hover {
        background: rgba(239, 68, 68, 0.1);
    }

    /* Downloads */
    .downloads-section {
        margin-top: 2rem;
        border-top: 1px solid var(--border-color);
        padding-top: 1.5rem;
    }

    .version-list {
        list-style: none;
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
    }

    .version-list li {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 0.75rem 1.25rem;
    }

    .version-info {
        display: flex;
        flex-direction: column;
    }

    .version-date {
        font-size: 0.8rem;
        color: var(--text-muted);
    }

    .btn-download {
        background: var(--primary);
        color: #fff;
        text-decoration: none;
        padding: 0.4rem 1rem;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 500;
        transition: background-color 0.2s;
    }

    .btn-download:hover {
        background: var(--primary-hover);
    }

    /* Sidebar columns */
    .sidebar-column {
        display: flex;
        flex-direction: column;
        gap: 2rem;
    }

    .sidebar-card {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 16px;
        padding: 2rem;
        backdrop-filter: blur(12px);
    }

    .sidebar-card h3 {
        font-size: 1.15rem;
        margin-bottom: 1.25rem;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 0.75rem;
    }

    .profile-details p {
        margin-bottom: 0.75rem;
        font-size: 0.95rem;
    }

    .profile-details strong {
        color: var(--text-muted);
    }

    .empty-state {
        background: var(--card-bg);
        border: 1px dashed var(--border-color);
        border-radius: 16px;
        padding: 3rem;
        text-align: center;
        color: var(--text-muted);
    }
</style>
