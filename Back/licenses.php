<?php
/**
 * CRXSM Admin View - License Keys Manager
 */

if (!defined('Vault\DB')) {
    http_response_code(403);
    die("Direct access not allowed.");
}

use Vault\DB;
use Vault\Crypto;
use Vault\Csrf;
use Vault\Audit;

$action = $_GET['action'] ?? 'list';
$licenseId = (int)($_GET['id'] ?? 0);
$flashSuccess = '';
$flashError = '';

// Handle POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Csrf::verifyOrDie();
    
    $postAction = $_POST['action'] ?? '';
    
    if ($postAction === 'create') {
        $softwareId = (int)($_POST['software_id'] ?? 0);
        $userEmail  = trim($_POST['user_email'] ?? '');
        $limit      = (int)($_POST['activation_limit'] ?? 1);
        $expiresAt  = !empty($_POST['expires_at']) ? $_POST['expires_at'] : null;

        // Verify Software
        $sw = DB::fetch("SELECT * FROM software WHERE id = :id", [':id' => $softwareId]);
        // Verify User
        $user = DB::fetch("SELECT id FROM users WHERE email = :email", [':email' => $userEmail]);

        if (!$sw) {
            $flashError = "Invalid software selection.";
        } elseif (!$user) {
            $flashError = "Customer email not found. Please create the customer under the 'Customers list' menu first.";
        } else {
            try {
                // Decrypt Software Private Key using Master Key
                $decryptedPrivateKey = Crypto::decryptSecret($sw['private_key'], $masterKey);

                // Insert placeholder record to get new License ID
                DB::execute(
                    "INSERT INTO licenses (software_id, user_id, license_key, activation_limit, status, expires_at) 
                     VALUES (:sw_id, :user_id, '', :limit, 'generated', :expires_at)",
                    [
                        ':sw_id'      => $sw['id'],
                        ':user_id'    => $user['id'],
                        ':limit'      => $limit,
                        ':expires_at' => $expiresAt
                    ]
                );
                $newId = (int)DB::lastInsertId();

                // Construct token payload
                $payload = [
                    'license_id'  => $newId,
                    'software_id' => (int)$sw['id'],
                    'user_id'     => (int)$user['id'],
                    'expires_at'  => $expiresAt
                ];

                // Generate Ed25519-signed token key
                $licenseKey = Crypto::generateLicenseKey($payload, $decryptedPrivateKey);

                // Update registry with generated key
                DB::execute("UPDATE licenses SET license_key = :key WHERE id = :id", [':key' => $licenseKey, ':id' => $newId]);

                Audit::log('admin', $admin['id'], 'create_license', "Issued License ID {$newId} for product {$sw['name']} to {$userEmail}");
                $flashSuccess = "License key issued successfully.";
                header("Location: index.php?view=licenses&action=list");
                exit;
            } catch (Exception $e) {
                $flashError = "Failed to issue license: " . $e->getMessage();
            }
        }
    }

    if ($postAction === 'edit') {
        $limit      = (int)($_POST['activation_limit'] ?? 1);
        $expiresAt  = !empty($_POST['expires_at']) ? $_POST['expires_at'] : null;
        $status     = $_POST['status'] ?? 'generated';

        try {
            $lic = DB::fetch(
                "SELECT l.*, s.private_key, s.id as sw_id FROM licenses l 
                 JOIN software s ON l.software_id = s.id 
                 WHERE l.id = :id", 
                [':id' => $licenseId]
            );

            if ($lic) {
                // Decrypt private key
                $decryptedPrivateKey = Crypto::decryptSecret($lic['private_key'], $masterKey);

                // Regenerate structured signature token since parameters changed
                $payload = [
                    'license_id'  => $licenseId,
                    'software_id' => (int)$lic['sw_id'],
                    'user_id'     => (int)$lic['user_id'],
                    'expires_at'  => $expiresAt
                ];
                $newLicenseKey = Crypto::generateLicenseKey($payload, $decryptedPrivateKey);

                DB::execute(
                    "UPDATE licenses SET 
                        activation_limit = :limit, 
                        expires_at = :expires_at, 
                        status = :status, 
                        license_key = :key 
                     WHERE id = :id",
                    [
                        ':limit'      => $limit,
                        ':expires_at' => $expiresAt,
                        ':status'     => $status,
                        ':key'        => $newLicenseKey,
                        ':id'         => $licenseId
                    ]
                );

                Audit::log('admin', $admin['id'], 'edit_license', "Updated parameters for License ID {$licenseId}");
                $flashSuccess = "License updated successfully.";
                $action = 'list';
            }
        } catch (Exception $e) {
            $flashError = "Failed to update license: " . $e->getMessage();
        }
    }

    if ($postAction === 'revoke') {
        DB::execute("UPDATE licenses SET status = 'revoked' WHERE id = :id", [':id' => $licenseId]);
        // Free activations
        DB::execute("DELETE FROM license_activations WHERE license_id = :id", [':id' => $licenseId]);

        Audit::log('admin', $admin['id'], 'revoke_license', "Revoked License ID {$licenseId} and removed all active slots");
        $flashSuccess = "License successfully revoked.";
        $action = 'list';
    }
}

// Retrieve Software list
$softwares = DB::fetchAll("SELECT id, name FROM software ORDER BY name ASC");
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

<!-- VIEW: LIST LICENSES -->
<?php if ($action === 'list'): 
    $licensesList = DB::fetchAll(
        "SELECT l.*, s.name as software_name, u.email as user_email, COUNT(a.id) as act_count 
         FROM licenses l 
         JOIN software s ON l.software_id = s.id 
         JOIN users u ON l.user_id = u.id 
         LEFT JOIN license_activations a ON l.id = a.license_id 
         GROUP BY l.id 
         ORDER BY l.created_at DESC"
    );
?>
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem;">
        <h2>Issued Licenses</h2>
        <a href="index.php?view=licenses&action=new" class="btn-sm btn-primary" style="text-decoration:none;">Issue License</a>
    </div>

    <table class="data-table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Software</th>
                <th>Customer</th>
                <th>Activations</th>
                <th>Expires</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($licensesList as $lic): ?>
                <tr>
                    <td><?php echo $lic['id']; ?></td>
                    <td><strong><?php echo htmlspecialchars($lic['software_name']); ?></strong></td>
                    <td><?php echo htmlspecialchars($lic['user_email']); ?></td>
                    <td><?php echo $lic['act_count']; ?> / <?php echo $lic['activation_limit']; ?></td>
                    <td><?php echo $lic['expires_at'] ? date('M d, Y', strtotime($lic['expires_at'])) : 'Lifetime'; ?></td>
                    <td><span class="badge status-<?php echo $lic['status']; ?>"><?php echo $lic['status']; ?></span></td>
                    <td>
                        <a href="index.php?view=licenses&action=edit&id=<?php echo $lic['id']; ?>" class="btn-sm btn-primary" style="text-decoration:none; padding: 0.2rem 0.5rem; font-size:0.75rem;">Edit</a>
                        <form action="index.php?view=licenses&id=<?php echo $lic['id']; ?>" method="post" style="display:inline;" onsubmit="return confirm('Revoking will block access for this key immediately. Proceed?');">
                            <?php echo Csrf::getHiddenInput(); ?>
                            <input type="hidden" name="action" value="revoke">
                            <button type="submit" class="btn-sm btn-danger" style="padding: 0.2rem 0.5rem; font-size:0.75rem;">Revoke</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($licensesList)): ?>
                <tr><td colspan="7" class="text-center text-muted">No licenses issued yet. Click "Issue License" to begin.</td></tr>
            <?php endif; ?>
        </tbody>
    </table>

    <style>
        .badge.status-active, .badge.status-activated { background:#d1fae5; color:#065f46; }
        .badge.status-generated { background:#e0e7ff; color:#3730a3; }
        .badge.status-expired { background:#fef3c7; color:#92400e; }
        .badge.status-revoked { background:#fee2e2; color:#991b1b; }
    </style>

<!-- VIEW: ISSUE NEW LICENSE -->
<?php elseif ($action === 'new'): ?>
    <h2>Issue Software License</h2>
    <div class="grid-card" style="margin-top:1.5rem; max-width:600px;">
        <form action="index.php?view=licenses&action=list" method="post">
            <?php echo Csrf::getHiddenInput(); ?>
            <input type="hidden" name="action" value="create">
            
            <div class="form-group">
                <label class="form-label">Software Product</label>
                <select name="software_id" class="form-control" required>
                    <option value="">-- Select Product --</option>
                    <?php foreach ($softwares as $s): ?>
                        <option value="<?php echo $s['id']; ?>"><?php echo htmlspecialchars($s['name']); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            
            <div class="form-group">
                <label class="form-label">Customer Email Address</label>
                <input type="email" name="user_email" class="form-control" required placeholder="customer@example.com">
                <span class="text-muted" style="font-size:0.75rem;">The customer must already be registered under the customer portal or created in the database first.</span>
            </div>
            
            <div class="form-group">
                <label class="form-label">Activation Limit</label>
                <input type="number" name="activation_limit" class="form-control" value="1" min="1" required>
            </div>
            
            <div class="form-group">
                <label class="form-label">Expiration Date (Optional)</label>
                <input type="date" name="expires_at" class="form-control">
                <span class="text-muted" style="font-size:0.75rem;">Leave empty for a lifetime, non-expiring license.</span>
            </div>
            
            <button type="submit" class="btn-sm btn-primary">Generate & Issue Key</button>
            <a href="index.php?view=licenses" style="margin-left:1rem; font-size:0.9rem; color:var(--text-muted);">Cancel</a>
        </form>
    </div>

<!-- VIEW: EDIT LICENSE -->
<?php elseif ($action === 'edit' && $licenseId > 0): 
    $lic = DB::fetch(
        "SELECT l.*, s.name as software_name, u.email as user_email 
         FROM licenses l 
         JOIN software s ON l.software_id = s.id 
         JOIN users u ON l.user_id = u.id 
         WHERE l.id = :id", 
        [':id' => $licenseId]
    );
    if (!$lic) {
        die("License not found.");
    }
?>
    <h2>Edit License #<?php echo $licenseId; ?></h2>
    <div class="grid-card" style="margin-top:1.5rem; max-width:600px;">
        <div style="margin-bottom:1.5rem; font-size:0.95rem;">
            <p><strong>Product:</strong> <?php echo htmlspecialchars($lic['software_name']); ?></p>
            <p><strong>Customer:</strong> <?php echo htmlspecialchars($lic['user_email']); ?></p>
            <p style="margin-top:0.5rem;"><strong>Raw Token Key:</strong></p>
            <textarea class="form-control" rows="2" readonly style="font-family:monospace; font-size:0.8rem; background:#f8fafc; resize:none;"><?php echo htmlspecialchars($lic['license_key']); ?></textarea>
        </div>
        
        <form action="index.php?view=licenses&id=<?php echo $licenseId; ?>" method="post">
            <?php echo Csrf::getHiddenInput(); ?>
            <input type="hidden" name="action" value="edit">
            
            <div class="form-group">
                <label class="form-label">Activation Limit</label>
                <input type="number" name="activation_limit" class="form-control" value="<?php echo (int)$lic['activation_limit']; ?>" min="1" required>
            </div>
            
            <div class="form-group">
                <label class="form-label">Expiration Date (Optional)</label>
                <input type="date" name="expires_at" class="form-control" value="<?php echo $lic['expires_at'] ? date('Y-m-d', strtotime($lic['expires_at'])) : ''; ?>">
            </div>
            
            <div class="form-group">
                <label class="form-label">Status</label>
                <select name="status" class="form-control" required>
                    <option value="generated" <?php echo $lic['status'] === 'generated' ? 'selected' : ''; ?>>Generated</option>
                    <option value="active" <?php echo $lic['status'] === 'active' ? 'selected' : ''; ?>>Active</option>
                    <option value="expired" <?php echo $lic['status'] === 'expired' ? 'selected' : ''; ?>>Expired</option>
                    <option value="revoked" <?php echo $lic['status'] === 'revoked' ? 'selected' : ''; ?>>Revoked</option>
                </select>
                <span class="text-muted" style="font-size:0.75rem;">Note: Changing limits or expiry will automatically regenerate the token signature.</span>
            </div>
            
            <button type="submit" class="btn-sm btn-primary">Save Changes & Resign Token</button>
            <a href="index.php?view=licenses" style="margin-left:1rem; font-size:0.9rem; color:var(--text-muted);">Cancel</a>
        </form>
    </div>
<?php endif; ?>
