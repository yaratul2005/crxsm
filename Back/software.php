<?php
/**
 * CRXSM Admin View - Software Registry
 */

if (!defined('CRXSM_ACCESS')) {
    http_response_code(403);
    die("Direct access not allowed.");
}

use Vault\DB;
use Vault\Crypto;
use Vault\Csrf;
use Vault\Storage;
use Vault\Audit;

$action = $_GET['action'] ?? 'list';
$softwareId = (int)($_GET['id'] ?? 0);
$flashSuccess = '';
$flashError = '';
$showSecretOnce = '';

// Handle POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Csrf::verifyOrDie();
    
    $postAction = $_POST['action'] ?? '';
    
    if ($postAction === 'create') {
        $name = trim($_POST['name'] ?? '');
        $slug = trim($_POST['slug'] ?? '');
        $category = trim($_POST['category'] ?? '');
        $description = trim($_POST['description'] ?? '');
        
        if (empty($slug)) {
            $slug = strtolower(preg_replace('/[^a-zA-Z0-9-]+/', '-', $name));
        }

        // Validate slug uniqueness
        $exists = DB::fetch("SELECT id FROM software WHERE slug = :slug", [':slug' => $slug]);
        if ($exists) {
            $flashError = "A software product with this slug already exists.";
        } else {
            try {
                // Generate Ed25519 Keypair
                $keypair = Crypto::generateKeyPair(); // returns [public_key => hex, private_key => hex]

                // Generate Client ID and plain Client Secret
                $clientId = 'sw_' . bin2hex(random_bytes(16));
                $plainSecret = bin2hex(random_bytes(24));

                // Encrypt Secret & Private Key using Platform Master Key
                $encryptedSecret = Crypto::encryptSecret($plainSecret, $masterKey);
                $encryptedPrivateKey = Crypto::encryptSecret($keypair['private_key'], $masterKey);

                DB::execute(
                    "INSERT INTO software (name, slug, category, description, public_key, private_key, client_id, client_secret) 
                     VALUES (:name, :slug, :category, :description, :public_key, :private_key, :client_id, :client_secret)",
                    [
                        ':name'          => $name,
                        ':slug'          => $slug,
                        ':category'      => $category,
                        ':description'   => $description,
                        ':public_key'    => $keypair['public_key'],
                        ':private_key'   => $encryptedPrivateKey,
                        ':client_id'     => $clientId,
                        ':client_secret' => $encryptedSecret
                    ]
                );

                $newId = DB::lastInsertId();
                Audit::log('admin', $admin['id'], 'create_software', "Created software product: {$name} (ID: {$newId})");
                
                // Keep the secret to show exactly once
                $_SESSION['show_secret_once'] = $plainSecret;
                header("Location: index.php?view=software&action=view&id=" . $newId);
                exit;
            } catch (Exception $e) {
                $flashError = "Error creating software: " . $e->getMessage();
            }
        }
    }

    if ($postAction === 'edit') {
        $name = trim($_POST['name'] ?? '');
        $category = trim($_POST['category'] ?? '');
        $description = trim($_POST['description'] ?? '');
        
        DB::execute(
            "UPDATE software SET name = :name, category = :category, description = :description WHERE id = :id",
            [':name' => $name, ':category' => $category, ':description' => $description, ':id' => $softwareId]
        );
        Audit::log('admin', $admin['id'], 'edit_software', "Updated software ID {$softwareId}");
        $flashSuccess = "Software details updated successfully.";
        $action = 'view';
    }

    if ($postAction === 'rotate_secret') {
        $plainSecret = bin2hex(random_bytes(24));
        $encryptedSecret = Crypto::encryptSecret($plainSecret, $masterKey);

        DB::execute(
            "UPDATE software SET client_secret = :secret WHERE id = :id",
            [':secret' => $encryptedSecret, ':id' => $softwareId]
        );
        Audit::log('admin', $admin['id'], 'rotate_client_secret', "Rotated client secret for software ID {$softwareId}");
        
        $_SESSION['show_secret_once'] = $plainSecret;
        header("Location: index.php?view=software&action=view&id=" . $softwareId);
        exit;
    }

    if ($postAction === 'add_version') {
        $version = trim($_POST['version'] ?? '');
        $changelog = trim($_POST['changelog'] ?? '');
        
        if (empty($version)) {
            $flashError = "Please specify a version number (e.g. 1.0.0).";
        } elseif (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            $flashError = "Please select a valid .zip file to upload.";
        } else {
            try {
                $sw = DB::fetch("SELECT slug FROM software WHERE id = :id", [':id' => $softwareId]);
                $filePath = Storage::uploadVersionFile($_FILES['file'], $sw['slug'], $version);

                DB::execute(
                    "INSERT INTO software_versions (software_id, version, changelog, file_path) 
                     VALUES (:software_id, :version, :changelog, :file_path)",
                    [
                        ':software_id' => $softwareId,
                        ':version'     => $version,
                        ':changelog'   => $changelog,
                        ':file_path'   => $filePath
                    ]
                );

                Audit::log('admin', $admin['id'], 'upload_version', "Uploaded version v{$version} for software ID {$softwareId}");
                $flashSuccess = "New version v{$version} uploaded successfully.";
            } catch (Exception $e) {
                $flashError = "Upload failed: " . $e->getMessage();
            }
        }
        $action = 'view';
    }

    if ($postAction === 'delete_version') {
        $versionId = (int)$_POST['version_id'];
        $ver = DB::fetch("SELECT * FROM software_versions WHERE id = :id AND software_id = :sw_id", [':id' => $versionId, ':sw_id' => $softwareId]);
        if ($ver) {
            // Delete actual file
            if (file_exists($ver['file_path'])) {
                @unlink($ver['file_path']);
            }
            DB::execute("DELETE FROM software_versions WHERE id = :id", [':id' => $versionId]);
            Audit::log('admin', $admin['id'], 'delete_version', "Deleted version ID {$versionId} (v{$ver['version']}) for software ID {$softwareId}");
            $flashSuccess = "Version deleted successfully.";
        }
        $action = 'view';
    }
}

// Retrieve any session flash secret
if (isset($_SESSION['show_secret_once'])) {
    $showSecretOnce = $_SESSION['show_secret_once'];
    unset($_SESSION['show_secret_once']);
}
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

<!-- VIEW: LIST ALL SOFTWARE -->
<?php if ($action === 'list'): ?>
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem;">
        <h2>Registered Products</h2>
        <a href="index.php?view=software&action=new" class="btn-sm btn-primary" style="text-decoration:none;">Add Software</a>
    </div>

    <table class="data-table">
        <thead>
            <tr>
                <th>Name</th>
                <th>Slug</th>
                <th>Category</th>
                <th>Client ID</th>
                <th>Versions</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php 
            $list = DB::fetchAll("SELECT s.*, COUNT(v.id) as version_count FROM software s LEFT JOIN software_versions v ON s.id = v.software_id GROUP BY s.id ORDER BY s.name ASC");
            foreach ($list as $sw): 
            ?>
                <tr>
                    <td><strong><a href="index.php?view=software&action=view&id=<?php echo $sw['id']; ?>"><?php echo htmlspecialchars($sw['name']); ?></a></strong></td>
                    <td><code><?php echo htmlspecialchars($sw['slug']); ?></code></td>
                    <td><?php echo htmlspecialchars($sw['category'] ?? '—'); ?></td>
                    <td><code><?php echo htmlspecialchars($sw['client_id']); ?></code></td>
                    <td><span class="badge badge-success"><?php echo $sw['version_count']; ?></span></td>
                    <td>
                        <a href="index.php?view=software&action=view&id=<?php echo $sw['id']; ?>" class="btn-sm btn-primary" style="text-decoration:none;">Manage</a>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($list)): ?>
                <tr><td colspan="6" class="text-center text-muted">No products registered yet. Click "Add Software" to begin.</td></tr>
            <?php endif; ?>
        </tbody>
    </table>

<!-- VIEW: CREATE NEW SOFTWARE -->
<?php elseif ($action === 'new'): ?>
    <h2>Register New Software Product</h2>
    <div class="grid-card" style="margin-top:1.5rem; max-width:600px;">
        <form action="index.php?view=software&action=list" method="post">
            <?php echo Csrf::getHiddenInput(); ?>
            <input type="hidden" name="action" value="create">
            <div class="form-group">
                <label class="form-label">Product Name</label>
                <input type="text" name="name" class="form-control" required placeholder="e.g. My Premium WP Plugin">
            </div>
            <div class="form-group">
                <label class="form-label">Slug (Optional)</label>
                <input type="text" name="slug" class="form-control" placeholder="e.g. my-premium-wp-plugin">
            </div>
            <div class="form-group">
                <label class="form-label">Category</label>
                <input type="text" name="category" class="form-control" placeholder="e.g. WordPress, SaaS, Desktop">
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <textarea name="description" class="form-control" rows="4"></textarea>
            </div>
            <button type="submit" class="btn-sm btn-primary">Generate Keys & Save</button>
            <a href="index.php?view=software" style="margin-left:1rem; font-size:0.9rem; color:var(--text-muted);">Cancel</a>
        </form>
    </div>

<!-- VIEW: MANAGE SOFTWARE DETAILS -->
<?php elseif ($action === 'view' && $softwareId > 0): 
    $sw = DB::fetch("SELECT * FROM software WHERE id = :id", [':id' => $softwareId]);
    if (!$sw) {
        die("Software not found.");
    }
    $versions = DB::fetchAll("SELECT * FROM software_versions WHERE software_id = :id ORDER BY version DESC", [':id' => $softwareId]);
?>
    <div style="margin-bottom:2rem;">
        <a href="index.php?view=software" style="font-size:0.9rem; text-decoration:none;">&larr; Back to Software Registry</a>
        <h2 style="margin-top:1rem;"><?php echo htmlspecialchars($sw['name']); ?> Management</h2>
    </div>

    <?php if (!empty($showSecretOnce)): ?>
        <div style="background:#fff; border: 2px solid var(--primary); padding:1.5rem; border-radius:12px; margin-bottom:2rem; box-shadow:0 0 15px rgba(37,99,235,0.15)">
            <h4 style="color:var(--primary); margin-bottom:0.5rem;">&#9888; Client Secret Generated</h4>
            <p style="font-size:0.9rem; color:var(--text-color); margin-bottom:1rem;">
                Copy this client secret now. It is stored encrypted in the database and **cannot be displayed again** for security reasons.
            </p>
            <div style="display:flex; gap:1rem; align-items:center;">
                <code style="background:#f1f5f9; padding:0.5rem 1rem; border-radius:6px; font-size:1.1rem; border:1px solid #cbd5e1; font-weight:700; flex:1; overflow-x:auto;">
                    <?php echo htmlspecialchars($showSecretOnce); ?>
                </code>
                <button class="btn-sm btn-primary" onclick="navigator.clipboard.writeText('<?php echo htmlspecialchars($showSecretOnce); ?>'); alert('Client secret copied!');">Copy</button>
            </div>
        </div>
    <?php endif; ?>

    <div class="dashboard-grid">
        <!-- LEFT: CREDENTIALS & VERSIONS -->
        <div style="display:flex; flex-direction:column; gap:2rem;">
            <div class="grid-card">
                <h3>API Integration Credentials</h3>
                <div style="display:flex; flex-direction:column; gap:1rem; margin-top:1rem; font-size:0.9rem;">
                    <div>
                        <strong>Client ID:</strong>
                        <code style="display:block; background:#f1f5f9; padding:0.5rem; border-radius:6px; margin-top:0.3rem;">
                            <?php echo htmlspecialchars($sw['client_id']); ?>
                        </code>
                    </div>
                    <div>
                        <strong>Ed25519 Public Verification Key:</strong>
                        <textarea class="form-control" rows="2" readonly style="font-family:monospace; background:#f8fafc; font-size:0.85rem; margin-top:0.3rem; resize:none;"><?php echo htmlspecialchars($sw['public_key']); ?></textarea>
                        <span class="text-muted" style="font-size:0.75rem;">Bundle this public key inside your distributed client software to verify offline license signatures.</span>
                    </div>
                    <div style="margin-top:1rem;">
                        <form action="index.php?view=software&id=<?php echo $softwareId; ?>" method="post" onsubmit="return confirm('Rotating the secret will immediately break connection for any clients using the old secret. Proceed?');">
                            <?php echo Csrf::getHiddenInput(); ?>
                            <input type="hidden" name="action" value="rotate_secret">
                            <button type="submit" class="btn-sm btn-danger">Rotate Client Secret</button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Uploaded Versions List -->
            <div class="grid-card">
                <h3>Uploaded Versions</h3>
                <table class="data-table" style="margin-top:1rem;">
                    <thead>
                        <tr>
                            <th>Version</th>
                            <th>Release Date</th>
                            <th>File Location</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($versions as $ver): ?>
                            <tr>
                                <td><strong>v<?php echo htmlspecialchars($ver['version']); ?></strong></td>
                                <td><?php echo date('M d, Y H:i', strtotime($ver['created_at'])); ?></td>
                                <td><code style="font-size:0.75rem;"><?php echo htmlspecialchars(basename($ver['file_path'])); ?></code></td>
                                <td>
                                    <form action="index.php?view=software&id=<?php echo $softwareId; ?>" method="post" onsubmit="return confirm('Delete this version file? This action is permanent.');" style="display:inline;">
                                        <?php echo Csrf::getHiddenInput(); ?>
                                        <input type="hidden" name="action" value="delete_version">
                                        <input type="hidden" name="version_id" value="<?php echo $ver['id']; ?>">
                                        <button type="submit" class="btn-sm btn-danger">Delete</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($versions)): ?>
                            <tr><td colspan="4" class="text-center text-muted">No versions uploaded yet. Use the upload panel.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- RIGHT: EDIT SOFTWARE & UPLOAD VERSION -->
        <div style="display:flex; flex-direction:column; gap:2rem;">
            <!-- Upload Panel -->
            <div class="grid-card">
                <h3>Upload New Version (.zip)</h3>
                <form action="index.php?view=software&id=<?php echo $softwareId; ?>" method="post" enctype="multipart/form-data" style="margin-top:1rem;">
                    <?php echo Csrf::getHiddenInput(); ?>
                    <input type="hidden" name="action" value="add_version">
                    
                    <div class="form-group">
                        <label class="form-label">Version Number</label>
                        <input type="text" name="version" class="form-control" placeholder="e.g. 1.0.2" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Zip File</label>
                        <input type="file" name="file" class="form-control" accept=".zip" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Release Notes / Changelog</label>
                        <textarea name="changelog" class="form-control" rows="3" placeholder="Fix bugs, performance tweaks..."></textarea>
                    </div>
                    
                    <button type="submit" class="btn-sm btn-primary">Upload & Publish</button>
                </form>
            </div>

            <!-- Edit software info -->
            <div class="grid-card">
                <h3>Edit Product Details</h3>
                <form action="index.php?view=software&id=<?php echo $softwareId; ?>" method="post" style="margin-top:1rem;">
                    <?php echo Csrf::getHiddenInput(); ?>
                    <input type="hidden" name="action" value="edit">
                    
                    <div class="form-group">
                        <label class="form-label">Product Name</label>
                        <input type="text" name="name" class="form-control" value="<?php echo htmlspecialchars($sw['name']); ?>" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Category</label>
                        <input type="text" name="category" class="form-control" value="<?php echo htmlspecialchars($sw['category'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Description</label>
                        <textarea name="description" class="form-control" rows="4"><?php echo htmlspecialchars($sw['description'] ?? ''); ?></textarea>
                    </div>
                    
                    <button type="submit" class="btn-sm btn-primary">Save Changes</button>
                </form>
            </div>
        </div>
    </div>
<?php endif; ?>
