<?php
/**
 * CRXSM Admin View - CMS Builder
 */

if (!defined('CRXSM_ACCESS')) {
    http_response_code(403);
    die("Direct access not allowed.");
}

use Vault\DB;
use Vault\Csrf;
use Vault\Audit;

$type = $_GET['type'] ?? 'page'; // 'page' or 'post'
$action = $_GET['action'] ?? 'list';
$id = (int)($_GET['id'] ?? 0);
$flashSuccess = '';
$flashError = '';

// Handle posts/pages processing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Csrf::verifyOrDie();
    
    $postAction = $_POST['action'] ?? '';
    
    if ($postAction === 'save_page') {
        $title = trim($_POST['title'] ?? '');
        $slug = trim($_POST['slug'] ?? '');
        $editorMode = $_POST['editor_mode'] ?? 'canvas';
        $content = $_POST['content'] ?? ''; // Can be raw Markdown or serialized JSON blocks
        $seoTitle = trim($_POST['seo_title'] ?? '');
        $seoDesc = trim($_POST['seo_description'] ?? '');
        $headScripts = $_POST['head_scripts'] ?? '';
        $status = $_POST['status'] ?? 'draft';

        if (empty($slug)) {
            $slug = strtolower(preg_replace('/[^a-zA-Z0-9-]+/', '-', $title));
        }

        // Validate slug unique (except self)
        $exists = DB::fetch("SELECT id FROM pages WHERE slug = :slug AND id != :id", [':slug' => $slug, ':id' => $id]);
        if ($exists) {
            $flashError = "A page with this slug already exists.";
            $action = $id > 0 ? 'edit' : 'new';
        } else {
            if ($id > 0) {
                // Update page
                DB::execute(
                    "UPDATE pages SET title = :title, slug = :slug, content = :content, editor_mode = :mode, 
                     seo_title = :seo_title, seo_description = :seo_desc, head_scripts = :head_scripts, status = :status 
                     WHERE id = :id",
                    [
                        ':title'        => $title,
                        ':slug'         => $slug,
                        ':content'      => $content,
                        ':mode'         => $editorMode,
                        ':seo_title'    => $seoTitle,
                        ':seo_desc'     => $seoDesc,
                        ':head_scripts' => $headScripts,
                        ':status'       => $status,
                        ':id'           => $id
                    ]
                );
                Audit::log('admin', $admin['id'], 'edit_page', "Updated CMS page: {$title} (ID: {$id})");
                $flashSuccess = "Page updated successfully.";
            } else {
                // Insert page
                DB::execute(
                    "INSERT INTO pages (title, slug, content, editor_mode, seo_title, seo_description, head_scripts, status) 
                     VALUES (:title, :slug, :content, :mode, :seo_title, :seo_desc, :head_scripts, :status)",
                    [
                        ':title'        => $title,
                        ':slug'         => $slug,
                        ':content'      => $content,
                        ':mode'         => $editorMode,
                        ':seo_title'    => $seoTitle,
                        ':seo_desc'     => $seoDesc,
                        ':head_scripts' => $headScripts,
                        ':status'       => $status
                    ]
                );
                $newId = DB::lastInsertId();
                Audit::log('admin', $admin['id'], 'create_page', "Created CMS page: {$title} (ID: {$newId})");
                $flashSuccess = "Page created successfully.";
            }
            $action = 'list';
        }
    }

    if ($postAction === 'save_post') {
        $title = trim($_POST['title'] ?? '');
        $slug = trim($_POST['slug'] ?? '');
        $content = $_POST['content'] ?? '';
        $category = trim($_POST['category'] ?? 'General');
        $tags = trim($_POST['tags'] ?? '');
        $seoTitle = trim($_POST['seo_title'] ?? '');
        $seoDesc = trim($_POST['seo_description'] ?? '');
        $status = $_POST['status'] ?? 'draft';

        if (empty($slug)) {
            $slug = strtolower(preg_replace('/[^a-zA-Z0-9-]+/', '-', $title));
        }

        // Validate slug uniqueness
        $exists = DB::fetch("SELECT id FROM posts WHERE slug = :slug AND id != :id", [':slug' => $slug, ':id' => $id]);
        if ($exists) {
            $flashError = "A blog post with this slug already exists.";
            $action = $id > 0 ? 'edit' : 'new';
        } else {
            if ($id > 0) {
                DB::execute(
                    "UPDATE posts SET title = :title, slug = :slug, content = :content, category = :cat, tags = :tags, 
                     seo_title = :seo_title, seo_description = :seo_desc, status = :status WHERE id = :id",
                    [
                        ':title'     => $title,
                        ':slug'      => $slug,
                        ':content'   => $content,
                        ':cat'       => $category,
                        ':tags'      => $tags,
                        ':seo_title' => $seoTitle,
                        ':seo_desc'  => $seoDesc,
                        ':status'    => $status,
                        ':id'        => $id
                    ]
                );
                Audit::log('admin', $admin['id'], 'edit_post', "Updated CMS post: {$title} (ID: {$id})");
                $flashSuccess = "Post updated successfully.";
            } else {
                DB::execute(
                    "INSERT INTO posts (title, slug, content, category, tags, seo_title, seo_description, status) 
                     VALUES (:title, :slug, :content, :cat, :tags, :seo_title, :seo_desc, :status)",
                    [
                        ':title'     => $title,
                        ':slug'      => $slug,
                        ':content'   => $content,
                        ':cat'       => $category,
                        ':tags'      => $tags,
                        ':seo_title' => $seoTitle,
                        ':seo_desc'  => $seoDesc,
                        ':status'    => $status
                    ]
                );
                $newId = DB::lastInsertId();
                Audit::log('admin', $admin['id'], 'create_post', "Created CMS post: {$title} (ID: {$newId})");
                $flashSuccess = "Post created successfully.";
            }
            $action = 'list';
        }
    }

    if ($postAction === 'delete') {
        if ($type === 'page') {
            DB::execute("DELETE FROM pages WHERE id = :id", [':id' => $id]);
            Audit::log('admin', $admin['id'], 'delete_page', "Deleted page ID {$id}");
        } else {
            DB::execute("DELETE FROM posts WHERE id = :id", [':id' => $id]);
            Audit::log('admin', $admin['id'], 'delete_post', "Deleted post ID {$id}");
        }
        $flashSuccess = "Deleted successfully.";
        $action = 'list';
    }
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

<!-- VIEW: LISTING PAGES / POSTS -->
<?php if ($action === 'list'): ?>
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem;">
        <div>
            <a href="index.php?view=cms&type=page" class="btn-sm <?php echo $type === 'page' ? 'btn-primary' : 'btn-secondary'; ?>" style="text-decoration:none; padding: 0.5rem 1rem;">Pages</a>
            <a href="index.php?view=cms&type=post" class="btn-sm <?php echo $type === 'post' ? 'btn-primary' : 'btn-secondary'; ?>" style="text-decoration:none; padding: 0.5rem 1rem; margin-left:0.5rem;">Blog Posts</a>
        </div>
        <a href="index.php?view=cms&type=<?php echo $type; ?>&action=new" class="btn-sm btn-primary" style="text-decoration:none;">
            New <?php echo ucfirst($type); ?>
        </a>
    </div>

    <table class="data-table">
        <thead>
            <tr>
                <th>Title</th>
                <th>Slug</th>
                <th>Status</th>
                <th>Last Updated</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php 
            if ($type === 'page') {
                $list = DB::fetchAll("SELECT id, title, slug, status, updated_at FROM pages ORDER BY updated_at DESC");
            } else {
                $list = DB::fetchAll("SELECT id, title, slug, status, updated_at FROM posts ORDER BY updated_at DESC");
            }
            foreach ($list as $item): 
            ?>
                <tr>
                    <td><strong><a href="index.php?view=cms&type=<?php echo $type; ?>&action=edit&id=<?php echo $item['id']; ?>"><?php echo htmlspecialchars($item['title']); ?></a></strong></td>
                    <td><code><?php echo htmlspecialchars($item['slug']); ?></code></td>
                    <td><span class="badge <?php echo $item['status'] === 'published' ? 'badge-success' : 'badge-danger'; ?>"><?php echo $item['status']; ?></span></td>
                    <td><?php echo date('M d, Y H:i', strtotime($item['updated_at'])); ?></td>
                    <td>
                        <a href="index.php?view=cms&type=<?php echo $type; ?>&action=edit&id=<?php echo $item['id']; ?>" class="btn-sm btn-primary" style="text-decoration:none; padding: 0.2rem 0.5rem; font-size:0.75rem;">Edit</a>
                        <form action="index.php?view=cms&type=<?php echo $type; ?>&id=<?php echo $item['id']; ?>" method="post" style="display:inline;" onsubmit="return confirm('Are you sure you want to delete this?');">
                            <?php echo Csrf::getHiddenInput(); ?>
                            <input type="hidden" name="action" value="delete">
                            <button type="submit" class="btn-sm btn-danger" style="padding: 0.2rem 0.5rem; font-size:0.75rem;">Delete</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($list)): ?>
                <tr><td colspan="5" class="text-center text-muted">No content published yet. Click "New" to begin.</td></tr>
            <?php endif; ?>
        </tbody>
    </table>

<!-- VIEW: ADD / EDIT CONTENT -->
<?php elseif ($action === 'new' || $action === 'edit'): 
    $titleVal = '';
    $slugVal = '';
    $contentVal = '';
    $modeVal = ($type === 'page') ? 'canvas' : 'markdown';
    $catVal = 'General';
    $tagsVal = '';
    $seoTitleVal = '';
    $seoDescVal = '';
    $headScriptsVal = '';
    $statusVal = 'draft';

    if ($action === 'edit' && $id > 0) {
        if ($type === 'page') {
            $item = DB::fetch("SELECT * FROM pages WHERE id = :id", [':id' => $id]);
            if ($item) {
                $titleVal = $item['title'];
                $slugVal = $item['slug'];
                $contentVal = $item['content'];
                $modeVal = $item['editor_mode'];
                $seoTitleVal = $item['seo_title'];
                $seoDescVal = $item['seo_description'];
                $headScriptsVal = $item['head_scripts'];
                $statusVal = $item['status'];
            }
        } else {
            $item = DB::fetch("SELECT * FROM posts WHERE id = :id", [':id' => $id]);
            if ($item) {
                $titleVal = $item['title'];
                $slugVal = $item['slug'];
                $contentVal = $item['content'];
                $catVal = $item['category'];
                $tagsVal = $item['tags'];
                $seoTitleVal = $item['seo_title'];
                $seoDescVal = $item['seo_description'];
                $statusVal = $item['status'];
                $modeVal = 'markdown'; // posts only support markdown
            }
        }
    }
?>
    <div style="margin-bottom:2rem;">
        <a href="index.php?view=cms&type=<?php echo $type; ?>" style="font-size:0.9rem; text-decoration:none;">&larr; Back to Listings</a>
        <h2 style="margin-top:1rem;"><?php echo ($action === 'new') ? 'Create' : 'Edit'; ?> <?php echo ucfirst($type); ?></h2>
    </div>

    <form action="index.php?view=cms&type=<?php echo $type; ?>&id=<?php echo $id; ?>" method="post" id="cms-editor-form">
        <?php echo Csrf::getHiddenInput(); ?>
        <input type="hidden" name="action" value="save_<?php echo $type; ?>">
        
        <div style="display:grid; grid-template-columns: 2.5fr 1fr; gap:2rem; align-items:start;">
            <!-- LEFT COLUMN: MAIN EDITOR -->
            <div class="grid-card">
                <div class="form-group">
                    <label class="form-label">Title</label>
                    <input type="text" name="title" class="form-control" style="font-size:1.15rem; font-weight:600;" value="<?php echo htmlspecialchars($titleVal); ?>" required placeholder="e.g. Services Page or Product Release Notes">
                </div>
                
                <div class="form-group">
                    <label class="form-label">URL Slug (leave empty to auto-generate)</label>
                    <input type="text" name="slug" class="form-control" value="<?php echo htmlspecialchars($slugVal); ?>" placeholder="e.g. services">
                </div>

                <?php if ($type === 'page'): ?>
                    <div class="form-group">
                        <label class="form-label">Editor Mode</label>
                        <select name="editor_mode" id="editor-mode-select" class="form-control" onchange="toggleEditorMode(this.value)">
                            <option value="canvas" <?php echo $modeVal === 'canvas' ? 'selected' : ''; ?>>Canvas Block Builder</option>
                            <option value="markdown" <?php echo $modeVal === 'markdown' ? 'selected' : ''; ?>>Markdown Text Mode</option>
                        </select>
                    </div>
                <?php endif; ?>

                <!-- EDITOR WRAPPERS -->
                <!-- 1. Markdown Editor -->
                <div id="markdown-editor-wrapper" style="display: <?php echo ($modeVal === 'markdown') ? 'block' : 'none'; ?>;">
                    <div class="form-group">
                        <label class="form-label">Content (Markdown / Text)</label>
                        <textarea name="markdown_content" id="markdown-textarea" class="form-control" rows="20" placeholder="Type page content using plain text or Markdown..."><?php echo ($modeVal === 'markdown') ? htmlspecialchars($contentVal) : ''; ?></textarea>
                    </div>
                </div>

                <!-- 2. Canvas Visual Block Editor -->
                <?php if ($type === 'page'): ?>
                    <div id="canvas-editor-wrapper" style="display: <?php echo ($modeVal === 'canvas') ? 'block' : 'none'; ?>;">
                        <label class="form-label" style="margin-bottom:1rem;">Visual Layout Blocks</label>
                        
                        <!-- List of blocks -->
                        <div id="canvas-blocks-container" style="display:flex; flex-direction:column; gap:1.5rem; margin-bottom:2rem;">
                            <!-- Blocks populated dynamically by JavaScript -->
                        </div>

                        <!-- Add Block Panel -->
                        <div style="background:#f8fafc; border:1px dashed var(--border-color); border-radius:8px; padding:1.5rem; text-align:center;">
                            <span style="font-size:0.9rem; color:var(--text-muted); display:block; margin-bottom:0.75rem;">Add blocks to build the landing page structure:</span>
                            <div style="display:flex; justify-content:center; gap:0.5rem; flex-wrap:wrap;">
                                <button type="button" class="btn-sm btn-primary" onclick="addCanvasBlock('hero')">+ Hero Section</button>
                                <button type="button" class="btn-sm btn-primary" onclick="addCanvasBlock('features')">+ Feature Cards</button>
                                <button type="button" class="btn-sm btn-primary" onclick="addCanvasBlock('cta')">+ Call to Action</button>
                                <button type="button" class="btn-sm btn-primary" onclick="addCanvasBlock('text')">+ Plain Text Block</button>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

                <input type="hidden" name="content" id="final-content-input">
            </div>

            <!-- RIGHT COLUMN: SIDEBAR METADATA -->
            <div style="display:flex; flex-direction:column; gap:2rem;">
                <div class="grid-card">
                    <h3>Publish Configuration</h3>
                    <div class="form-group" style="margin-top:1rem;">
                        <label class="form-label">Status</label>
                        <select name="status" class="form-control">
                            <option value="draft" <?php echo $statusVal === 'draft' ? 'selected' : ''; ?>>Draft</option>
                            <option value="published" <?php echo $statusVal === 'published' ? 'selected' : ''; ?>>Published</option>
                        </select>
                    </div>

                    <?php if ($type === 'post'): ?>
                        <div class="form-group">
                            <label class="form-label">Category</label>
                            <input type="text" name="category" class="form-control" value="<?php echo htmlspecialchars($catVal); ?>">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Tags (comma separated)</label>
                            <input type="text" name="tags" class="form-control" value="<?php echo htmlspecialchars($tagsVal); ?>" placeholder="wordpress, licensing">
                        </div>
                    <?php endif; ?>

                    <button type="submit" class="btn-sm btn-primary" style="width:100%; padding: 0.8rem;">Save Content</button>
                </div>

                <div class="grid-card">
                    <h3>SEO Optimization</h3>
                    <div class="form-group" style="margin-top:1rem;">
                        <label class="form-label">SEO Title Tag</label>
                        <input type="text" name="seo_title" class="form-control" value="<?php echo htmlspecialchars($seoTitleVal); ?>" placeholder="Search Engine Title">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Meta Description</label>
                        <textarea name="seo_description" class="form-control" rows="4" placeholder="Brief page summary..."><?php echo htmlspecialchars($seoDescVal); ?></textarea>
                    </div>
                </div>

                <?php if ($type === 'page'): ?>
                    <div class="grid-card">
                        <h3>Advanced Injections</h3>
                        <div class="form-group" style="margin-top:1rem;">
                            <label class="form-label">Page-level scripts (GTM, Pixel, etc.)</label>
                            <textarea name="head_scripts" class="form-control" rows="5" style="font-family:monospace; font-size:0.8rem;" placeholder="<script>...</script>"><?php echo htmlspecialchars($headScriptsVal); ?></textarea>
                            <span class="text-muted" style="font-size:0.75rem;">Injected directly into this page's head tag.</span>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </form>

    <!-- Canvas Builder JS Logic -->
    <script>
        let canvasBlocks = [];

        // Load existing canvas content
        <?php if ($type === 'page' && $modeVal === 'canvas' && !empty($contentVal)): ?>
            try {
                canvasBlocks = <?php echo $contentVal; ?>;
            } catch (e) {
                canvasBlocks = [];
            }
        <?php endif; ?>

        function toggleEditorMode(mode) {
            document.getElementById('markdown-editor-wrapper').style.display = (mode === 'markdown') ? 'block' : 'none';
            const canvasWrapper = document.getElementById('canvas-editor-wrapper');
            if (canvasWrapper) {
                canvasWrapper.style.display = (mode === 'canvas') ? 'block' : 'none';
            }
        }

        function addCanvasBlock(type) {
            let block = { type: type, title: '', text: '' };
            if (type === 'hero' || type === 'cta') {
                block.cta_url = '';
                block.cta_text = 'Learn More';
            } else if (type === 'features') {
                block.items = [{ name: 'Feature 1', desc: 'Description of feature.' }];
            }
            canvasBlocks.push(block);
            renderCanvasBlocks();
        }

        function removeCanvasBlock(index) {
            canvasBlocks.splice(index, 1);
            renderCanvasBlocks();
        }

        function moveBlock(index, direction) {
            if (direction === 'up' && index > 0) {
                let temp = canvasBlocks[index];
                canvasBlocks[index] = canvasBlocks[index - 1];
                canvasBlocks[index - 1] = temp;
            } else if (direction === 'down' && index < canvasBlocks.length - 1) {
                let temp = canvasBlocks[index];
                canvasBlocks[index] = canvasBlocks[index + 1];
                canvasBlocks[index + 1] = temp;
            }
            renderCanvasBlocks();
        }

        function updateBlockField(index, field, value) {
            canvasBlocks[index][field] = value;
        }

        function addFeatureItem(blockIndex) {
            if (!canvasBlocks[blockIndex].items) {
                canvasBlocks[blockIndex].items = [];
            }
            canvasBlocks[blockIndex].items.push({ name: 'New Feature', desc: 'Description.' });
            renderCanvasBlocks();
        }

        function updateFeatureItem(blockIndex, itemIndex, field, value) {
            canvasBlocks[blockIndex].items[itemIndex][field] = value;
        }

        function removeFeatureItem(blockIndex, itemIndex) {
            canvasBlocks[blockIndex].items.splice(itemIndex, 1);
            renderCanvasBlocks();
        }

        function renderCanvasBlocks() {
            const container = document.getElementById('canvas-blocks-container');
            if (!container) return;
            container.innerHTML = '';

            if (canvasBlocks.length === 0) {
                container.innerHTML = '<div class="text-muted text-center" style="padding:2rem;">No blocks added yet. Use the add panel below to construct layout.</div>';
                return;
            }

            canvasBlocks.forEach((block, idx) => {
                const blockDiv = document.createElement('div');
                blockDiv.style.background = '#f8fafc';
                blockDiv.style.border = '1px solid var(--border-color)';
                blockDiv.style.borderRadius = '8px';
                blockDiv.style.padding = '1.5rem';
                blockDiv.style.position = 'relative';

                // Header
                let html = `<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem; border-bottom:1px solid var(--border-color); padding-bottom:0.5rem;">
                                <strong style="text-transform:uppercase; font-size:0.8rem; color:var(--primary);">${block.type} Block</strong>
                                <div style="display:flex; gap:0.25rem;">
                                    <button type="button" class="btn-sm" style="background:#cbd5e1; color:#0f172a; padding: 0.15rem 0.4rem; font-size:0.75rem;" onclick="moveBlock(${idx}, 'up')">&#9650;</button>
                                    <button type="button" class="btn-sm" style="background:#cbd5e1; color:#0f172a; padding: 0.15rem 0.4rem; font-size:0.75rem;" onclick="moveBlock(${idx}, 'down')">&#9660;</button>
                                    <button type="button" class="btn-sm btn-danger" style="padding: 0.15rem 0.4rem; font-size:0.75rem;" onclick="removeCanvasBlock(${idx})">Remove</button>
                                </div>
                            </div>`;

                // Title field
                html += `<div class="form-group">
                            <label class="form-label" style="font-size:0.75rem;">Block Title</label>
                            <input type="text" class="form-control" value="${block.title || ''}" oninput="updateBlockField(${idx}, 'title', this.value)">
                         </div>`;

                // Text field
                html += `<div class="form-group">
                            <label class="form-label" style="font-size:0.75rem;">Block Body Text</label>
                            <textarea class="form-control" rows="3" oninput="updateBlockField(${idx}, 'text', this.value)">${block.text || ''}</textarea>
                         </div>`;

                // CTA fields
                if (block.type === 'hero' || block.type === 'cta') {
                    html += `<div style="display:grid; grid-template-columns: 1fr 1fr; gap:1rem;">
                                <div class="form-group">
                                    <label class="form-label" style="font-size:0.75rem;">CTA Button Label</label>
                                    <input type="text" class="form-control" value="${block.cta_text || 'Learn More'}" oninput="updateBlockField(${idx}, 'cta_text', this.value)">
                                </div>
                                <div class="form-group">
                                    <label class="form-label" style="font-size:0.75rem;">CTA Link Destination</label>
                                    <input type="text" class="form-control" value="${block.cta_url || ''}" oninput="updateBlockField(${idx}, 'cta_url', this.value)" placeholder="/login or https://google.com">
                                </div>
                             </div>`;
                }

                // Features fields
                if (block.type === 'features') {
                    html += `<div style="margin-top:1.5rem; background:#fff; padding:1rem; border-radius:6px; border:1px solid var(--border-color);">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
                                    <strong style="font-size:0.8rem;">Feature Items</strong>
                                    <button type="button" class="btn-sm btn-success" style="padding:0.2rem 0.5rem; font-size:0.75rem;" onclick="addFeatureItem(${idx})">+ Add Item</button>
                                </div>`;
                    
                    const items = block.items || [];
                    items.forEach((item, itemIdx) => {
                        html += `<div style="border-top:1px solid var(--border-color); padding-top:1rem; margin-top:1rem; display:grid; grid-template-columns: 1fr 2fr auto; gap:1rem; align-items:end;">
                                    <div class="form-group" style="margin-bottom:0;">
                                        <label class="form-label" style="font-size:0.75rem;">Feature Title</label>
                                        <input type="text" class="form-control" value="${item.name || ''}" oninput="updateFeatureItem(${idx}, ${itemIdx}, 'name', this.value)">
                                    </div>
                                    <div class="form-group" style="margin-bottom:0;">
                                        <label class="form-label" style="font-size:0.75rem;">Feature Description</label>
                                        <input type="text" class="form-control" value="${item.desc || ''}" oninput="updateFeatureItem(${idx}, ${itemIdx}, 'desc', this.value)">
                                    </div>
                                    <button type="button" class="btn-sm btn-danger" onclick="removeFeatureItem(${idx}, ${itemIdx})" style="padding:0.5rem 0.6rem; font-size:0.75rem; margin-bottom:0.1rem;">Delete</button>
                                 </div>`;
                    });
                    html += `</div>`;
                }

                blockDiv.innerHTML = html;
                container.appendChild(blockDiv);
            });
        }

        // Intercept form submit to serialize canvas blocks into the final hidden textarea
        document.getElementById('cms-editor-form').addEventListener('submit', function(e) {
            const selectMode = document.getElementById('editor-mode-select');
            const finalInput = document.getElementById('final-content-input');
            
            if (selectMode && selectMode.value === 'canvas') {
                finalInput.value = JSON.stringify(canvasBlocks);
            } else {
                finalInput.value = document.getElementById('markdown-textarea').value;
            }
        });

        // First render
        <?php if ($type === 'page' && $modeVal === 'canvas'): ?>
            renderCanvasBlocks();
        <?php endif; ?>
    </script>

<?php endif; ?>
