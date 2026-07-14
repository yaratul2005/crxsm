<?php
/**
 * CRXSM Admin View - Support Tickets Dashboard
 */

if (!defined('CRXSM_ACCESS')) {
    http_response_code(403);
    die("Direct access not allowed.");
}

use Vault\DB;
use Vault\Csrf;
use Vault\Mailer;
use Vault\Audit;

$successMsg = '';
$errorMsg = '';

// Retrieve settings for notifications
$siteName = getSettingVal('site_name', 'CRXSM Platform');
$baseUrl = rtrim($config['base_url'], '/');

// Handle Actions (Replies / Status Changes)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Csrf::verifyOrDie();
    
    $action = $_POST['action'] ?? '';
    $ticketId = (int)($_POST['ticket_id'] ?? 0);
    
    // 1. Post a reply
    if ($action === 'reply' && $ticketId > 0) {
        $message = trim($_POST['message'] ?? '');
        $newStatus = $_POST['status'] ?? 'pending';
        
        if (empty($message)) {
            $errorMsg = "Reply message cannot be empty.";
        } else {
            // Find ticket
            $ticket = DB::fetch("SELECT * FROM support_tickets WHERE id = ?", [$ticketId]);
            if ($ticket) {
                // Insert message
                DB::execute(
                    "INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message) VALUES (?, 'admin', 'System Admin', ?)",
                    [$ticketId, $message]
                );
                
                // Update status
                DB::execute(
                    "UPDATE support_tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    [$newStatus, $ticketId]
                );
                
                Audit::log('admin', $admin['id'], 'ticket_reply', "Replied to Ticket #{$ticketId} (new status: {$newStatus})");
                
                // Send email alert to client
                $trackingUrl = $baseUrl . '/?action=track&token=' . $ticket['ticket_token'];
                $subject = "Update on your ticket: " . $ticket['subject'];
                $mailBody = "<h3>Support Ticket Update</h3>" .
                            "<p>Hello " . htmlspecialchars($ticket['name']) . ",</p>" .
                            "<p>An administrator has replied to your support ticket regarding: <strong>" . htmlspecialchars($ticket['subject']) . "</strong></p>" .
                            "<p><strong>Message summary:</strong></p>" .
                            "<blockquote style='background:#f1f5f9; padding:12px; border-left:4px solid #2563eb; color:#334155; margin:1rem 0; font-style:italic;'>" . 
                            nl2br(htmlspecialchars(substr($message, 0, 300))) . "...</blockquote>" .
                            "<p>To view the full response and reply back, click the tracking link below:</p>" .
                            "<p><a href='{$trackingUrl}' style='display:inline-block; padding:10px 20px; background:#2563eb; color:#fff; text-decoration:none; border-radius:6px; font-weight:bold;'>View Conversation Thread</a></p>";
                
                Mailer::send($ticket['email'], $subject, $mailBody);
                $successMsg = "Reply posted and email notification sent.";
                
                // Redirect to keep selected ticket active in view
                header("Location: index.php?view=tickets&id=" . $ticketId);
                exit;
            } else {
                $errorMsg = "Ticket not found.";
            }
        }
    }
    
    // 2. Change ticket status directly
    if ($action === 'change_status' && $ticketId > 0) {
        $newStatus = $_POST['status'] ?? 'open';
        $exists = DB::fetch("SELECT id FROM support_tickets WHERE id = ?", [$ticketId]);
        if ($exists) {
            DB::execute("UPDATE support_tickets SET status = ? WHERE id = ?", [$newStatus, $ticketId]);
            Audit::log('admin', $admin['id'], 'ticket_status_change', "Changed status of Ticket #{$ticketId} to {$newStatus}");
            $successMsg = "Ticket status updated to " . strtoupper($newStatus) . ".";
            header("Location: index.php?view=tickets&id=" . $ticketId);
            exit;
        }
    }
}

// Fetch active tickets list
$statusFilter = $_GET['status'] ?? 'all';
$selectedId = (int)($_GET['id'] ?? 0);

$querySql = "SELECT * FROM support_tickets";
$params = [];
if ($statusFilter !== 'all') {
    $querySql .= " WHERE status = ?";
    $params[] = $statusFilter;
}
$querySql .= " ORDER BY updated_at DESC";
$tickets = DB::fetchAll($querySql, $params);

// Fetch details for selected ticket
$selectedTicket = null;
$messages = [];
if ($selectedId > 0) {
    $selectedTicket = DB::fetch("SELECT * FROM support_tickets WHERE id = ?", [$selectedId]);
    if ($selectedTicket) {
        $messages = DB::fetchAll("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [$selectedId]);
    }
}
?>

<?php if (!empty($successMsg)): ?>
    <div style="background:#d1fae5; color:#065f46; border:1px solid #a7f3d0; padding:1rem; border-radius:8px; margin-bottom:1.5rem;">
        <?php echo htmlspecialchars($successMsg); ?>
    </div>
<?php endif; ?>

<?php if (!empty($errorMsg)): ?>
    <div style="background:#fee2e2; color:#991b1b; border:1px solid #fca5a5; padding:1rem; border-radius:8px; margin-bottom:1.5rem;">
        <?php echo htmlspecialchars($errorMsg); ?>
    </div>
<?php endif; ?>

<div class="tickets-layout">
    <!-- LEFT PANEL: TICKETS LIST -->
    <div class="tickets-sidebar card-box">
        <div class="sidebar-filter-tabs">
            <a href="index.php?view=tickets&status=all" class="<?php echo $statusFilter === 'all' ? 'active' : ''; ?>">All</a>
            <a href="index.php?view=tickets&status=open" class="<?php echo $statusFilter === 'open' ? 'active' : ''; ?>">Open</a>
            <a href="index.php?view=tickets&status=pending" class="<?php echo $statusFilter === 'pending' ? 'active' : ''; ?>">Pending</a>
            <a href="index.php?view=tickets&status=resolved" class="<?php echo $statusFilter === 'resolved' ? 'active' : ''; ?>">Resolved</a>
            <a href="index.php?view=tickets&status=closed" class="<?php echo $statusFilter === 'closed' ? 'active' : ''; ?>">Closed</a>
        </div>

        <div class="tickets-list">
            <?php if (empty($tickets)): ?>
                <div class="empty-list">No tickets found.</div>
            <?php else: ?>
                <?php foreach ($tickets as $t): ?>
                    <a href="index.php?view=tickets&status=<?php echo $statusFilter; ?>&id=<?php echo $t['id']; ?>" class="ticket-item <?php echo $selectedId === (int)$t['id'] ? 'active' : ''; ?>">
                        <div class="ticket-item-header">
                            <span class="ticket-author"><?php echo htmlspecialchars($t['name']); ?></span>
                            <span class="ticket-date"><?php echo date('M d', strtotime($t['updated_at'])); ?></span>
                        </div>
                        <div class="ticket-subject"><?php echo htmlspecialchars($t['subject']); ?></div>
                        <div class="ticket-item-footer">
                            <span class="ticket-badge badge-<?php echo $t['status']; ?>"><?php echo $t['status']; ?></span>
                            <code class="ticket-token-label"><?php echo $t['ticket_token']; ?></code>
                        </div>
                    </a>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- RIGHT PANEL: TICKET DETAILS & CONVERSATION -->
    <div class="ticket-view-pane card-box">
        <?php if ($selectedTicket): ?>
            <div class="ticket-detail-header">
                <div class="header-main-info">
                    <h2><?php echo htmlspecialchars($selectedTicket['subject']); ?></h2>
                    <div class="ticket-meta-row">
                        <span>Submitted by: <strong><?php echo htmlspecialchars($selectedTicket['name']); ?></strong> (<?php echo htmlspecialchars($selectedTicket['email']); ?>)</span>
                        <span>Token: <code><?php echo $selectedTicket['ticket_token']; ?></code></span>
                    </div>
                </div>
                
                <!-- Quick Status change controls -->
                <div class="header-status-controls">
                    <form action="index.php?view=tickets&id=<?php echo $selectedId; ?>" method="post" style="display:inline-flex; gap:0.5rem; align-items:center;">
                        <?php echo Csrf::getHiddenInput(); ?>
                        <input type="hidden" name="action" value="change_status">
                        <input type="hidden" name="ticket_id" value="<?php echo $selectedId; ?>">
                        <select name="status" class="form-control" onchange="this.form.submit()" style="width: auto; padding: 0.3rem 0.5rem;">
                            <option value="open" <?php echo $selectedTicket['status'] === 'open' ? 'selected' : ''; ?>>Open</option>
                            <option value="pending" <?php echo $selectedTicket['status'] === 'pending' ? 'selected' : ''; ?>>Pending Response</option>
                            <option value="resolved" <?php echo $selectedTicket['status'] === 'resolved' ? 'selected' : ''; ?>>Resolved</option>
                            <option value="closed" <?php echo $selectedTicket['status'] === 'closed' ? 'selected' : ''; ?>>Closed</option>
                        </select>
                    </form>
                </div>
            </div>

            <!-- CHAT LOGS -->
            <div class="chat-thread-container">
                <?php foreach ($messages as $msg): ?>
                    <div class="chat-bubble-wrapper <?php echo $msg['sender_type'] === 'admin' ? 'bubble-right' : 'bubble-left'; ?>">
                        <div class="chat-bubble">
                            <div class="bubble-sender"><?php echo htmlspecialchars($msg['sender_name']); ?></div>
                            <div class="bubble-content"><?php echo nl2br(htmlspecialchars($msg['message'])); ?></div>
                            <div class="bubble-time"><?php echo date('h:i A - M d, Y', strtotime($msg['created_at'])); ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- REPLY FORM -->
            <?php if ($selectedTicket['status'] !== 'closed'): ?>
                <div class="chat-reply-box">
                    <form action="index.php?view=tickets&id=<?php echo $selectedId; ?>" method="post">
                        <?php echo Csrf::getHiddenInput(); ?>
                        <input type="hidden" name="action" value="reply">
                        <input type="hidden" name="ticket_id" value="<?php echo $selectedId; ?>">
                        
                        <div class="form-group">
                            <label class="form-label">Submit Response</label>
                            <textarea name="message" required class="form-control" rows="4" placeholder="Type your reply here..."></textarea>
                        </div>
                        
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div class="form-group" style="margin:0; display:flex; align-items:center; gap:0.5rem;">
                                <label class="form-label" style="margin:0;">Next Status:</label>
                                <select name="status" class="form-control" style="width:auto; padding:0.3rem 0.5rem;">
                                    <option value="pending" selected>Pending Response</option>
                                    <option value="resolved">Resolved</option>
                                    <option value="closed">Closed / Solved</option>
                                </select>
                            </div>
                            <button type="submit" class="btn-sm btn-primary" style="padding:0.6rem 1.5rem;">Send Response & Alert Client</button>
                        </div>
                    </form>
                </div>
            <?php else: ?>
                <div class="chat-closed-notice">
                    This ticket has been marked as CLOSED. If you want to reply, reopen the ticket by changing its status to "Open" in the drop-down.
                </div>
            <?php endif; ?>

        <?php else: ?>
            <div class="empty-state-view">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-muted); opacity:0.5; margin-bottom:1rem;">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                </svg>
                <h3>No Ticket Selected</h3>
                <p>Select a support ticket from the sidebar to view the conversation history and write replies.</p>
            </div>
        <?php endif; ?>
    </div>
</div>

<style>
    .tickets-layout {
        display: grid;
        grid-template-columns: 320px 1fr;
        gap: 2rem;
        height: calc(100vh - 180px);
        align-items: stretch;
    }
    
    .card-box {
        background: #fff;
        border: 1px solid var(--border-color);
        border-radius: 12px;
        display: flex;
        flex-direction: column;
        overflow: hidden;
    }
    
    /* Sidebar filters */
    .sidebar-filter-tabs {
        display: flex;
        overflow-x: auto;
        border-bottom: 1px solid var(--border-color);
        background: #f8fafc;
        padding: 0.5rem;
        gap: 0.25rem;
    }
    
    .sidebar-filter-tabs a {
        padding: 0.4rem 0.6rem;
        font-size: 0.75rem;
        font-weight: 600;
        text-decoration: none;
        color: var(--text-muted);
        border-radius: 6px;
        transition: all 0.2s;
        white-space: nowrap;
    }
    
    .sidebar-filter-tabs a.active, .sidebar-filter-tabs a:hover {
        background: #e2e8f0;
        color: var(--text-color);
    }
    
    .tickets-list {
        flex: 1;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
    }
    
    .empty-list {
        padding: 2rem;
        text-align: center;
        color: var(--text-muted);
        font-size: 0.9rem;
    }
    
    .ticket-item {
        padding: 1.25rem;
        border-bottom: 1px solid var(--border-color);
        text-decoration: none;
        color: inherit;
        display: flex;
        flex-direction: column;
        gap: 0.4rem;
        transition: background 0.2s;
    }
    
    .ticket-item:hover {
        background: #f8fafc;
    }
    
    .ticket-item.active {
        background: rgba(37, 99, 235, 0.05);
        border-left: 4px solid var(--primary);
        padding-left: 1.05rem;
    }
    
    .ticket-item-header {
        display: flex;
        justify-content: space-between;
        font-size: 0.75rem;
        color: var(--text-muted);
    }
    
    .ticket-author {
        font-weight: 600;
        color: var(--text-color);
    }
    
    .ticket-subject {
        font-weight: 500;
        font-size: 0.9rem;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    
    .ticket-item-footer {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-top: 0.25rem;
    }
    
    .ticket-token-label {
        font-size: 0.7rem;
        background: #f1f5f9;
        padding: 0.1rem 0.3rem;
        border-radius: 4px;
    }
    
    /* Badges */
    .ticket-badge {
        font-size: 0.7rem;
        font-weight: 700;
        padding: 0.15rem 0.4rem;
        border-radius: 50px;
        text-transform: uppercase;
        letter-spacing: 0.02em;
    }
    
    .badge-open { background: #fee2e2; color: #ef4444; }
    .badge-pending { background: #fef3c7; color: #d97706; }
    .badge-resolved { background: #d1fae5; color: #059669; }
    .badge-closed { background: #e2e8f0; color: #64748b; }
    
    /* Right Pane Detail */
    .ticket-view-pane {
        flex: 1;
    }
    
    .ticket-detail-header {
        padding: 1.5rem 2rem;
        border-bottom: 1px solid var(--border-color);
        background: #f8fafc;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 2rem;
    }
    
    .header-main-info h2 {
        font-size: 1.35rem;
        margin-bottom: 0.4rem;
        color: var(--text-color);
    }
    
    .ticket-meta-row {
        font-size: 0.8rem;
        color: var(--text-muted);
        display: flex;
        gap: 1.5rem;
    }
    
    /* Chat Thread */
    .chat-thread-container {
        flex: 1;
        overflow-y: auto;
        padding: 2rem;
        background: #f8fafc;
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
    }
    
    .chat-bubble-wrapper {
        display: flex;
        width: 100%;
    }
    
    .chat-bubble-wrapper.bubble-left { justify-content: flex-start; }
    .chat-bubble-wrapper.bubble-right { justify-content: flex-end; }
    
    .chat-bubble {
        max-width: 70%;
        padding: 1rem 1.25rem;
        border-radius: 12px;
        position: relative;
        box-shadow: 0 2px 8px rgba(0,0,0,0.02);
    }
    
    .bubble-left .chat-bubble {
        background: #fff;
        border: 1px solid var(--border-color);
        border-top-left-radius: 2px;
    }
    
    .bubble-right .chat-bubble {
        background: var(--primary);
        color: #fff;
        border-top-right-radius: 2px;
    }
    
    .bubble-sender {
        font-size: 0.7rem;
        font-weight: 700;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
        opacity: 0.8;
    }
    
    .bubble-content {
        font-size: 0.95rem;
        line-height: 1.5;
        word-break: break-word;
    }
    
    .bubble-time {
        font-size: 0.65rem;
        margin-top: 0.5rem;
        opacity: 0.7;
        text-align: right;
    }
    
    /* Reply & Closed Box */
    .chat-reply-box {
        padding: 1.5rem 2rem;
        border-top: 1px solid var(--border-color);
        background: #fff;
    }
    
    .chat-closed-notice {
        padding: 2rem;
        background: #f1f5f9;
        text-align: center;
        color: var(--text-muted);
        font-weight: 500;
        font-size: 0.9rem;
        border-top: 1px solid var(--border-color);
    }
    
    .empty-state-view {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 4rem;
        text-align: center;
    }
    
    .empty-state-view h3 {
        font-size: 1.2rem;
        margin-bottom: 0.5rem;
        color: var(--text-color);
    }
    
    .empty-state-view p {
        color: var(--text-muted);
        font-size: 0.9rem;
        max-width: 320px;
    }
</style>
