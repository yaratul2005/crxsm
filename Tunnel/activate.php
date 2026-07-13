<?php
/**
 * CRXSM API Endpoint - Activate License Key
 */

if (!isset($requestData) || !isset($software)) {
    http_response_code(400);
    die("Direct access not allowed.");
}

$licenseKey = $requestData['license_key'] ?? '';
$domain     = trim($requestData['domain'] ?? '');
$machineId  = trim($requestData['machine_id'] ?? '');

if (empty($licenseKey) || empty($domain) || empty($machineId)) {
    echo json_encode(['success' => false, 'error' => 'Missing required parameters (license_key, domain, machine_id).']);
    exit;
}

try {
    // 1. Verify Signature
    $payload = \Vault\Crypto::verifyLicenseKey($licenseKey, $software['public_key']);
    if (!$payload) {
        echo json_encode(['success' => false, 'error' => 'Invalid cryptographic signature.']);
        exit;
    }

    $licenseId = (int)$payload['license_id'];

    // 2. Fetch License Record
    $license = \Vault\DB::fetch("SELECT * FROM licenses WHERE id = :id", [':id' => $licenseId]);
    if (!$license) {
        echo json_encode(['success' => false, 'error' => 'License not found in registry.']);
        exit;
    }

    // 3. Status Checks
    if ($license['status'] === 'revoked') {
        echo json_encode(['success' => false, 'error' => 'This license has been revoked.']);
        exit;
    }

    if ($license['status'] === 'expired' || ($license['expires_at'] !== null && strtotime($license['expires_at']) < time())) {
        echo json_encode(['success' => false, 'error' => 'This license has expired.']);
        exit;
    }

    // 4. Check for Existing Activation
    $existing = \Vault\DB::fetch(
        "SELECT id FROM license_activations WHERE license_id = :license_id AND domain = :domain AND machine_id = :machine_id",
        [':license_id' => $licenseId, ':domain' => $domain, ':machine_id' => $machineId]
    );

    if ($existing) {
        // Just update last active timestamp
        \Vault\DB::execute(
            "UPDATE license_activations SET last_active_at = CURRENT_TIMESTAMP WHERE id = :id",
            [':id' => $existing['id']]
        );

        echo json_encode([
            'success' => true,
            'message' => 'License is already active on this system.',
            'license_id' => $licenseId
        ]);
        exit;
    }

    // 5. Check Activation Limits
    $activations = \Vault\DB::fetchAll("SELECT id FROM license_activations WHERE license_id = :id", [':id' => $licenseId]);
    $currentCount = count($activations);

    if ($currentCount >= (int)$license['activation_limit']) {
        echo json_encode([
            'success' => false, 
            'error' => 'Activation limit reached. Please deactivate an existing installation first.'
        ]);
        exit;
    }

    // 6. Record New Activation (bind domain and machine ID)
    $ip = \Vault\Audit::getIpAddress();
    \Vault\DB::execute(
        "INSERT INTO license_activations (license_id, domain, machine_id, ip_address) 
         VALUES (:license_id, :domain, :machine_id, :ip_address)",
        [
            ':license_id' => $licenseId,
            ':domain'     => $domain,
            ':machine_id' => $machineId,
            ':ip_address' => $ip
        ]
    );

    // 7. Update License Status if needed
    if ($license['status'] === 'generated' || $license['status'] === 'activated') {
        \Vault\DB::execute(
            "UPDATE licenses SET status = 'active' WHERE id = :id",
            [':id' => $licenseId]
        );
    }

    // 8. Log Audit
    \Vault\Audit::log('system', null, 'license_activated', "License ID {$licenseId} activated on {$domain} (Machine ID: {$machineId})");

    echo json_encode([
        'success' => true,
        'message' => 'Activation successful.',
        'license_id' => $licenseId
    ]);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => 'Activation error: ' . $e->getMessage()]);
}
