<?php
/**
 * CRXSM API Endpoint - Heartbeat check-in
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

    // 2. Fetch Live License Data
    $license = \Vault\DB::fetch("SELECT * FROM licenses WHERE id = :id", [':id' => $licenseId]);
    if (!$license) {
        echo json_encode(['success' => false, 'error' => 'License not found.']);
        exit;
    }

    // 3. Locate Activation Record
    $activation = \Vault\DB::fetch(
        "SELECT id FROM license_activations WHERE license_id = :license_id AND domain = :domain AND machine_id = :machine_id",
        [':license_id' => $licenseId, ':domain' => $domain, ':machine_id' => $machineId]
    );

    if ($activation) {
        // 4. Update last active check-in timestamp
        \Vault\DB::execute(
            "UPDATE license_activations SET last_active_at = CURRENT_TIMESTAMP WHERE id = :id",
            [':id' => $activation['id']]
        );

        echo json_encode([
            'success'    => true,
            'status'     => $license['status'],
            'expires_at' => $license['expires_at'],
            'message'    => 'Heartbeat recorded.'
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'error'   => 'Installation registration not found for this system. Activation is required.'
        ]);
    }

} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => 'Heartbeat error: ' . $e->getMessage()]);
}
