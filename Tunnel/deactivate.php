<?php
/**
 * CRXSM API Endpoint - Deactivate License Key
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

    // 2. Locate and Delete Activation Record
    $stmt = \Vault\DB::query(
        "DELETE FROM license_activations WHERE license_id = :license_id AND domain = :domain AND machine_id = :machine_id",
        [':license_id' => $licenseId, ':domain' => $domain, ':machine_id' => $machineId]
    );

    if ($stmt->rowCount() > 0) {
        // 3. Log Audit
        \Vault\Audit::log('system', null, 'license_deactivated', "License ID {$licenseId} deactivated on {$domain} (Machine: {$machineId})");

        echo json_encode([
            'success' => true,
            'message' => 'Deactivation successful.'
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'error' => 'No active installation found matching this domain and machine ID.'
        ]);
    }

} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => 'Deactivation error: ' . $e->getMessage()]);
}
