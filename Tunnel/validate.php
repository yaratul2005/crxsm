<?php
/**
 * CRXSM API Endpoint - Validate License Key
 */

if (!isset($requestData) || !isset($software)) {
    http_response_code(400);
    die("Direct access not allowed.");
}

$licenseKey = $requestData['license_key'] ?? '';

if (empty($licenseKey)) {
    echo json_encode(['success' => false, 'error' => 'Missing license_key parameter.']);
    exit;
}

try {
    // 1. Asynchronously Verify License Key Signature using Software Public Key
    $payload = \Vault\Crypto::verifyLicenseKey($licenseKey, $software['public_key']);
    
    if (!$payload) {
        echo json_encode(['success' => false, 'error' => 'Invalid cryptographic signature.']);
        exit;
    }

    $licenseId = (int)($payload['license_id'] ?? 0);
    $softwareId = (int)($payload['software_id'] ?? 0);

    // Ensure token belongs to this software
    if ($softwareId !== (int)$software['id']) {
        echo json_encode(['success' => false, 'error' => 'License key belongs to another software product.']);
        exit;
    }

    // 2. Fetch Live License Data from DB
    $license = \Vault\DB::fetch("SELECT * FROM licenses WHERE id = :id", [':id' => $licenseId]);
    if (!$license) {
        echo json_encode(['success' => false, 'error' => 'License record not found in registry.']);
        exit;
    }

    // 3. Expiry Check
    $isExpired = false;
    if ($license['expires_at'] !== null) {
        $expiryTime = strtotime($license['expires_at']);
        if ($expiryTime < time()) {
            $isExpired = true;
            if ($license['status'] !== 'expired') {
                // Update status to expired
                \Vault\DB::execute(
                    "UPDATE licenses SET status = 'expired' WHERE id = :id",
                    [':id' => $licenseId]
                );
                $license['status'] = 'expired';
                \Vault\Audit::log('system', null, 'license_expired', "License ID {$licenseId} auto-expired");
            }
        }
    }

    // 4. Return License Status
    // Get count of current activations
    $activations = \Vault\DB::fetchAll("SELECT domain, machine_id, last_active_at FROM license_activations WHERE license_id = :id", [':id' => $licenseId]);
    $activationCount = count($activations);

    echo json_encode([
        'success'          => true,
        'license_id'       => $licenseId,
        'status'           => $license['status'],
        'expires_at'       => $license['expires_at'],
        'activation_limit' => (int)$license['activation_limit'],
        'activation_count' => $activationCount,
        'activations'      => $activations
    ]);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => 'Validation error: ' . $e->getMessage()]);
}
