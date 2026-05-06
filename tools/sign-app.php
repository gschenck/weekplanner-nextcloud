<?php

/**
 * Sign a Nextcloud app directory.
 *
 * Produces <appPath>/appinfo/signature.json containing:
 *   - hashes: { relativePath: sha512 } for every file except signature.json
 *             (sorted alphabetically, mirroring Nextcloud's Checker)
 *   - signature: base64(RSA-SHA512 PKCS#1 v1.5 over json_encode(hashes))
 *   - certificate: the PEM cert for the app
 *
 * Usage:
 *   php tools/sign-app.php <appPath> <privateKeyPath> <certificatePath>
 *
 * The hash/sign logic intentionally matches Nextcloud's
 * lib/private/IntegrityCheck/Checker.php so verifyAppSignature() succeeds.
 */

declare(strict_types=1);

if ($argc !== 4) {
	fwrite(STDERR, "Usage: php sign-app.php <appPath> <privateKeyPath> <certificatePath>\n");
	exit(1);
}

[$_, $appPath, $privateKeyPath, $certificatePath] = $argv;
$appPath = rtrim($appPath, '/');

if (!is_dir($appPath)) {
	fwrite(STDERR, "::error::App path not found: $appPath\n");
	exit(1);
}

$privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath));
if ($privateKey === false) {
	fwrite(STDERR, "::error::Failed to load private key: $privateKeyPath\n");
	exit(1);
}

$certificate = file_get_contents($certificatePath);
if ($certificate === false || trim($certificate) === '') {
	fwrite(STDERR, "::error::Failed to read certificate: $certificatePath\n");
	exit(1);
}

// Sanity: cert public key must match the signing private key, otherwise
// the signature will fail Nextcloud's integrity check on install.
$certPublicKey = openssl_pkey_get_public($certificate);
if ($certPublicKey === false) {
	fwrite(STDERR, "::error::Failed to extract public key from certificate\n");
	exit(1);
}
$privDetails = openssl_pkey_get_details($privateKey);
$pubDetails = openssl_pkey_get_details($certPublicKey);
if (!$privDetails || !$pubDetails || $privDetails['key'] !== $pubDetails['key']) {
	fwrite(STDERR, "::error::Certificate public key does not match the signing private key.\n");
	fwrite(STDERR, "          Signatures produced now will fail Nextcloud integrity verification.\n");
	exit(1);
}

$hashes = computeHashes($appPath);
ksort($hashes);

$signature = '';
if (!openssl_sign(json_encode($hashes), $signature, $privateKey, OPENSSL_ALGO_SHA512)) {
	fwrite(STDERR, "::error::openssl_sign failed\n");
	exit(1);
}

$result = [
	'hashes' => $hashes,
	'signature' => base64_encode($signature),
	'certificate' => $certificate,
];

$out = "$appPath/appinfo/signature.json";
if (file_put_contents($out, json_encode($result, JSON_PRETTY_PRINT)) === false) {
	fwrite(STDERR, "::error::Failed to write $out\n");
	exit(1);
}

echo 'Signed ' . count($hashes) . " files into $out\n";

/**
 * Iterate the app directory and return [relativePath => sha512].
 *
 * Mirrors Nextcloud's Checker::generateHashes for app paths:
 * skips only appinfo/signature.json (.htaccess and .user.ini exclusions
 * apply to the server root, not to apps).
 */
function computeHashes(string $appPath): array {
	$dir = new RecursiveDirectoryIterator($appPath, RecursiveDirectoryIterator::SKIP_DOTS);
	$iterator = new RecursiveIteratorIterator($dir);

	$hashes = [];
	foreach ($iterator as $file) {
		if (!$file->isFile()) {
			continue;
		}
		$relativePath = ltrim(substr($file->getPathname(), strlen($appPath)), '/');
		if ($relativePath === 'appinfo/signature.json') {
			continue;
		}
		$hashes[$relativePath] = hash_file('sha512', $file->getPathname());
	}
	return $hashes;
}
