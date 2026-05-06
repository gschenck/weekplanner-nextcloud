<?php

/**
 * Locally verify a Nextcloud app's signature.json the same way the
 * server does on install / `occ integrity:check-app`.
 *
 * Mirrors lib/private/IntegrityCheck/Checker::verify() for an app path:
 *   1. Load signature.json, ksort hashes, decode signature.
 *   2. Verify RSA-SHA512 PKCS#1 v1.5 signature over json_encode(hashes)
 *      using the public key embedded in the bundled certificate.
 *   3. Re-hash the app directory and report any missing / extra / changed
 *      files vs the stored hashes.
 *
 * Optional flags:
 *   --root-ca=<path>  Verify the bundled certificate against this CA cert
 *                     (Nextcloud's resources/codesigning/root.crt). Skipped
 *                     when not provided so contributors without the CA can
 *                     still validate hash + signature integrity locally.
 *   --cn=<appId>      Assert the certificate CN matches this app id.
 *
 * Usage:
 *   php tools/verify-app-signature.php <appPath> [--root-ca=<path>] [--cn=<appId>]
 *
 * Exit codes:
 *   0 — signature verified
 *   1 — verification failed (with a diagnostic on stderr)
 */

declare(strict_types=1);

if ($argc < 2) {
	fwrite(STDERR, "Usage: php verify-app-signature.php <appPath> [--root-ca=<path>] [--cn=<appId>]\n");
	exit(1);
}

$appPath = rtrim($argv[1], '/');
$rootCaPath = null;
$expectedCN = null;
for ($i = 2; $i < $argc; $i++) {
	if (str_starts_with($argv[$i], '--root-ca=')) {
		$rootCaPath = substr($argv[$i], strlen('--root-ca='));
	} elseif (str_starts_with($argv[$i], '--cn=')) {
		$expectedCN = substr($argv[$i], strlen('--cn='));
	} else {
		fwrite(STDERR, "::error::Unknown argument: {$argv[$i]}\n");
		exit(1);
	}
}

$signaturePath = "$appPath/appinfo/signature.json";
if (!file_exists($signaturePath)) {
	fwrite(STDERR, "::error::signature.json not found at $signaturePath\n");
	exit(1);
}

$signatureData = json_decode(file_get_contents($signaturePath), true);
if (!is_array($signatureData)
	|| !isset($signatureData['hashes'], $signatureData['signature'], $signatureData['certificate'])) {
	fwrite(STDERR, "::error::signature.json is malformed (missing hashes/signature/certificate)\n");
	exit(1);
}

// 1. Hashes & signature — sort like Nextcloud does before verifying.
$expectedHashes = $signatureData['hashes'];
ksort($expectedHashes);
$signature = base64_decode($signatureData['signature'], true);
if ($signature === false) {
	fwrite(STDERR, "::error::signature.json signature field is not valid base64\n");
	exit(1);
}
$certificate = $signatureData['certificate'];

// 2. Optional CA chain check.
if ($rootCaPath !== null) {
	$rootCa = @file_get_contents($rootCaPath);
	if ($rootCa === false) {
		fwrite(STDERR, "::error::Failed to read root CA: $rootCaPath\n");
		exit(1);
	}
	// openssl_x509_verify isn't a chain verifier, so use openssl_pkey_get_public on the CA
	// and call openssl verify equivalent via a tempfile + `openssl verify` is heavy.
	// We instead extract the CA's public key, then manually verify via openssl_x509_parse
	// for sanity. Full chain validation is the server's job; we only catch obvious mismatches.
	$caParsed = openssl_x509_parse($rootCa);
	$certParsed = openssl_x509_parse($certificate);
	if ($caParsed === false || $certParsed === false) {
		fwrite(STDERR, "::error::Failed to parse certificate(s)\n");
		exit(1);
	}
	if (($certParsed['issuer']['CN'] ?? null) !== ($caParsed['subject']['CN'] ?? null)) {
		fwrite(STDERR, sprintf(
			"::error::Certificate issuer CN (%s) does not match root CA CN (%s)\n",
			$certParsed['issuer']['CN'] ?? '?',
			$caParsed['subject']['CN'] ?? '?',
		));
		exit(1);
	}
}

// 3. Optional CN check.
if ($expectedCN !== null) {
	$certParsed = openssl_x509_parse($certificate);
	$cn = $certParsed['subject']['CN'] ?? null;
	if ($cn !== $expectedCN) {
		fwrite(STDERR, sprintf(
			"::error::Certificate CN (%s) does not match expected app id (%s)\n",
			$cn ?? '?',
			$expectedCN,
		));
		exit(1);
	}
}

// 4. Verify the RSA signature over json_encode(expectedHashes).
$publicKey = openssl_pkey_get_public($certificate);
if ($publicKey === false) {
	fwrite(STDERR, "::error::Failed to extract public key from bundled certificate\n");
	exit(1);
}
$verifyResult = openssl_verify(json_encode($expectedHashes), $signature, $publicKey, OPENSSL_ALGO_SHA512);
if ($verifyResult !== 1) {
	fwrite(STDERR, "::error::Signature could not get verified (openssl_verify returned $verifyResult).\n");
	fwrite(STDERR, "         This is the same error Nextcloud's integrity check would raise.\n");
	exit(1);
}

// 5. Re-hash the disk and compare to stored hashes.
$currentHashes = computeHashes($appPath);
ksort($currentHashes);

$missing = array_diff_key($expectedHashes, $currentHashes);
$extra = array_diff_key($currentHashes, $expectedHashes);
$changed = [];
foreach ($expectedHashes as $path => $hash) {
	if (isset($currentHashes[$path]) && $currentHashes[$path] !== $hash) {
		$changed[] = $path;
	}
}

if ($missing || $extra || $changed) {
	fwrite(STDERR, "::error::Hash mismatch — Nextcloud's integrity check would fail.\n");
	if ($missing) {
		fwrite(STDERR, 'Missing on disk (' . count($missing) . "):\n");
		foreach (array_keys($missing) as $f) {
			fwrite(STDERR, "  - $f\n");
		}
	}
	if ($extra) {
		fwrite(STDERR, 'Unsigned files on disk (' . count($extra) . "):\n");
		foreach (array_keys($extra) as $f) {
			fwrite(STDERR, "  - $f\n");
		}
	}
	if ($changed) {
		fwrite(STDERR, 'Modified after signing (' . count($changed) . "):\n");
		foreach ($changed as $f) {
			fwrite(STDERR, "  - $f\n");
		}
	}
	exit(1);
}

echo 'Signature verified for ' . count($expectedHashes) . " files in $appPath\n";

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
