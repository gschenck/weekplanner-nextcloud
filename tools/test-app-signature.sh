#!/usr/bin/env bash
#
# Round-trip test for tools/sign-app.php and tools/verify-app-signature.php.
# Generates a throwaway RSA keypair + self-signed cert, signs a fixture app
# directory, then asserts that:
#   1. A clean signed app verifies.
#   2. Modifying any file after signing breaks verification.
#   3. Adding any file after signing breaks verification.
#   4. A cert/key mismatch is rejected at signing time.
#
# This is the CI gate that would have caught the v1.8.1 signing bug.
#
# Exits 0 on success, non-zero on the first failed assertion.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

red() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

# 1. Build a tiny fixture app.
APP="$WORK/weekplanner"
mkdir -p "$APP/appinfo" "$APP/lib" "$APP/js" "$APP/css"
cat > "$APP/appinfo/info.xml" <<'EOF'
<?xml version="1.0"?>
<info><id>weekplanner</id><version>0.0.0</version></info>
EOF
echo '// fixture' > "$APP/lib/Bootstrap.php"
echo '/* fixture */' > "$APP/js/main.js"
echo '/* fixture */' > "$APP/css/main.css"

# 2. Generate a throwaway key + self-signed cert with CN=weekplanner.
openssl req -new -newkey rsa:2048 -nodes -x509 -days 1 \
	-subj "/CN=weekplanner" \
	-keyout "$WORK/app.key" -out "$WORK/app.crt" 2>/dev/null

# 3. Happy path: sign + verify.
php "$ROOT_DIR/tools/sign-app.php" "$APP" "$WORK/app.key" "$WORK/app.crt" >/dev/null
php "$ROOT_DIR/tools/verify-app-signature.php" "$APP" --cn=weekplanner >/dev/null
green "[ok] clean signature verifies"

# 4. Tamper: modify a file → verify must fail.
echo '// tampered' >> "$APP/js/main.js"
if php "$ROOT_DIR/tools/verify-app-signature.php" "$APP" >/dev/null 2>&1; then
	red "[fail] modified file did not break verification"
	exit 1
fi
green "[ok] modified file breaks verification"

# 5. Re-sign, then add an extra file → verify must fail.
php "$ROOT_DIR/tools/sign-app.php" "$APP" "$WORK/app.key" "$WORK/app.crt" >/dev/null
echo 'sneaky' > "$APP/lib/Sneaky.php"
if php "$ROOT_DIR/tools/verify-app-signature.php" "$APP" >/dev/null 2>&1; then
	red "[fail] extra file did not break verification"
	exit 1
fi
green "[ok] extra file breaks verification"

# 6. Cert/key mismatch must be rejected by sign-app (the cause of the v1.8.1 bug
#    if APP_PRIVATE_KEY ever drifts from the published certificate).
openssl req -new -newkey rsa:2048 -nodes -x509 -days 1 \
	-subj "/CN=weekplanner" \
	-keyout "$WORK/other.key" -out "$WORK/other.crt" 2>/dev/null
rm -rf "$APP"
mkdir -p "$APP/appinfo"
echo '<?xml version="1.0"?><info><id>weekplanner</id></info>' > "$APP/appinfo/info.xml"
if php "$ROOT_DIR/tools/sign-app.php" "$APP" "$WORK/app.key" "$WORK/other.crt" >/dev/null 2>&1; then
	red "[fail] cert/key mismatch was not rejected"
	exit 1
fi
green "[ok] cert/key mismatch is rejected"

green "All signature round-trip checks passed."
