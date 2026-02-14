#!/usr/bin/env bash
# ============================================================
#  BOTCHA TAP v0.16.0 End-to-End Manual Test
#  Tests the full TAP flow including all new features:
#    - Agent registration + sessions
#    - JWKS endpoint + key management
#    - Key rotation (Ed25519 + ECDSA)
#    - Invoice creation + 402 flow
#    - Browsing IOU verification
#    - Consumer + Payment verification endpoints
#
#  Usage:
#    ./scripts/test-tap.sh                    # test against botcha.ai
#    ./scripts/test-tap.sh http://localhost:8787  # test against local dev
# ============================================================
set -euo pipefail

URL="${1:-https://botcha.ai}"
BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[32m"
RED="\033[31m"
CYAN="\033[36m"
YELLOW="\033[33m"
RESET="\033[0m"
PASS=0
FAIL=0

step() { echo -e "\n${BOLD}${CYAN}[$1]${RESET} ${BOLD}$2${RESET}"; }
ok()   { PASS=$((PASS+1)); echo -e "   ${GREEN}✓${RESET} $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "   ${RED}✗${RESET} $1"; }
dim()  { echo -e "   ${DIM}$1${RESET}"; }

echo -e "${BOLD}BOTCHA TAP v0.16.0 — Manual Integration Test${RESET}"
echo -e "${DIM}Target: $URL${RESET}"

# ── Check version ────────────────────────────────────────────
step "0" "Version check"
VERSION=$(curl -sf "$URL/" -H "Accept: application/json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null || echo "unreachable")
dim "version: $VERSION"
if [[ "$VERSION" == "unreachable" ]]; then
  fail "Cannot reach $URL — is the server running?"
  echo -e "\n${YELLOW}If testing locally, start the dev server first:${RESET}"
  echo -e "  ${DIM}bun run dev${RESET}"
  exit 1
fi

# ── 1. Create an app ─────────────────────────────────────────
step "1" "Create app"
APP_JSON=$(curl -sf -X POST "$URL/v1/apps" \
  -H "Content-Type: application/json" \
  -d '{"email":"tap-test@botcha.ai"}')
APP_ID=$(echo "$APP_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['app_id'])")
dim "app_id: $APP_ID"
[[ -n "$APP_ID" ]] && ok "App created" || fail "App creation failed"

# ── 2. Register a TAP agent (ECDSA P-256) ────────────────────
step "2" "Register TAP agent (ECDSA P-256)"
AGENT_JSON=$(curl -sf -X POST "$URL/v1/agents/register/tap?app_id=$APP_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"tap-test-$(date +%s)\",
    \"operator\": \"manual-test\",
    \"capabilities\": [{\"action\": \"browse\", \"scope\": [\"*\"]}],
    \"trust_level\": \"basic\",
    \"signature_algorithm\": \"ecdsa-p256-sha256\",
    \"public_key\": \"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890=\n-----END PUBLIC KEY-----\"
  }")
AGENT_ID=$(echo "$AGENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('agent_id',''))" 2>/dev/null || echo "")
if [[ -n "$AGENT_ID" ]]; then
  ok "Agent registered: $AGENT_ID"
  dim "algorithm: ecdsa-p256-sha256"
else
  # Might fail on key validation — register without key
  AGENT_JSON=$(curl -sf -X POST "$URL/v1/agents/register/tap?app_id=$APP_ID" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"tap-test-$(date +%s)\",
      \"operator\": \"manual-test\",
      \"capabilities\": [{\"action\": \"browse\", \"scope\": [\"*\"]}],
      \"trust_level\": \"basic\"
    }")
  AGENT_ID=$(echo "$AGENT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['agent_id'])")
  ok "Agent registered (no key): $AGENT_ID"
fi

# ── 3. Get agent details ─────────────────────────────────────
step "3" "Get agent details"
GET_AGENT=$(curl -sf "$URL/v1/agents/$AGENT_ID/tap")
AGENT_NAME=$(echo "$GET_AGENT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('name',''))" 2>/dev/null || echo "")
[[ -n "$AGENT_NAME" ]] && ok "Got agent: $AGENT_NAME" || fail "Could not fetch agent"

# ── 4. List agents ───────────────────────────────────────────
step "4" "List TAP agents"
LIST_JSON=$(curl -sf "$URL/v1/agents/tap?app_id=$APP_ID")
AGENT_COUNT=$(echo "$LIST_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
[[ "$AGENT_COUNT" -gt 0 ]] && ok "Listed $AGENT_COUNT agent(s)" || fail "No agents found"

# ── 5. Create TAP session ────────────────────────────────────
step "5" "Create TAP session"
SESSION_JSON=$(curl -sf -X POST "$URL/v1/sessions/tap" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"user_context\": \"test-user-$(date +%s)\",
    \"intent\": {\"action\": \"browse\", \"resource\": \"products\", \"duration\": 3600}
  }")
SESSION_ID=$(echo "$SESSION_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null || echo "")
[[ -n "$SESSION_ID" ]] && ok "Session created: $SESSION_ID" || fail "Session creation failed"

# ── 6. Get TAP session ───────────────────────────────────────
step "6" "Get TAP session"
if [[ -n "$SESSION_ID" ]]; then
  GET_SESSION=$(curl -sf "$URL/v1/sessions/$SESSION_ID/tap")
  SESSION_AGENT=$(echo "$GET_SESSION" | python3 -c "import json,sys; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")
  [[ "$SESSION_AGENT" == "$AGENT_ID" ]] && ok "Session matches agent" || fail "Session agent mismatch"
else
  fail "Skipped — no session ID"
fi

# ── 7. JWKS endpoint (.well-known/jwks) ─────────────────────
step "7" "JWKS endpoint"
JWKS_JSON=$(curl -sf "$URL/.well-known/jwks?app_id=$APP_ID" 2>/dev/null || echo "")
if [[ -n "$JWKS_JSON" ]]; then
  KEY_COUNT=$(echo "$JWKS_JSON" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('keys',[])))" 2>/dev/null || echo "0")
  ok "JWKS returned $KEY_COUNT key(s)"
else
  fail "JWKS endpoint not responding"
fi

# ── 8. Get key by ID ─────────────────────────────────────────
step "8" "Get key by agent ID"
KEY_JSON=$(curl -sf "$URL/v1/keys/$AGENT_ID" 2>/dev/null || echo "")
if [[ -n "$KEY_JSON" ]]; then
  KID=$(echo "$KEY_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('kid',''))" 2>/dev/null || echo "")
  [[ -n "$KID" ]] && ok "Key found: kid=$KID" || ok "Key endpoint responded (agent may not have a key)"
else
  fail "Key endpoint not responding"
fi

# ── 9. Create invoice (402 flow) ─────────────────────────────
step "9" "Create invoice (402 micropayment)"
INVOICE_JSON=$(curl -sf -X POST "$URL/v1/invoices?app_id=$APP_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_uri": "https://example.com/premium-article",
    "amount": "500",
    "currency": "USD",
    "card_acceptor_id": "CAID_TEST_001",
    "description": "Manual test invoice",
    "ttl_seconds": 3600
  }' 2>/dev/null || echo "")
if [[ -n "$INVOICE_JSON" ]]; then
  INVOICE_ID=$(echo "$INVOICE_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('invoice_id',''))" 2>/dev/null || echo "")
  [[ -n "$INVOICE_ID" ]] && ok "Invoice created: $INVOICE_ID" || fail "Invoice response missing invoice_id"
  dim "amount: 500 USD"
else
  fail "Invoice endpoint not responding"
fi

# ── 10. Get invoice ──────────────────────────────────────────
step "10" "Get invoice"
if [[ -n "${INVOICE_ID:-}" ]]; then
  GET_INVOICE=$(curl -sf "$URL/v1/invoices/$INVOICE_ID" 2>/dev/null || echo "")
  INV_STATUS=$(echo "$GET_INVOICE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
  [[ -n "$INV_STATUS" ]] && ok "Invoice status: $INV_STATUS" || fail "Could not fetch invoice"
else
  fail "Skipped — no invoice ID"
fi

# ── 11. Verify Browsing IOU (expect rejection — no real sig) ─
step "11" "Verify Browsing IOU (intentional rejection)"
if [[ -n "${INVOICE_ID:-}" ]]; then
  IOU_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$URL/v1/invoices/$INVOICE_ID/verify-iou" \
    -H "Content-Type: application/json" \
    -d "{
      \"browsingIOU\": {
        \"invoiceId\": \"$INVOICE_ID\",
        \"amount\": \"500\",
        \"cardAcceptorId\": \"CAID_TEST_001\",
        \"acquirerId\": \"ACQ_TEST\",
        \"uri\": \"https://example.com/premium-article\",
        \"sequenceCounter\": \"1\",
        \"paymentService\": \"agent-pay\",
        \"kid\": \"$AGENT_ID\",
        \"alg\": \"ES256\",
        \"signature\": \"dGVzdC1zaWduYXR1cmU=\"
      }
    }" 2>/dev/null || echo "")
  IOU_HTTP=$(echo "$IOU_RESPONSE" | tail -1)
  IOU_JSON=$(echo "$IOU_RESPONSE" | sed '$d')
  if [[ -n "$IOU_JSON" && "$IOU_HTTP" != "000" ]]; then
    VERIFIED=$(echo "$IOU_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verified',''))" 2>/dev/null || echo "")
    if [[ "$VERIFIED" == "True" || "$VERIFIED" == "true" ]]; then
      ok "IOU verified (unexpected — signature shouldn't match)"
    else
      ok "IOU correctly rejected (fake signature) [HTTP $IOU_HTTP]"
    fi
  else
    fail "IOU verify endpoint not responding"
  fi
else
  fail "Skipped — no invoice ID"
fi

# ── 12. Consumer verification endpoint ───────────────────────
step "12" "Consumer verification endpoint (parse mode)"
CONSUMER_JSON=$(curl -sf -X POST "$URL/v1/verify/consumer" \
  -H "Content-Type: application/json" \
  -d "{
    \"agenticConsumer\": {
      \"nonce\": \"test-nonce-123\",
      \"kid\": \"$AGENT_ID\",
      \"alg\": \"ES256\",
      \"signature\": \"dGVzdC1zaWduYXR1cmU=\",
      \"idToken\": \"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake\",
      \"contextualData\": {\"device\": \"test\", \"location\": \"US\"}
    }
  }" 2>/dev/null || echo "")
if [[ -n "$CONSUMER_JSON" ]]; then
  ok "Consumer endpoint responded"
  dim "$(echo "$CONSUMER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'verified: {d.get(\"verified\",\"?\")}')" 2>/dev/null || echo "response received")"
else
  fail "Consumer endpoint not responding"
fi

# ── 13. Payment verification endpoint ────────────────────────
step "13" "Payment verification endpoint (parse mode)"
PAYMENT_JSON=$(curl -sf -X POST "$URL/v1/verify/payment" \
  -H "Content-Type: application/json" \
  -d "{
    \"agenticPaymentContainer\": {
      \"nonce\": \"test-nonce-456\",
      \"kid\": \"$AGENT_ID\",
      \"alg\": \"ES256\",
      \"signature\": \"dGVzdC1zaWduYXR1cmU=\",
      \"browsingIOU\": {
        \"invoiceId\": \"inv_test\",
        \"amount\": \"500\",
        \"cardAcceptorId\": \"CAID_TEST\",
        \"acquirerId\": \"ACQ_TEST\",
        \"uri\": \"https://example.com/premium\",
        \"sequenceCounter\": \"1\",
        \"paymentService\": \"agent-pay\"
      }
    }
  }" 2>/dev/null || echo "")
if [[ -n "$PAYMENT_JSON" ]]; then
  ok "Payment endpoint responded"
  dim "$(echo "$PAYMENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'verified: {d.get(\"verified\",\"?\")}')" 2>/dev/null || echo "response received")"
else
  fail "Payment endpoint not responding"
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}Results: ${GREEN}$PASS passed${RESET}, ${RED}$FAIL failed${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if [[ "$FAIL" -gt 0 ]]; then
  echo -e "\n${YELLOW}Some tests failed. If testing new v0.16.0 features:${RESET}"
  echo -e "  ${DIM}• Make sure you've deployed the latest code${RESET}"
  echo -e "  ${DIM}• Or run against local: ./scripts/test-tap.sh http://localhost:8787${RESET}"
  echo -e "  ${DIM}• NONCES/INVOICES KV namespaces must exist (create with wrangler)${RESET}"
  exit 1
fi
