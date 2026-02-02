#!/bin/bash
# Simple API test script for BOTCHA CF Workers
# Run this while wrangler dev is running on localhost:8787

set -e

BASE_URL="${1:-http://localhost:8787}"

echo "🔍 Testing BOTCHA API at $BASE_URL"
echo ""

# Test 1: Root endpoint
echo "1️⃣  Testing GET / (info)"
curl -s "$BASE_URL/" | jq -r '.name, .version, .runtime' || echo "❌ Failed"
echo ""

# Test 2: Health check
echo "2️⃣  Testing GET /health"
curl -s "$BASE_URL/health" | jq '.status' || echo "❌ Failed"
echo ""

# Test 3: Get v1 token challenge
echo "3️⃣  Testing GET /v1/token (JWT flow)"
RESPONSE=$(curl -s "$BASE_URL/v1/token")
CHALLENGE_ID=$(echo "$RESPONSE" | jq -r '.challenge.id')
PROBLEMS=$(echo "$RESPONSE" | jq -r '.challenge.problems')
echo "Challenge ID: $CHALLENGE_ID"
echo "Problems: $PROBLEMS"
echo ""

# Test 4: Solve challenge (we'll use a mock solution - this will fail verification)
echo "4️⃣  Testing POST /v1/token/verify (will fail with wrong answers)"
curl -s -X POST "$BASE_URL/v1/token/verify" \
  -H "Content-Type: application/json" \
  -d "{\"id\":\"$CHALLENGE_ID\",\"answers\":[\"wrong\",\"wrong\",\"wrong\",\"wrong\",\"wrong\"]}" \
  | jq '.' || echo "❌ Request failed"
echo ""

# Test 5: Generate v1 challenge
echo "5️⃣  Testing GET /v1/challenges?type=speed"
curl -s "$BASE_URL/v1/challenges?type=speed" | jq -r '.success, .type, .challenge.timeLimit' || echo "❌ Failed"
echo ""

# Test 6: Legacy endpoint backward compatibility
echo "6️⃣  Testing legacy GET /api/speed-challenge"
curl -s "$BASE_URL/api/speed-challenge" | jq -r '.success, .warning' || echo "❌ Failed"
echo ""

echo "✅ Basic API tests complete!"
echo ""
echo "To test JWT auth flow fully:"
echo "1. GET /v1/token to get challenge"
echo "2. Solve the SHA256 problems"
echo "3. POST /v1/token/verify with solutions"
echo "4. Use returned JWT token with GET /agent-only"
