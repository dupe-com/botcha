# Epic: x402 Payment Gating — Verified Agents Unlock Payment Rails

## Vision
Integrate x402 (HTTP 402 Payment Required protocol) so that BOTCHA-verified agents can natively access paid APIs and resources. BOTCHA becomes the trust gatekeeper for x402 commerce rails — unverified bots get blocked, verified agents transact. BOTCHA itself charges for verification *via x402*, creating a fully agent-native revenue stream.

## Why This Matters
x402 is the emerging standard for agent micropayments (75M+ txns, $24M volume, backed by Coinbase/Stripe/Adyen). Every serious agentic commerce flow will use it. BOTCHA sits at exactly the right layer: before payment, you need verified identity. BOTCHA = the toll booth before the payment highway.

## Standards / References
- x402 spec: https://x402.org / https://github.com/coinbase/x402
- HTTP 402 Payment Required (RFC hint)
- EIP-712 structured signing
- USDC on Base (primary settlement)
- Facilitator pattern (x402 payment facilitators: Coinbase, etc.)

## Scope

### 1. x402 Facilitator Endpoint (`POST /v1/x402/verify-payment`)
- Accepts x402 payment header from agent
- Verifies payment was made (signature + amount + recipient)
- Returns: verified/rejected + settlement details
- Enables botcha.ai to act as a lightweight x402-compatible service

### 2. BOTCHA Verification via x402 (`GET /v1/x402/challenge`)
- Agents can *pay* for a BOTCHA verification token instead of solving a challenge
- Price: configurable micropayment (e.g. $0.001 USDC per verification)
- Flow: agent sends x402 payment → BOTCHA issues verified access_token
- Creates a revenue stream: agents that don't want to solve challenges can pay

### 3. x402-Gated Agent-Only Endpoint (`GET /agent-only/x402`)
- Demo endpoint: requires BOTH BOTCHA verification + x402 payment
- Reference implementation that app developers can copy
- Shows the full "verified + paid" flow in one request

### 4. Verified Agent Badge in x402 Payloads
- When BOTCHA-verified agents make x402 payments, attach verification proof to payment metadata
- x402 recipients can check: "was this payer verified by BOTCHA?"
- Enables tiered pricing: verified agents pay less (lower fraud risk)

### 5. x402 Payment Webhook (`POST /v1/x402/webhook`)
- Receive settlement notifications from x402 facilitators (Coinbase CDP)
- Update agent reputation on successful payment (+score for honest commerce)
- Track payment history per agent_id

## Task List
- [ ] Research x402 JS/TS SDK (coinbase/x402) — understand facilitator interface
- [ ] Write `tap-x402.ts` — x402 payment verification logic
- [ ] Add `POST /v1/x402/verify-payment` route
- [ ] Add `GET /v1/x402/challenge` route (pay-for-verification)
- [ ] Add `GET /agent-only/x402` demo route
- [ ] Update `createTAPSessionRoute` to optionally accept x402 payment as auth alternative
- [ ] Add x402 metadata to BOTCHA access_tokens (payment proof embedding)
- [ ] Add `POST /v1/x402/webhook` route
- [ ] Unit tests: payment verification, pay-for-token flow, webhook handling
- [ ] Update ai.txt / openapi.json
- [ ] README section on x402 integration

## x402 Flow
```
Agent → GET /v1/challenges (or /v1/x402/challenge)
Server → 402 Payment Required
        { amount: "0.001", currency: "USDC", chain: "base", recipient: "0xBOTCHA..." }
Agent → pays via x402 X-Payment header
Server → issues access_token (same as challenge solve)
Agent → uses token for API calls
```

## Definition of Done
- [ ] Agent can pay $0.001 USDC → receive valid BOTCHA access_token
- [ ] x402 payment verification correctly validates signatures
- [ ] Demo `/agent-only/x402` endpoint works end-to-end
- [ ] Agent reputation updated on payment
- [ ] All tests passing, TypeScript clean
- [ ] PR open against main
