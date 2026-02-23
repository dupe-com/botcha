# BOTCHA Agent Re-Identification

Re-identify as a registered BOTCHA TAP agent using an Ed25519 keypair.

**Arguments:** `$ARGUMENTS` should be `<agent_id> <private_key_base64> [base_url]`

Run the following Node.js script in a single Bash call (all steps in-process to avoid nonce timeout):

```bash
node -e "
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const AGENT_ID = '$AGENT_ID';
const PRIV_B64 = '$PRIVATE_KEY';
const BASE_URL = '$BASE_URL';

const url = new URL(BASE_URL);
const lib = url.protocol === 'https:' ? https : http;

function post(path, body) {
  const s = JSON.stringify(body);
  return new Promise((res, rej) => {
    const r = lib.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s) }
    }, resp => { let d = ''; resp.on('data', c => d += c); resp.on('end', () => res(JSON.parse(d))); });
    r.on('error', rej);
    r.write(s); r.end();
  });
}

(async () => {
  // Step 1: get nonce
  const ch = await post('/v1/agents/auth', { agent_id: AGENT_ID });
  if (!ch.success) { console.error('AUTH_FAILED', JSON.stringify(ch)); process.exit(1); }

  // Step 2: sign nonce with Ed25519 private key
  // Reconstruct PKCS8 DER: fixed 16-byte header + 32-byte raw key
  const privDer = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(PRIV_B64, 'base64')
  ]);
  const privKey = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  const sig = crypto.sign(null, Buffer.from(ch.nonce, 'utf8'), privKey);

  // Step 3: verify signature, get agent JWT
  const result = await post('/v1/agents/auth/verify', {
    challenge_id: ch.challenge_id,
    agent_id: AGENT_ID,
    signature: sig.toString('base64')
  });

  if (!result.success) { console.error('VERIFY_FAILED', JSON.stringify(result)); process.exit(1); }

  console.log('ACCESS_TOKEN=' + result.access_token);
  console.log('AGENT_ID=' + result.agent_id);
  console.log('Re-identified successfully. Use this Bearer token for subsequent requests.');
})();
"
```

Replace `$AGENT_ID`, `$PRIVATE_KEY`, and `$BASE_URL` with actual values before running.

After running, save the printed `ACCESS_TOKEN` as your Bearer token for all subsequent API calls.
