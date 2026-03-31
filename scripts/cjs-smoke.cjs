#!/usr/bin/env node
/**
 * CJS smoke test — verifies that all three published packages can be require()'d
 * after a tsup build. Run after `bun run build` in CI.
 */

'use strict';

const path = require('path');
const root = path.resolve(__dirname, '..');

let passed = 0;
let failed = 0;

function check(label, fn) {
  try {
    const result = fn();
    console.log(`  ✓ ${label}`);
    if (result && typeof result === 'object') {
      const keys = Object.keys(result).slice(0, 3);
      if (keys.length) console.log(`    exports: ${keys.join(', ')}${keys.length < Object.keys(result).length ? ', …' : ''}`);
    }
    passed++;
  } catch (err) {
    console.error(`  ✗ ${label}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

// ── @dupecom/botcha ────────────────────────────────────────────────────────────
console.log('\n@dupecom/botcha');
check('require("./dist/lib/index.cjs")', () =>
  require(path.join(root, 'dist/lib/index.cjs')),
);
check('require("./dist/lib/client/index.cjs")', () =>
  require(path.join(root, 'dist/lib/client/index.cjs')),
);
check('require("./dist/src/middleware/tap-enhanced-verify.cjs")', () =>
  require(path.join(root, 'dist/src/middleware/tap-enhanced-verify.cjs')),
);

// ── @dupecom/botcha-verify ─────────────────────────────────────────────────────
console.log('\n@dupecom/botcha-verify');
check('require("./packages/verify/dist/index.cjs")', () =>
  require(path.join(root, 'packages/verify/dist/index.cjs')),
);
check('require("./packages/verify/dist/middleware/express.cjs")', () =>
  require(path.join(root, 'packages/verify/dist/middleware/express.cjs')),
);
check('require("./packages/verify/dist/middleware/hono.cjs")', () =>
  require(path.join(root, 'packages/verify/dist/middleware/hono.cjs')),
);

// ── @dupecom/botcha-langchain ──────────────────────────────────────────────────
console.log('\n@dupecom/botcha-langchain');
check('require("./packages/langchain/dist/index.cjs")', () =>
  require(path.join(root, 'packages/langchain/dist/index.cjs')),
);

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n${passed + failed} checks: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
