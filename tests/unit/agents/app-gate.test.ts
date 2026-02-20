import { describe, expect, test } from 'vitest';
import {
  APP_GATE_OPEN_PATHS,
  isAppManagementPath,
  isPublicV1Path,
  shouldBypassAppGate,
} from '../../../packages/cloudflare-workers/src/app-gate.js';

describe('app-gate path rules', () => {
  test('includes expected static public paths', () => {
    expect(APP_GATE_OPEN_PATHS).toContain('/v1/ans/discover');
    expect(APP_GATE_OPEN_PATHS).toContain('/v1/ans/botcha');
    expect(APP_GATE_OPEN_PATHS).toContain('/v1/credentials/verify');
    expect(APP_GATE_OPEN_PATHS).toContain('/v1/x402/challenge');
  });

  test('app management paths are recognized', () => {
    expect(isAppManagementPath('/v1/apps/app_123/verify-email')).toBe(true);
    expect(isAppManagementPath('/v1/apps/app_123/resend-verification')).toBe(true);
    expect(isAppManagementPath('/v1/apps/app_123/rotate-secret')).toBe(false);
  });

  test('dynamic public v1 paths are recognized', () => {
    expect(isPublicV1Path('/v1/ans/resolve/myagent.example.com')).toBe(true);
    expect(isPublicV1Path('/v1/ans/resolve/ans%3A%2F%2Fv1.0.botcha.ai')).toBe(true);
    expect(isPublicV1Path('/v1/dids/did%3Aweb%3Abotcha.ai/resolve')).toBe(true);
    expect(isPublicV1Path('/v1/dids/did%3Akey%3Az6Mk/resolve')).toBe(true);
    expect(isPublicV1Path('/v1/dids/did%3Aweb%3Abotcha.ai')).toBe(false);
  });

  test('middleware bypass decision matches expected behavior', () => {
    // Public endpoints should bypass
    expect(shouldBypassAppGate('/v1/ans/discover')).toBe(true);
    expect(shouldBypassAppGate('/v1/ans/resolve/lookup')).toBe(true);
    expect(shouldBypassAppGate('/v1/ans/resolve/myagent.example.com')).toBe(true);
    expect(shouldBypassAppGate('/v1/credentials/verify')).toBe(true);
    expect(shouldBypassAppGate('/v1/dids/did%3Aweb%3Abotcha.ai/resolve')).toBe(true);

    // Protected endpoints should not bypass
    expect(shouldBypassAppGate('/v1/credentials/issue')).toBe(false);
    expect(shouldBypassAppGate('/v1/ans/verify')).toBe(false);
    expect(shouldBypassAppGate('/v1/agents/register')).toBe(false);
  });
});
