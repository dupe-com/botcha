import { describe, test, expect } from 'vitest';
import { isTrustedProvider, TRUSTED_PROVIDERS, verifyWebBotAuth } from '../../../src/utils/signature.js';

describe('Signature Utils', () => {
  describe('isTrustedProvider', () => {
    test('returns true for anthropic.com URLs', () => {
      expect(isTrustedProvider('https://api.anthropic.com/agents/123')).toBe(true);
      expect(isTrustedProvider('https://anthropic.com/directory')).toBe(true);
    });

    test('returns true for openai.com URLs', () => {
      expect(isTrustedProvider('https://api.openai.com/agents/456')).toBe(true);
      expect(isTrustedProvider('https://openai.com/directory')).toBe(true);
    });

    test('returns false for untrusted domain', () => {
      expect(isTrustedProvider('https://evil.com/fake-agent')).toBe(false);
      expect(isTrustedProvider('https://example.com/fake-directory')).toBe(false);
      expect(isTrustedProvider('https://notanthropic.net/phishing')).toBe(false);
    });

    test('handles invalid URLs gracefully', () => {
      expect(isTrustedProvider('not-a-url')).toBe(false);
      expect(isTrustedProvider('ftp://invalid')).toBe(false);
      expect(isTrustedProvider('')).toBe(false);
      expect(isTrustedProvider('javascript:alert(1)')).toBe(false);
    });
  });

  describe('TRUSTED_PROVIDERS', () => {
    test('contains expected providers', () => {
      expect(TRUSTED_PROVIDERS).toContain('anthropic.com');
      expect(TRUSTED_PROVIDERS).toContain('openai.com');
      expect(TRUSTED_PROVIDERS).toContain('api.anthropic.com');
      expect(TRUSTED_PROVIDERS).toContain('api.openai.com');
      expect(TRUSTED_PROVIDERS).toContain('openclaw.ai');
      expect(TRUSTED_PROVIDERS).toContain('bedrock.amazonaws.com');
    });

    test('is an array', () => {
      expect(Array.isArray(TRUSTED_PROVIDERS)).toBe(true);
      expect(TRUSTED_PROVIDERS.length).toBeGreaterThan(0);
    });
  });

  describe('Internal Functions', () => {
    test('parseSignatureInput - not exported (internal function)', () => {
      // Note: parseSignatureInput() is internal and not exported from signature.ts
      // This is intentional - it's an implementation detail.
      // If needed for testing, it could be exported in the future.
    });

    test('buildSignatureBase - not exported (internal function)', () => {
      // Note: buildSignatureBase() is internal and not exported from signature.ts
      // This is intentional - it's an implementation detail.
      // If needed for testing, it could be exported in the future.
    });
  });

  describe('verifyWebBotAuth', () => {
    test('returns invalid without Signature-Agent header', async () => {
      const result = await verifyWebBotAuth(
        {},
        'GET',
        '/api/challenge'
      );

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Missing Signature-Agent header');
    });

    test('returns invalid without Signature header', async () => {
      const result = await verifyWebBotAuth(
        {
          'signature-agent': 'https://api.anthropic.com/.well-known/directory',
        },
        'GET',
        '/api/challenge'
      );

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Missing Signature or Signature-Input header');
    });

    test('returns invalid without Signature-Input header', async () => {
      const result = await verifyWebBotAuth(
        {
          'signature-agent': 'https://api.anthropic.com/.well-known/directory',
          'signature': 'sig1=:abc123:',
        },
        'GET',
        '/api/challenge'
      );

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Missing Signature or Signature-Input header');
    });

    test('handles invalid directory URL gracefully', async () => {
      const result = await verifyWebBotAuth(
        {
          'signature-agent': 'https://invalid-provider.example/bad-directory',
          'signature': 'sig1=:abc123:',
          'signature-input': 'sig1=("@method" "@path");keyid="key-1"',
        },
        'GET',
        '/api/challenge'
      );

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Could not fetch agent directory');
    });

    test('returns error details in response', async () => {
      const result = await verifyWebBotAuth(
        {},
        'POST',
        '/api/verify'
      );

      expect(result).toHaveProperty('valid');
      expect(result).toHaveProperty('error');
      expect(result.valid).toBe(false);
      expect(typeof result.error).toBe('string');
    });
  });
});
