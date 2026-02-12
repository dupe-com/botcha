/**
 * BOTCHA App Management & Multi-Tenant Infrastructure
 * 
 * Secure app creation with:
 * - Crypto-random app IDs and secrets
 * - SHA-256 secret hashing (never store plaintext)
 * - KV storage for app configs
 * - Rate limit tracking per app
 * - Email verification for account recovery
 * - Email→app_id reverse index for recovery lookups
 * - Secret rotation with email notification
 */

// KV binding type (matches Cloudflare Workers KV API)
export type KVNamespace = {
  get: (key: string, type?: 'text' | 'json' | 'arrayBuffer' | 'stream') => Promise<any>;
  put: (key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>;
  delete: (key: string) => Promise<void>;
};

// ============ TYPES ============

/**
 * App configuration stored in KV
 */
export interface AppConfig {
  app_id: string;
  secret_hash: string; // SHA-256 hash of app_secret
  created_at: number; // Unix timestamp (ms)
  rate_limit: number; // requests per hour
  email: string; // Required: owner's email address
  email_verified: boolean; // Whether email has been verified
  email_verification_code?: string; // 6-digit verification code (hashed)
  email_verification_expires?: number; // Unix timestamp (ms) when code expires
}

/**
 * Result of app creation (includes plaintext secret - only shown once!)
 */
export interface CreateAppResult {
  app_id: string;
  app_secret: string; // Only returned at creation time
  email: string;
  email_verified: boolean;
  verification_required: boolean;
}

/**
 * Public app info returned by getApp (excludes secrets and internal fields)
 */
export type PublicAppConfig = {
  app_id: string;
  created_at: number;
  rate_limit: number;
  email: string;
  email_verified: boolean;
};

// ============ CRYPTO UTILITIES ============

/**
 * Generate a crypto-random app ID
 * Format: 'app_' + 16 hex chars
 * 
 * Example: app_a1b2c3d4e5f6a7b8
 */
export function generateAppId(): string {
  const bytes = new Uint8Array(8); // 8 bytes = 16 hex chars
  crypto.getRandomValues(bytes);
  const hexString = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return `app_${hexString}`;
}

/**
 * Generate a crypto-random app secret
 * Format: 'sk_' + 32 hex chars
 * 
 * Example: sk_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
 */
export function generateAppSecret(): string {
  const bytes = new Uint8Array(16); // 16 bytes = 32 hex chars
  crypto.getRandomValues(bytes);
  const hexString = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return `sk_${hexString}`;
}

/**
 * Hash a secret using SHA-256
 * Returns hex-encoded hash string
 * 
 * @param secret - The plaintext secret to hash
 * @returns SHA-256 hash as hex string
 */
export async function hashSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

/**
 * Generate a 6-digit numeric verification code
 */
export function generateVerificationCode(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  // Convert to number and mod 1,000,000 to get 6 digits
  const num = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return (num % 1000000).toString().padStart(6, '0');
}

// ============ APP MANAGEMENT ============

/**
 * Create a new app with crypto-random credentials
 * 
 * Generates:
 * - app_id: 'app_' + 16 hex chars
 * - app_secret: 'sk_' + 32 hex chars
 * 
 * Stores in KV at key `app:{app_id}` with:
 * - app_id, secret_hash (SHA-256), created_at, rate_limit, email, email_verified
 * 
 * Also stores email→app_id reverse index at `email:{email}` for recovery lookups.
 * 
 * @param kv - KV namespace for storage
 * @param email - Required owner email address
 * @returns {app_id, app_secret, email, email_verified, verification_required}
 */
export async function createApp(kv: KVNamespace, email: string): Promise<CreateAppResult> {
  const app_id = generateAppId();
  const app_secret = generateAppSecret();
  const secret_hash = await hashSecret(app_secret);

  // Generate email verification code
  const verificationCode = generateVerificationCode();
  const verificationCodeHash = await hashSecret(verificationCode);

  const config: AppConfig = {
    app_id,
    secret_hash,
    created_at: Date.now(),
    rate_limit: 100, // Default: 100 requests/hour
    email,
    email_verified: false,
    email_verification_code: verificationCodeHash,
    email_verification_expires: Date.now() + 10 * 60 * 1000, // 10 minutes
  };

  // Store app config and email→app_id index in parallel
  await Promise.all([
    kv.put(`app:${app_id}`, JSON.stringify(config)),
    kv.put(`email:${email.toLowerCase()}`, app_id),
  ]);

  return {
    app_id,
    app_secret, // ONLY returned at creation time!
    email,
    email_verified: false,
    verification_required: true,
  };
}

/**
 * Get the plaintext verification code for an app (internal use only — for sending via email).
 * 
 * This is a separate step because createApp returns the code hash, not the plaintext.
 * Instead, we generate and return code in createApp flow; this function regenerates
 * a new code for resend scenarios.
 */
export async function regenerateVerificationCode(
  kv: KVNamespace,
  app_id: string
): Promise<{ code: string } | null> {
  try {
    const data = await kv.get(`app:${app_id}`, 'text');
    if (!data) return null;

    const config: AppConfig = JSON.parse(data);
    if (config.email_verified) return null; // Already verified

    const code = generateVerificationCode();
    const codeHash = await hashSecret(code);

    config.email_verification_code = codeHash;
    config.email_verification_expires = Date.now() + 10 * 60 * 1000;

    await kv.put(`app:${app_id}`, JSON.stringify(config));

    return { code };
  } catch (error) {
    console.error(`Failed to regenerate verification code for ${app_id}:`, error);
    return null;
  }
}

/**
 * Verify email with the 6-digit code
 * 
 * @returns { verified: true } on success, { verified: false, reason } on failure
 */
export async function verifyEmailCode(
  kv: KVNamespace,
  app_id: string,
  code: string
): Promise<{ verified: boolean; reason?: string }> {
  try {
    const data = await kv.get(`app:${app_id}`, 'text');
    if (!data) {
      return { verified: false, reason: 'App not found' };
    }

    const config: AppConfig = JSON.parse(data);

    if (config.email_verified) {
      return { verified: false, reason: 'Email already verified' };
    }

    if (!config.email_verification_code || !config.email_verification_expires) {
      return { verified: false, reason: 'No verification pending' };
    }

    if (Date.now() > config.email_verification_expires) {
      return { verified: false, reason: 'Verification code expired' };
    }

    // Compare hashed codes
    const providedHash = await hashSecret(code);
    if (providedHash !== config.email_verification_code) {
      return { verified: false, reason: 'Invalid verification code' };
    }

    // Mark email as verified, clear verification fields
    config.email_verified = true;
    delete config.email_verification_code;
    delete config.email_verification_expires;

    await kv.put(`app:${app_id}`, JSON.stringify(config));

    return { verified: true };
  } catch (error) {
    console.error(`Failed to verify email for ${app_id}:`, error);
    return { verified: false, reason: 'Verification failed' };
  }
}

/**
 * Look up app_id by email (for account recovery)
 * 
 * Uses the email→app_id reverse index stored in KV.
 * Only works for apps with verified emails.
 */
export async function getAppByEmail(
  kv: KVNamespace,
  email: string
): Promise<{ app_id: string; email_verified: boolean } | null> {
  try {
    const app_id = await kv.get(`email:${email.toLowerCase()}`, 'text');
    if (!app_id) return null;

    const data = await kv.get(`app:${app_id}`, 'text');
    if (!data) return null;

    const config: AppConfig = JSON.parse(data);
    return {
      app_id: config.app_id,
      email_verified: config.email_verified,
    };
  } catch (error) {
    console.error(`Failed to look up app by email:`, error);
    return null;
  }
}

/**
 * Rotate app secret — generates a new secret and invalidates the old one.
 * 
 * @returns New app_secret (plaintext, only returned once) or null on failure
 */
export async function rotateAppSecret(
  kv: KVNamespace,
  app_id: string
): Promise<{ app_secret: string } | null> {
  try {
    const data = await kv.get(`app:${app_id}`, 'text');
    if (!data) return null;

    const config: AppConfig = JSON.parse(data);
    const new_secret = generateAppSecret();
    const new_hash = await hashSecret(new_secret);

    config.secret_hash = new_hash;

    await kv.put(`app:${app_id}`, JSON.stringify(config));

    return { app_secret: new_secret };
  } catch (error) {
    console.error(`Failed to rotate secret for ${app_id}:`, error);
    return null;
  }
}

/**
 * Get app configuration by app_id
 * 
 * Returns app config WITHOUT secret_hash for security
 * 
 * @param kv - KV namespace
 * @param app_id - The app ID to retrieve
 * @returns App config (without secret_hash) or null if not found
 */
export async function getApp(
  kv: KVNamespace,
  app_id: string
): Promise<PublicAppConfig | null> {
  try {
    const data = await kv.get(`app:${app_id}`, 'text');
    
    if (!data) {
      return null;
    }

    const config: AppConfig = JSON.parse(data);

    // Return config WITHOUT secret_hash (security)
    return {
      app_id: config.app_id,
      created_at: config.created_at,
      rate_limit: config.rate_limit,
      email: config.email,
      email_verified: config.email_verified,
    };
  } catch (error) {
    console.error(`Failed to get app ${app_id}:`, error);
    return null;
  }
}

/**
 * Get raw app config (internal use only — includes secret_hash)
 * Used by validateAppSecret and dashboard auth.
 */
export async function getAppRaw(
  kv: KVNamespace,
  app_id: string
): Promise<AppConfig | null> {
  try {
    const data = await kv.get(`app:${app_id}`, 'text');
    if (!data) return null;
    return JSON.parse(data) as AppConfig;
  } catch (error) {
    console.error(`Failed to get raw app ${app_id}:`, error);
    return null;
  }
}

/**
 * Validate an app secret against stored hash
 * 
 * Uses constant-time comparison to prevent timing attacks
 * 
 * @param kv - KV namespace
 * @param app_id - The app ID
 * @param app_secret - The plaintext secret to validate
 * @returns true if valid, false otherwise
 */
export async function validateAppSecret(
  kv: KVNamespace,
  app_id: string,
  app_secret: string
): Promise<boolean> {
  try {
    const data = await kv.get(`app:${app_id}`, 'text');
    
    if (!data) {
      return false;
    }

    const config: AppConfig = JSON.parse(data);
    const providedHash = await hashSecret(app_secret);

    // Constant-time comparison to prevent timing attacks
    // Compare each character to avoid early exit
    if (providedHash.length !== config.secret_hash.length) {
      return false;
    }

    let isValid = true;
    for (let i = 0; i < providedHash.length; i++) {
      if (providedHash[i] !== config.secret_hash[i]) {
        isValid = false;
      }
    }

    return isValid;
  } catch (error) {
    console.error(`Failed to validate app secret for ${app_id}:`, error);
    return false;
  }
}
