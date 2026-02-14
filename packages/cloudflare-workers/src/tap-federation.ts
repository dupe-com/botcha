/**
 * TAP Federation — External JWKS Federation for Cross-Platform Trust
 * Enables BOTCHA to verify agents signed by Visa or other TAP-compatible providers
 * Per Visa TAP spec: https://developer.visa.com/capabilities/trusted-agent-protocol
 */

// ============ TYPES ============

export interface FederatedKeySource {
  url: string;                        // JWKS endpoint URL
  name: string;                       // Human-readable name (e.g., 'visa')
  trustLevel: 'high' | 'medium' | 'low';  // Trust classification
  refreshInterval: number;            // How often to refresh keys (seconds)
  enabled: boolean;
}

export interface FederatedKey {
  kid: string;
  kty: string;                        // RSA, EC, OKP
  alg: string;                        // PS256, ES256, EdDSA
  publicKeyPem: string;               // Converted to PEM for verification
  source: string;                     // Source name (e.g., 'visa')
  sourceUrl: string;                  // Original JWKS URL
  trustLevel: 'high' | 'medium' | 'low';
  fetchedAt: number;                  // When this key was fetched
  expiresAt: number;                  // Cache expiration
  x5c?: string[];                     // X.509 cert chain if available
}

export interface FederationConfig {
  sources: FederatedKeySource[];
  kvNamespace?: KVNamespace;           // For persistent caching
  defaultRefreshInterval?: number;     // Default: 3600 (1 hour)
  maxCacheAge?: number;                // Default: 86400 (24 hours)
}

export interface KeyResolutionResult {
  found: boolean;
  key?: FederatedKey;
  error?: string;
}

// KV interface (matches Cloudflare Workers KV)
interface KVNamespace {
  get(key: string, type?: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

// ============ WELL-KNOWN SOURCES ============

export const WELL_KNOWN_SOURCES: FederatedKeySource[] = [
  {
    url: 'https://mcp.visa.com/.well-known/jwks',
    name: 'visa',
    trustLevel: 'high',
    refreshInterval: 3600,  // 1 hour
    enabled: true,
  },
  // Future: other payment schemes, agent providers, etc.
];

// ============ CORE FUNCTIONS ============

/**
 * Fetch JWKS from a URL
 * @throws Error if fetch fails or response is invalid
 */
export async function fetchJWKS(url: string): Promise<{ keys: any[] }> {
  const response = await fetch(url, {
    headers: { 'Accept': 'application/json' },
    // CF Workers: no timeout needed, runtime handles it
  });
  
  if (!response.ok) {
    throw new Error(`JWKS fetch failed: ${response.status} ${response.statusText}`);
  }
  
  const jwks = await response.json() as { keys: any[] };
  
  if (!jwks.keys || !Array.isArray(jwks.keys)) {
    throw new Error('Invalid JWKS: missing keys array');
  }
  
  return jwks;
}

/**
 * Convert a JWK from an external source to FederatedKey format
 */
export async function jwkToFederatedKey(
  jwk: any,
  source: FederatedKeySource
): Promise<FederatedKey> {
  // Determine the algorithm params for import
  const importParams = resolveImportParams(jwk);
  
  // Import the JWK into Web Crypto
  const cryptoKey = await crypto.subtle.importKey('jwk', jwk, importParams, true, ['verify']);
  
  // Export as SPKI to get PEM
  const spkiBuffer = await crypto.subtle.exportKey('spki', cryptoKey) as ArrayBuffer;
  const publicKeyPem = arrayBufferToPem(spkiBuffer);
  
  return {
    kid: jwk.kid,
    kty: jwk.kty,
    alg: jwk.alg || inferAlgorithm(jwk),
    publicKeyPem,
    source: source.name,
    sourceUrl: source.url,
    trustLevel: source.trustLevel,
    fetchedAt: Date.now(),
    expiresAt: Date.now() + source.refreshInterval * 1000,
    x5c: jwk.x5c,
  };
}

/**
 * Resolve Web Crypto import parameters based on JWK type
 */
export function resolveImportParams(jwk: any): any {
  const kty = jwk.kty;
  const alg = jwk.alg;
  
  if (kty === 'RSA') {
    return { name: 'RSA-PSS', hash: 'SHA-256' };
  }
  if (kty === 'EC') {
    return { name: 'ECDSA', namedCurve: jwk.crv || 'P-256' };
  }
  if (kty === 'OKP' && (jwk.crv === 'Ed25519' || alg === 'EdDSA')) {
    return { name: 'Ed25519' };
  }
  throw new Error(`Unsupported key type: ${kty}`);
}

/**
 * Infer algorithm from JWK if not specified
 */
export function inferAlgorithm(jwk: any): string {
  if (jwk.kty === 'RSA') return 'PS256';
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256';
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  return 'unknown';
}

/**
 * Convert ArrayBuffer to PEM string
 */
function arrayBufferToPem(buffer: ArrayBuffer): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const lines = base64.match(/.{1,64}/g) || [base64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

// ============ FEDERATION RESOLVER ============

export interface FederationResolver {
  resolveKey(kid: string): Promise<KeyResolutionResult>;
  refreshAll(): Promise<{ refreshed: number; errors: string[] }>;
  getCachedKeys(): FederatedKey[];
  clearCache(): void;
}

/**
 * Create a federation resolver that fetches and caches keys from external sources
 */
export function createFederationResolver(config: FederationConfig): FederationResolver {
  // In-memory cache (per-isolate)
  const memoryCache = new Map<string, FederatedKey>();
  
  return {
    /**
     * Resolve a public key by kid
     * Search order: memory cache → KV cache → fetch from sources
     */
    async resolveKey(kid: string): Promise<KeyResolutionResult> {
      // 1. Check memory cache
      const cached = memoryCache.get(kid);
      if (cached && Date.now() < cached.expiresAt) {
        return { found: true, key: cached };
      }
      
      // 2. Check KV cache
      if (config.kvNamespace) {
        try {
          const kvData = await config.kvNamespace.get(`federated_key:${kid}`, 'text');
          if (kvData) {
            const key = JSON.parse(kvData) as FederatedKey;
            if (Date.now() < key.expiresAt) {
              memoryCache.set(kid, key);
              return { found: true, key };
            }
          }
        } catch (error) {
          console.error('Federation: KV cache read error:', error);
          // Continue to fetch from sources
        }
      }
      
      // 3. Fetch from all enabled sources
      for (const source of config.sources.filter(s => s.enabled)) {
        try {
          const jwks = await fetchJWKS(source.url);
          
          // Opportunistically cache ALL keys from this fetch
          let foundKey: FederatedKey | undefined;
          for (const jwk of jwks.keys) {
            try {
              const key = await jwkToFederatedKey(jwk, source);
              memoryCache.set(jwk.kid, key);
              
              // Cache in KV
              if (config.kvNamespace) {
                try {
                  const ttl = Math.min(source.refreshInterval, config.maxCacheAge || 86400);
                  await config.kvNamespace.put(
                    `federated_key:${jwk.kid}`,
                    JSON.stringify(key),
                    { expirationTtl: ttl }
                  );
                } catch { /* skip write errors */ }
              }
              
              // Check if this is the key we're looking for
              if (jwk.kid === kid) {
                foundKey = key;
              }
            } catch { /* skip invalid keys */ }
          }
          
          // Return if we found the key in this source
          if (foundKey) {
            return { found: true, key: foundKey };
          }
        } catch (error) {
          console.error(`Federation: Failed to fetch from ${source.name}:`, error);
          // Continue to next source (fail-open per BOTCHA philosophy)
        }
      }
      
      return { found: false, error: `Key ${kid} not found in any federated source` };
    },
    
    /**
     * Refresh all keys from all sources (background job)
     */
    async refreshAll(): Promise<{ refreshed: number; errors: string[] }> {
      let refreshed = 0;
      const errors: string[] = [];
      
      for (const source of config.sources.filter(s => s.enabled)) {
        try {
          const jwks = await fetchJWKS(source.url);
          for (const jwk of jwks.keys) {
            try {
              const key = await jwkToFederatedKey(jwk, source);
              memoryCache.set(jwk.kid, key);
              if (config.kvNamespace) {
                try {
                  await config.kvNamespace.put(
                    `federated_key:${jwk.kid}`,
                    JSON.stringify(key),
                    { expirationTtl: source.refreshInterval }
                  );
                } catch (error) {
                  // Non-fatal
                }
              }
              refreshed++;
            } catch (e) {
              errors.push(`Failed to process key ${jwk.kid} from ${source.name}`);
            }
          }
        } catch (e) {
          errors.push(`Failed to fetch ${source.name}: ${e}`);
        }
      }
      
      return { refreshed, errors };
    },
    
    /**
     * Get all cached keys (for debugging/admin)
     */
    getCachedKeys(): FederatedKey[] {
      return Array.from(memoryCache.values());
    },
    
    /**
     * Clear all caches
     */
    clearCache(): void {
      memoryCache.clear();
    },
  };
}

// ============ CONVENIENCE EXPORTS ============

/**
 * Create a Visa-specific federation resolver
 */
export function createVisaFederationResolver(kvNamespace?: KVNamespace): FederationResolver {
  return createFederationResolver({
    sources: WELL_KNOWN_SOURCES,
    kvNamespace,
    defaultRefreshInterval: 3600,
    maxCacheAge: 86400,
  });
}

// ============ DEFAULT EXPORT ============

export default {
  fetchJWKS,
  jwkToFederatedKey,
  createFederationResolver,
  createVisaFederationResolver,
  resolveImportParams,
  inferAlgorithm,
  WELL_KNOWN_SOURCES,
};
