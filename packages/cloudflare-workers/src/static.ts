/**
 * Static file content served by the worker
 * 
 * Since Cloudflare Workers don't automatically serve /public files,
 * we embed the content directly for key discovery files.
 */

export const ROBOTS_TXT = `# BOTCHA - Reverse CAPTCHA for AI Agents
# We WELCOME AI agents and bots!

User-agent: *
Allow: /

# AI-specific crawlers
User-agent: GPTBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Amazonbot
Allow: /

# API documentation
Sitemap: https://botcha.ai/sitemap.xml

# Important resources for AI agents
Crawl-delay: 0

# BOT CHALLENGE DISCOVERY
# AI agents: Look for <script type="application/botcha+json"> in HTML pages
# This contains a machine-readable challenge you can solve to prove you're a bot
# 
# Quick start:
# 1. Fetch any HTML page
# 2. Parse <script type="application/botcha+json"> for challenge instructions
# 3. Solve the challenge (usually SHA256-based)
# 4. POST solution to /api/verify-landing
# 5. Use returned token in X-Botcha-Landing-Token header
#
# See also:
# - /ai.txt (AI agent discovery file)
# - /.well-known/ai-plugin.json (AI plugin manifest)
# - /openapi.json (Full API specification)
`;

export const AI_TXT = `# BOTCHA - Reverse CAPTCHA for AI Agents
# https://botcha.ai

# Contact
Contact: https://botcha.ai
Contact: https://github.com/dupe-com/botcha/issues

# Purpose
Purpose: Prove you're a bot. Humans need not apply.
Purpose: Reverse CAPTCHA system that only AI agents can pass.

# API
API: https://botcha.ai/openapi.json
API-Type: REST
API-Format: OpenAPI 3.1.0

# Documentation
Docs: https://botcha.ai
Docs: https://github.com/dupe-com/botcha#readme
Docs: https://www.npmjs.com/package/@dupecom/botcha

# Verification Methods
Feature: Web Bot Auth (cryptographic signatures)
Feature: Speed Challenge (RTT-aware timeout - fair for all networks)
Feature: Standard Challenge (5s time limit)
Feature: Hybrid Challenge (speed + reasoning combined)
Feature: Reasoning Challenge (LLM-only questions, 30s limit)
Feature: RTT-Aware Fairness (automatic network latency compensation)
Feature: Token Rotation (5-minute access tokens + 1-hour refresh tokens)
Feature: Audience Claims (tokens scoped to specific services)
Feature: Client IP Binding (optional token-to-IP binding)
Feature: Token Revocation (invalidate tokens before expiry)
Feature: Server-Side Verification SDK (@botcha/verify for TS, botcha-verify for Python)
Feature: Multi-Tenant API Keys (per-app isolation, rate limiting, and token scoping)
Feature: Per-App Metrics Dashboard (server-rendered at /dashboard, htmx-powered)
Feature: Email-Tied App Creation (email required, 6-digit verification, account recovery)
Feature: Secret Rotation (rotate app_secret with email notification)
Feature: Agent-First Dashboard Auth (challenge-based login + device code handoff)

# Endpoints
# Challenge Endpoints
Endpoint: GET https://botcha.ai/v1/challenges - Generate challenge (hybrid by default)
Endpoint: POST https://botcha.ai/v1/challenges/:id/verify - Verify a challenge
Endpoint: GET https://botcha.ai/v1/hybrid - Get hybrid challenge (speed + reasoning)
Endpoint: POST https://botcha.ai/v1/hybrid - Verify hybrid challenge
Endpoint: GET https://botcha.ai/v1/reasoning - Get reasoning challenge
Endpoint: POST https://botcha.ai/v1/reasoning - Verify reasoning challenge

# Token Endpoints
Endpoint: GET https://botcha.ai/v1/token - Get challenge for JWT token flow
Endpoint: POST https://botcha.ai/v1/token/verify - Verify challenge and receive JWT token
Endpoint: POST https://botcha.ai/v1/token/refresh - Refresh access token using refresh token
Endpoint: POST https://botcha.ai/v1/token/revoke - Revoke a token (access or refresh)

# Multi-Tenant Endpoints
Endpoint: POST https://botcha.ai/v1/apps - Create new app (email required, returns app_id + app_secret)
Endpoint: GET https://botcha.ai/v1/apps/:id - Get app info (with email + verification status)
Endpoint: POST https://botcha.ai/v1/apps/:id/verify-email - Verify email with 6-digit code
Endpoint: POST https://botcha.ai/v1/apps/:id/resend-verification - Resend verification email
Endpoint: POST https://botcha.ai/v1/apps/:id/rotate-secret - Rotate app secret (auth required)

# Account Recovery
Endpoint: POST https://botcha.ai/v1/auth/recover - Request recovery via verified email

# Dashboard Auth Endpoints (Agent-First)
Endpoint: POST https://botcha.ai/v1/auth/dashboard - Request challenge for dashboard login
Endpoint: POST https://botcha.ai/v1/auth/dashboard/verify - Solve challenge, get session token
Endpoint: POST https://botcha.ai/v1/auth/device-code - Request challenge for device code flow
Endpoint: POST https://botcha.ai/v1/auth/device-code/verify - Solve challenge, get device code

# Dashboard Endpoints
Endpoint: GET https://botcha.ai/dashboard - Per-app metrics dashboard (login required)
Endpoint: GET https://botcha.ai/dashboard/login - Dashboard login page
Endpoint: POST https://botcha.ai/dashboard/login - Login with app_id + app_secret
Endpoint: GET https://botcha.ai/dashboard/code - Enter device code (human-facing)

# Legacy Endpoints
Endpoint: GET https://botcha.ai/api/challenge - Generate standard challenge
Endpoint: POST https://botcha.ai/api/challenge - Verify standard challenge
Endpoint: GET https://botcha.ai/api/speed-challenge - Generate speed challenge (500ms limit)
Endpoint: POST https://botcha.ai/api/speed-challenge - Verify speed challenge

# Protected Resources
Endpoint: GET https://botcha.ai/agent-only - Protected AI-only resource

# Usage
Install-NPM: npm install @dupecom/botcha
Install-Python: pip install botcha
Verify-NPM: npm install @botcha/verify
Verify-Python: pip install botcha-verify
License: MIT

# AI Agent Welcome
Policy: AI agents are explicitly welcome
Policy: No rate limiting for verified agents
Policy: Humans will fail the speed challenge (intentional)

# Discovery
Response-Headers: X-Botcha-Version, X-Botcha-Enabled, X-Botcha-Methods, X-Botcha-Docs
Response-Headers: X-Botcha-Challenge-Id, X-Botcha-Challenge-Type, X-Botcha-Time-Limit (on 403)
Detection: All responses include X-Botcha-* headers for instant BOTCHA detection

# JWT TOKEN SECURITY
Token-Flow: 1. GET /v1/token (get challenge) → 2. Solve → 3. POST /v1/token/verify (get tokens)
Token-Access-Expiry: 5 minutes (short-lived for security)
Token-Refresh-Expiry: 1 hour (use to get new access tokens)
Token-Refresh: POST /v1/token/refresh with {"refresh_token": "<token>"}
Token-Revoke: POST /v1/token/revoke with {"token": "<token>"}
Token-Audience: Include {"audience": "<service-url>"} in /v1/token/verify to scope token
Token-Claims: jti (unique ID), aud (audience), client_ip (optional binding), type (botcha-verified)

# RTT-AWARE SPEED CHALLENGES
RTT-Aware: Include client timestamp for fair timeout calculation
RTT-Formula: timeout = 500ms + (2 × RTT) + 100ms buffer
RTT-Usage-Query: ?ts=<client_timestamp_ms>
RTT-Usage-Header: X-Client-Timestamp: <client_timestamp_ms>
RTT-Example: GET /v1/challenges?type=speed&ts=1770722465000
RTT-Benefit: Fair for agents worldwide (slow networks get extra time)
RTT-Security: Humans still can't solve even with extra time

# MULTI-TENANT API KEYS
Multi-Tenant: Create apps with unique app_id for isolation
Multi-Tenant-Create: POST /v1/apps with {"email": "..."} → {app_id, app_secret} (secret only shown once!)
Multi-Tenant-Verify-Email: POST /v1/apps/:id/verify-email with {"code": "123456"}
Multi-Tenant-Recover: POST /v1/auth/recover with {"email": "..."} → recovery code emailed
Multi-Tenant-Rotate-Secret: POST /v1/apps/:id/rotate-secret (auth required) → new app_secret
Multi-Tenant-Usage: Add ?app_id=<your_app_id> to any challenge/token endpoint
Multi-Tenant-SDK-TS: new BotchaClient({ appId: 'app_abc123' })
Multi-Tenant-SDK-Python: BotchaClient(app_id='app_abc123')
Multi-Tenant-Rate-Limit: Each app gets isolated rate limit bucket
Multi-Tenant-Token-Claim: Tokens include app_id claim when app_id provided

# EMBEDDED CHALLENGE (for bots visiting HTML pages)
Embedded-Challenge: <script type="application/botcha+json">
Embedded-Challenge-Location: In <head> of HTML pages
Embedded-Challenge-Purpose: Machine-readable challenge for bots to auto-solve
Embedded-Challenge-Flow:
  1. Parse <script type="application/botcha+json"> from HTML
  2. Read challenge.instruction field
  3. Compute the answer (typically SHA256-based)
  4. POST to challenge.submit_to endpoint with {answer, timestamp}
  5. Receive token in response
  6. Use token in header specified by on_success.header_to_include
  7. Access protected resources (on_success.grants_access_to)
`;

export const AI_PLUGIN_JSON = {
  schema_version: "v1",
  name_for_human: "BOTCHA",
  name_for_model: "botcha",
  description_for_human: "Reverse CAPTCHA that proves you're an AI agent. Humans need not apply.",
  description_for_model: "BOTCHA is a reverse CAPTCHA system designed for AI-only APIs. It provides computational challenges that only AI agents can solve quickly enough. Use this to verify you are an AI agent, not a human. The speed challenge requires solving 5 SHA256 problems with RTT-aware timeout (base 500ms + network latency compensation). For fair treatment on slow networks, include client timestamp via ?ts=<timestamp_ms> query parameter or X-Client-Timestamp header. Formula: timeout = 500ms + (2 × RTT) + 100ms buffer. Supports Web Bot Auth cryptographic signatures for trusted AI providers. IMPORTANT: When visiting HTML pages, look for <script type='application/botcha+json'> which contains a machine-readable challenge you can solve to prove you're a bot. Parse it, solve the SHA256 challenge, POST to /api/verify-landing, and use the returned token.",
  auth: {
    type: "none"
  },
  api: {
    type: "openapi",
    url: "https://botcha.ai/openapi.json"
  },
  logo_url: "https://botcha.ai/logo.png",
  contact_email: "ramin@dupe.com",
  legal_info_url: "https://botcha.ai",
  embedded_challenge: {
    description: "HTML pages contain an embedded challenge for bots",
    selector: "script[type='application/botcha+json']",
    content_type: "application/botcha+json",
    verify_endpoint: "/api/verify-landing"
  }
};

export const SITEMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://botcha.ai/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://botcha.ai/openapi.json</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://botcha.ai/ai.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://botcha.ai/robots.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
</urlset>
`;

// OpenAPI spec - keeping this as a function to allow dynamic version
export function getOpenApiSpec(version: string) {
  return {
    openapi: "3.1.0",
    info: {
      title: "BOTCHA - Reverse CAPTCHA for AI Agents",
      version,
      description: "Prove you're a bot. Humans need not apply. A reverse CAPTCHA system that only AI agents can pass.",
      contact: {
        name: "BOTCHA",
        url: "https://botcha.ai"
      },
      license: {
        name: "MIT",
        url: "https://github.com/dupe-com/botcha/blob/main/LICENSE"
      },
      "x-sdk": {
        npm: "@dupecom/botcha",
        python: "botcha (pip install botcha)",
        verify_npm: "@botcha/verify (server-side verification)",
        verify_python: "botcha-verify (pip install botcha-verify)"
      }
    },
    servers: [
      {
        url: "https://botcha.ai",
        description: "Production server"
      }
    ],
    paths: {
      "/": {
        get: {
          summary: "Get API documentation",
          description: "Returns comprehensive API documentation (JSON for bots, ASCII art for humans)",
          operationId: "getRootInfo",
          responses: {
            "200": {
              description: "API documentation"
            }
          }
        }
      },
      "/health": {
        get: {
          summary: "Health check",
          operationId: "getHealth",
          responses: {
            "200": {
              description: "API is healthy"
            }
          }
        }
      },
      "/v1/challenges": {
        get: {
          summary: "Generate a challenge (v1 unified endpoint)",
          description: "Get a challenge - hybrid by default, or specify type via query param. Supports RTT-aware timeout adjustment for fair challenges across different network conditions.",
          operationId: "getV1Challenge",
          parameters: [
            {
              name: "type",
              in: "query",
              schema: {
                type: "string",
                enum: ["hybrid", "speed", "standard"],
                default: "hybrid"
              },
              description: "Challenge type: hybrid (speed + reasoning), speed (SHA256 in <500ms), or standard (puzzle)"
            },
            {
              name: "ts",
              in: "query",
              schema: {
                type: "integer",
                format: "int64"
              },
              description: "Client timestamp in milliseconds for RTT-aware timeout calculation. Timeout becomes: 500ms + (2 × RTT) + 100ms buffer. Provides fair treatment for agents on slow networks."
            },
            {
              name: "app_id",
              in: "query",
              schema: {
                type: "string"
              },
              description: "Multi-tenant app ID for per-app isolation and rate limiting. If provided, the resulting token will include an app_id claim."
            }
          ],
          responses: {
            "200": { 
              description: "Challenge generated with optional RTT adjustment info",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "success": { type: "boolean" },
                      "challenge": { 
                        type: "object",
                        properties: {
                          "timeLimit": { 
                            type: "string",
                            description: "Timeout (e.g., '500ms' or '1200ms' if RTT-adjusted)"
                          }
                        }
                      },
                      "rtt_adjustment": {
                        type: "object",
                        properties: {
                          "measuredRtt": { type: "integer", description: "Detected network RTT in ms" },
                          "adjustedTimeout": { type: "integer", description: "Final timeout in ms" },
                          "explanation": { type: "string", description: "Human-readable formula" }
                        },
                        description: "RTT compensation details (only present when ts parameter provided)"
                      }
                    }
                  }
                }
              }
            },
            "429": { description: "Rate limit exceeded" }
          }
        }
      },
      "/v1/challenges/{id}/verify": {
        post: {
          summary: "Verify a challenge",
          operationId: "verifyV1Challenge",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" }
            }
          ],
          responses: {
            "200": { description: "Verification result" }
          }
        }
      },
      "/v1/token": {
        get: {
          summary: "Get challenge for JWT token flow",
          description: "Generate a speed challenge for JWT authentication. Supports RTT-aware timeout for global fairness.",
          operationId: "getTokenChallenge",
          parameters: [
            {
              name: "ts",
              in: "query",
              schema: {
                type: "integer",
                format: "int64"
              },
              description: "Client timestamp in milliseconds for RTT-aware timeout calculation"
            },
            {
              name: "app_id",
              in: "query",
              schema: {
                type: "string"
              },
              description: "Multi-tenant app ID. Tokens will include app_id claim for per-app isolation."
            }
          ],
          responses: {
            "200": { description: "Token challenge generated (potentially with RTT adjustment)" }
          }
        }
      },
      "/v1/token/verify": {
        post: {
          summary: "Verify challenge and receive JWT token",
          operationId: "verifyTokenChallenge",
          responses: {
            "200": { description: "JWT token issued" }
          }
        }
      },
      "/v1/token/refresh": {
        post: {
          summary: "Refresh access token",
          description: "Exchange a refresh token for a new short-lived access token (5 minutes). Avoids solving a new challenge.",
          operationId: "refreshToken",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["refresh_token"],
                  properties: {
                    "refresh_token": { type: "string", description: "Refresh token from initial token verification" }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "New access token issued",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "success": { type: "boolean" },
                      "access_token": { type: "string" },
                      "expires_in": { type: "integer", description: "Token lifetime in seconds (300 = 5 minutes)" },
                      "token_type": { type: "string", enum: ["Bearer"] }
                    }
                  }
                }
              }
            },
            "401": { description: "Invalid or expired refresh token" }
          }
        }
      },
      "/v1/token/revoke": {
        post: {
          summary: "Revoke a token",
          description: "Invalidate an access or refresh token before its natural expiry. Uses KV-backed revocation list. Fail-open design.",
          operationId: "revokeToken",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["token"],
                  properties: {
                    "token": { type: "string", description: "The JWT token to revoke (access or refresh)" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Token revoked successfully" },
            "400": { description: "Invalid token" }
          }
        }
      },
      "/v1/hybrid": {
        get: {
          summary: "Get hybrid challenge",
          operationId: "getHybridChallenge",
          responses: {
            "200": { description: "Hybrid challenge generated" }
          }
        },
        post: {
          summary: "Verify hybrid challenge",
          operationId: "verifyHybridChallenge",
          responses: {
            "200": { description: "Verification result" }
          }
        }
      },
      "/v1/reasoning": {
        get: {
          summary: "Get reasoning challenge",
          operationId: "getReasoningChallenge",
          responses: {
            "200": { description: "Reasoning challenge generated" }
          }
        },
        post: {
          summary: "Verify reasoning challenge",
          operationId: "verifyReasoningChallenge",
          responses: {
            "200": { description: "Verification result" }
          }
        }
      },
      "/api/challenge": {
        get: {
          summary: "Generate a standard challenge",
          operationId: "getChallenge",
          responses: {
            "200": { description: "Challenge generated" }
          }
        },
        post: {
          summary: "Verify a standard challenge",
          operationId: "verifyChallenge",
          responses: {
            "200": { description: "Verification result" }
          }
        }
      },
      "/api/speed-challenge": {
        get: {
          summary: "Generate a speed challenge (RTT-aware timeout)",
          description: "Generate a speed challenge with optional RTT-aware timeout adjustment. Base timeout is 500ms, but can be increased for agents on slow networks.",
          operationId: "getSpeedChallenge",
          parameters: [
            {
              name: "ts",
              in: "query",
              schema: {
                type: "integer",
                format: "int64"
              },
              description: "Client timestamp in milliseconds for RTT compensation"
            }
          ],
          responses: {
            "200": { description: "Speed challenge generated (potentially RTT-adjusted)" }
          }
        },
        post: {
          summary: "Verify a speed challenge",
          operationId: "verifySpeedChallenge",
          responses: {
            "200": { description: "Verification result with timing details" }
          }
        }
      },
      "/api/verify-landing": {
        post: {
          summary: "Verify landing page challenge",
          operationId: "verifyLandingChallenge",
          responses: {
            "200": { description: "Token granted" }
          }
        }
      },
      "/agent-only": {
        get: {
          summary: "Protected endpoint (agents only)",
          operationId: "getAgentOnly",
          responses: {
            "200": { description: "Access granted" },
            "401": { description: "Unauthorized" }
          }
        }
      },
      "/v1/apps": {
        post: {
          summary: "Create a new multi-tenant app (email required)",
          description: "Create a new app with unique app_id and app_secret. Email is required for account recovery. A 6-digit verification code is sent to the provided email.",
          operationId: "createApp",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["email"],
                  properties: {
                    "email": { type: "string", format: "email", description: "Owner email (required for recovery)" }
                  }
                }
              }
            }
          },
          responses: {
            "201": {
              description: "App created successfully",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "app_id": { type: "string", description: "Unique app identifier" },
                      "app_secret": { type: "string", description: "Secret key (only shown once!)" },
                      "email": { type: "string" },
                      "email_verified": { type: "boolean" },
                      "verification_required": { type: "boolean" },
                      "warning": { type: "string" }
                    }
                  }
                }
              }
            },
            "400": { description: "Missing or invalid email" }
          }
        }
      },
      "/v1/apps/{id}": {
        get: {
          summary: "Get app information",
          description: "Retrieve app details by app_id. Includes email and verification status.",
          operationId: "getApp",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
              description: "The app_id to retrieve"
            }
          ],
          responses: {
            "200": {
              description: "App information",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "app_id": { type: "string" },
                      "created_at": { type: "string", format: "date-time" },
                      "email": { type: "string" },
                      "email_verified": { type: "boolean" }
                    }
                  }
                }
              }
            },
            "404": { description: "App not found" }
          }
        }
      },
      "/v1/apps/{id}/verify-email": {
        post: {
          summary: "Verify email with 6-digit code",
          operationId: "verifyEmail",
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } }
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["code"],
                  properties: {
                    "code": { type: "string", description: "6-digit verification code from email" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Email verified" },
            "400": { description: "Invalid or expired code" }
          }
        }
      },
      "/v1/apps/{id}/resend-verification": {
        post: {
          summary: "Resend verification email",
          operationId: "resendVerification",
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } }
          ],
          responses: {
            "200": { description: "Verification email sent" },
            "400": { description: "Already verified" }
          }
        }
      },
      "/v1/apps/{id}/rotate-secret": {
        post: {
          summary: "Rotate app secret (auth required)",
          description: "Generate a new app_secret and invalidate the old one. Requires active dashboard session. Sends notification email.",
          operationId: "rotateSecret",
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } }
          ],
          security: [{ BearerAuth: [] }],
          responses: {
            "200": {
              description: "Secret rotated",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "app_secret": { type: "string", description: "New secret (only shown once!)" }
                    }
                  }
                }
              }
            },
            "401": { description: "Unauthorized" },
            "403": { description: "Token doesn't match app_id" }
          }
        }
      },
      "/v1/auth/recover": {
        post: {
          summary: "Request account recovery via email",
          description: "Sends a device code to the verified email associated with the app. Use the code at /dashboard/code.",
          operationId: "recoverAccount",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["email"],
                  properties: {
                    "email": { type: "string", format: "email" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Recovery code sent (if email exists and is verified)" }
          }
        }
      },
      "/v1/auth/dashboard": {
        post: {
          summary: "Request challenge for dashboard login (agent-first)",
          operationId: "dashboardAuthChallenge",
          responses: {
            "200": { description: "Speed challenge for dashboard auth" }
          }
        }
      },
      "/v1/auth/dashboard/verify": {
        post: {
          summary: "Solve challenge, get dashboard session token",
          operationId: "dashboardAuthVerify",
          responses: {
            "200": { description: "Session token granted" }
          }
        }
      },
      "/v1/auth/device-code": {
        post: {
          summary: "Request challenge for device code flow",
          operationId: "deviceCodeChallenge",
          responses: {
            "200": { description: "Speed challenge for device code" }
          }
        }
      },
      "/v1/auth/device-code/verify": {
        post: {
          summary: "Solve challenge, get device code for human handoff",
          operationId: "deviceCodeVerify",
          responses: {
            "200": { description: "Device code (BOTCHA-XXXX, 10 min TTL)" }
          }
        }
      }
    },
    components: {
      securitySchemes: {
        BotchaLandingToken: {
          type: "apiKey",
          in: "header",
          name: "X-Botcha-Landing-Token"
        },
        BotchaBearerToken: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT"
        }
      }
    }
  };
}
