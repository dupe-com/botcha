/**
 * BOTCHA Email — Resend Integration
 *
 * Sends transactional emails via Resend API.
 * Falls back to console.log when RESEND_API_KEY is not set (local dev).
 *
 * Uses onboarding@resend.dev (Resend test domain) until botcha.ai
 * is verified as a sending domain.
 */

const RESEND_API = 'https://api.resend.com/emails';
const FROM_ADDRESS = 'BOTCHA <onboarding@resend.dev>';

export interface SendEmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

interface SendResult {
  success: boolean;
  id?: string;
  error?: string;
}

/**
 * Send an email via Resend. Falls back to console logging if no API key.
 */
export async function sendEmail(
  apiKey: string | undefined,
  options: SendEmailOptions
): Promise<SendResult> {
  // Fall back to logging when no API key (local dev)
  if (!apiKey) {
    console.log('[BOTCHA Email] No RESEND_API_KEY — logging instead of sending:');
    console.log(`  To: ${options.to}`);
    console.log(`  Subject: ${options.subject}`);
    console.log(`  Body: ${options.text || options.html.substring(0, 200)}`);
    return { success: true, id: 'dev-logged' };
  }

  try {
    const resp = await fetch(RESEND_API, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: FROM_ADDRESS,
        to: [options.to],
        subject: options.subject,
        html: options.html,
        text: options.text,
      }),
    });

    if (!resp.ok) {
      const text = await resp.text();
      console.error(`[BOTCHA Email] Resend error ${resp.status}:`, text);
      return { success: false, error: `Resend ${resp.status}: ${text.substring(0, 200)}` };
    }

    const data = (await resp.json()) as { id?: string };
    return { success: true, id: data.id };
  } catch (error) {
    console.error('[BOTCHA Email] Send failed:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

// ============ EMAIL TEMPLATES ============

/**
 * Email verification code email.
 */
export function verificationEmail(code: string): SendEmailOptions & { to: '' } {
  return {
    to: '', // caller fills in
    subject: `BOTCHA: Your verification code is ${code}`,
    html: `
<div style="font-family: 'Courier New', monospace; max-width: 480px; margin: 0 auto; padding: 2rem;">
  <h1 style="font-size: 1.5rem; margin-bottom: 1rem;">BOTCHA</h1>
  <p>Your email verification code:</p>
  <div style="background: #f5f5f5; border: 2px solid #333; padding: 1.5rem; text-align: center; font-size: 2rem; font-weight: bold; letter-spacing: 0.3em; margin: 1.5rem 0;">
    ${code}
  </div>
  <p style="color: #666; font-size: 0.875rem;">This code expires in 10 minutes.</p>
  <p style="color: #666; font-size: 0.875rem;">If you didn't request this, ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #ddd; margin: 2rem 0;">
  <p style="color: #999; font-size: 0.75rem;">BOTCHA — Prove you're a bot. Humans need not apply.</p>
</div>`,
    text: `BOTCHA: Your verification code is ${code}\n\nThis code expires in 10 minutes.\nIf you didn't request this, ignore this email.`,
  };
}

/**
 * Account recovery device code email.
 */
export function recoveryEmail(code: string, loginUrl: string): SendEmailOptions & { to: '' } {
  return {
    to: '', // caller fills in
    subject: `BOTCHA: Your recovery code is ${code}`,
    html: `
<div style="font-family: 'Courier New', monospace; max-width: 480px; margin: 0 auto; padding: 2rem;">
  <h1 style="font-size: 1.5rem; margin-bottom: 1rem;">BOTCHA</h1>
  <p>Someone requested access to your BOTCHA dashboard. Enter this code to log in:</p>
  <div style="background: #f5f5f5; border: 2px solid #333; padding: 1.5rem; text-align: center; font-size: 2rem; font-weight: bold; letter-spacing: 0.15em; margin: 1.5rem 0;">
    ${code}
  </div>
  <p>Enter this code at: <a href="${loginUrl}">${loginUrl}</a></p>
  <p style="color: #666; font-size: 0.875rem;">This code expires in 10 minutes.</p>
  <p style="color: #666; font-size: 0.875rem;">If you didn't request this, ignore this email. Your account is still secure.</p>
  <hr style="border: none; border-top: 1px solid #ddd; margin: 2rem 0;">
  <p style="color: #999; font-size: 0.75rem;">BOTCHA — Prove you're a bot. Humans need not apply.</p>
</div>`,
    text: `BOTCHA: Your recovery code is ${code}\n\nEnter this code at: ${loginUrl}\n\nThis code expires in 10 minutes.\nIf you didn't request this, ignore this email.`,
  };
}

/**
 * New secret notification email (sent after secret rotation).
 */
export function secretRotatedEmail(appId: string): SendEmailOptions & { to: '' } {
  return {
    to: '', // caller fills in
    subject: 'BOTCHA: Your app secret was rotated',
    html: `
<div style="font-family: 'Courier New', monospace; max-width: 480px; margin: 0 auto; padding: 2rem;">
  <h1 style="font-size: 1.5rem; margin-bottom: 1rem;">BOTCHA</h1>
  <p>The secret for app <strong>${appId}</strong> was just rotated.</p>
  <p>The old secret is no longer valid. Update your agent configuration with the new secret.</p>
  <p style="color: #666; font-size: 0.875rem;">If you didn't do this, someone with access to your dashboard rotated your secret. Log in and rotate again immediately.</p>
  <hr style="border: none; border-top: 1px solid #ddd; margin: 2rem 0;">
  <p style="color: #999; font-size: 0.75rem;">BOTCHA — Prove you're a bot. Humans need not apply.</p>
</div>`,
    text: `BOTCHA: The secret for app ${appId} was just rotated.\n\nThe old secret is no longer valid. Update your agent configuration with the new secret.\n\nIf you didn't do this, log in and rotate again immediately.`,
  };
}
