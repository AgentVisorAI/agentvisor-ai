/*
 * Portable mailer. One tiny interface, three drivers:
 *
 *   1. Resend      — if RESEND_API_KEY is set. Free 10k emails/mo,
 *                    the simplest way to get email out today.
 *   2. SMTP        — if SMTP_URL is set. Works with Postmark, SES,
 *                    Mailgun, self-hosted, whatever speaks SMTP. Zero
 *                    vendor lock-in — the same URL syntax works for
 *                    every provider we might need to swap to.
 *   3. dev-stub    — no env, and NODE_ENV !== production. Logs the
 *                    would-be email so local dev works without any
 *                    external service. Refuses to boot in prod so a
 *                    misconfigured deploy fails fast rather than
 *                    silently swallowing password-reset requests.
 *
 * All drivers implement the same async send() so the routes never
 * change. Templates are trivial HTML + plaintext for now — a real
 * email design system can drop in later without touching callers.
 */

import type { FastifyBaseLogger } from "fastify";
import nodemailer, { type Transporter } from "nodemailer";
import { Resend } from "resend";
import { env } from "../env.js";

export interface MailInput {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export interface Mailer {
  send(msg: MailInput): Promise<{ id?: string; driver: string }>;
  driver: "resend" | "smtp" | "dev-stub";
}

class ResendMailer implements Mailer {
  driver = "resend" as const;
  private client: Resend;
  constructor(apiKey: string) {
    this.client = new Resend(apiKey);
  }
  async send(msg: MailInput): Promise<{ id?: string; driver: string }> {
    const res = await this.client.emails.send({
      from: env.EMAIL_FROM,
      to: msg.to,
      subject: msg.subject,
      text: msg.text,
      html: msg.html,
    });
    if (res.error) {
      throw new Error(`resend_send_failed: ${res.error.message}`);
    }
    return { id: res.data?.id, driver: this.driver };
  }
}

class SmtpMailer implements Mailer {
  driver = "smtp" as const;
  private transport: Transporter;
  constructor(smtpUrl: string) {
    this.transport = nodemailer.createTransport(smtpUrl);
  }
  async send(msg: MailInput): Promise<{ id?: string; driver: string }> {
    const info = await this.transport.sendMail({
      from: env.EMAIL_FROM,
      to: msg.to,
      subject: msg.subject,
      text: msg.text,
      html: msg.html,
    });
    return { id: info.messageId, driver: this.driver };
  }
}

class DevStubMailer implements Mailer {
  driver = "dev-stub" as const;
  private log: FastifyBaseLogger;
  constructor(log: FastifyBaseLogger) {
    this.log = log;
  }
  async send(msg: MailInput): Promise<{ id?: string; driver: string }> {
    // Log a nicely-formatted "email" so local dev can copy the reset
    // link out of the terminal without a real mailbox.
    this.log.info(
      { mail: { to: msg.to, subject: msg.subject, text: msg.text } },
      "dev-mail (would send)",
    );
    return { driver: this.driver };
  }
}

let cached: Mailer | null = null;

/**
 * Build (or return the cached) mailer. In production we require a
 * real driver — the app refuses to boot without one so a misconfigured
 * deploy fails fast, not on the first reset-request 3 weeks later.
 */
export function getMailer(log: FastifyBaseLogger): Mailer {
  if (cached) return cached;
  if (env.RESEND_API_KEY) {
    cached = new ResendMailer(env.RESEND_API_KEY);
    return cached;
  }
  if (env.SMTP_URL) {
    cached = new SmtpMailer(env.SMTP_URL);
    return cached;
  }
  if (env.NODE_ENV === "production") {
    // Refuse to boot in production with no mailer — silently
    // swallowing password-reset requests is exactly the wrong failure
    // mode.
    throw new Error(
      "no_mailer_configured: set RESEND_API_KEY or SMTP_URL before running in production",
    );
  }
  cached = new DevStubMailer(log);
  return cached;
}

// Template helpers. Keep the HTML minimal — every mail client renders
// tables differently, and password-reset emails are a security
// sensitive path where a broken template shouldn't leak the token.
export function passwordResetMail(link: string): Pick<MailInput, "subject" | "text" | "html"> {
  const text = `Reset your AgentVisor AI password:

${link}

This link expires in 24 hours. If you didn't request a password reset,
you can ignore this email — nothing has changed on your account.
`;
  const html = `<div style="font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#222;max-width:520px">
  <h2 style="margin:0 0 12px;font-size:20px">Reset your password</h2>
  <p>Click the link below to choose a new password for your AgentVisor AI account.</p>
  <p><a href="${link}" style="display:inline-block;background:#0a5c8b;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:500">Reset password</a></p>
  <p style="font-size:13px;color:#666">Or copy this URL into your browser:<br><code style="word-break:break-all">${link}</code></p>
  <p style="font-size:13px;color:#666">This link expires in 24 hours. If you didn't request a reset, you can ignore this email — nothing has changed.</p>
</div>`;
  return { subject: "Reset your AgentVisor AI password", text, html };
}

export function welcomeMail(displayName: string): Pick<MailInput, "subject" | "text" | "html"> {
  const name = displayName || "there";
  const text = `Hi ${name},

Welcome to AgentVisor AI. Your account is ready.

Next steps:
  1. Install the daemon: https://github.com/AgentVisorAI/agentvisor-ai#quickstart
  2. Point your agent at the daemon and set default_workflow="signed".
  3. Watch your first sealed session appear in the console.

Questions? Reply to this email or hit us at hello@agentvisorai.me.
`;
  const html = `<div style="font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#222;max-width:520px">
  <h2 style="margin:0 0 12px;font-size:20px">Welcome, ${name} 👋</h2>
  <p>Your AgentVisor AI account is ready.</p>
  <ol>
    <li><a href="https://github.com/AgentVisorAI/agentvisor-ai#quickstart">Install the daemon</a></li>
    <li>Point your agent at the daemon and set <code>default_workflow="signed"</code>.</li>
    <li>Watch your first sealed session appear in the console.</li>
  </ol>
  <p style="font-size:13px;color:#666">Questions? Reply to this email or hit us at <a href="mailto:hello@agentvisorai.me">hello@agentvisorai.me</a>.</p>
</div>`;
  return { subject: "Welcome to AgentVisor AI", text, html };
}
