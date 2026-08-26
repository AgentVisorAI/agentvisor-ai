/**
 * Webhook payload adapters.
 *
 * For popular chat targets (Slack, Microsoft Teams, Discord), we
 * auto-detect the URL and reformat the JSON payload into the format
 * that platform expects, so the customer's #ops channel shows a
 * pretty card instead of a raw JSON dump. For any other URL we ship
 * the neutral AgentVisor envelope.
 *
 * The signature is still computed over the OUTBOUND body — whichever
 * format we send is what we sign — so the anti-tamper guarantee is
 * preserved regardless of adapter.
 *
 * All adapters get a normalized event envelope with { event, data,
 * createdAt } and produce a Buffer / string. Keep them pure so unit
 * tests are trivial.
 */
export type Adapter = "slack" | "teams" | "discord" | "raw";

export function pickAdapter(url: string): Adapter {
  let host = "";
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return "raw";
  }
  if (host === "hooks.slack.com") return "slack";
  if (host.endsWith(".webhook.office.com") || host === "webhook.office.com") return "teams";
  if (host === "discord.com" && /\/api\/webhooks\//.test(url)) return "discord";
  if (host === "discordapp.com") return "discord";
  return "raw";
}

interface Envelope {
  event: string;
  createdAt: string;
  data: Record<string, unknown>;
}

/** Prettify an event name like 'policy.block' -> 'Policy · Block'. */
function label(event: string): string {
  return event
    .split(".")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(" · ");
}

/** Truncate deep field values so a huge blob doesn't blow up the card. */
function shortValue(v: unknown): string {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > 240 ? s.slice(0, 240) + "…" : s;
}

export function slackBody(env: Envelope): string {
  const color =
    env.event === "policy.block" ? "#c9302c"
    : env.event.startsWith("webhook.") ? "#2b7be3"
    : "#5a2b8b";
  const fields = Object.entries(env.data).slice(0, 8).map(([k, v]) => ({
    type: "mrkdwn",
    text: `*${k}:*\n\`${shortValue(v)}\``,
  }));
  const payload = {
    text: `AgentVisor: ${label(env.event)}`,
    attachments: [
      {
        color,
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: `AgentVisor · ${label(env.event)}` },
          },
          ...(fields.length
            ? [{ type: "section", fields }]
            : [
                {
                  type: "section",
                  text: { type: "mrkdwn", text: "_(no fields)_" },
                },
              ]),
          {
            type: "context",
            elements: [
              { type: "mrkdwn", text: `at \`${env.createdAt}\`` },
            ],
          },
        ],
      },
    ],
  };
  return JSON.stringify(payload);
}

export function teamsBody(env: Envelope): string {
  const facts = Object.entries(env.data).slice(0, 12).map(([k, v]) => ({
    name: k,
    value: shortValue(v),
  }));
  const themeColor =
    env.event === "policy.block" ? "c9302c" : "2b7be3";
  // Legacy Office 365 connector format works with modern Teams
  // incoming webhooks. Simpler than AdaptiveCard for our needs.
  const payload = {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    themeColor,
    summary: `AgentVisor: ${label(env.event)}`,
    title: `AgentVisor · ${label(env.event)}`,
    sections: [
      {
        activityTitle: label(env.event),
        activitySubtitle: env.createdAt,
        facts: facts.length ? facts : [{ name: "info", value: "(no fields)" }],
      },
    ],
  };
  return JSON.stringify(payload);
}

export function discordBody(env: Envelope): string {
  const color =
    env.event === "policy.block" ? 0xc9302c : 0x2b7be3;
  const fields = Object.entries(env.data).slice(0, 24).map(([k, v]) => ({
    name: k,
    value: "`" + shortValue(v) + "`",
    inline: false,
  }));
  const payload = {
    embeds: [
      {
        title: `AgentVisor · ${label(env.event)}`,
        color,
        timestamp: env.createdAt,
        fields: fields.length ? fields : [{ name: "info", value: "(no fields)" }],
        footer: { text: env.event },
      },
    ],
  };
  return JSON.stringify(payload);
}

export function formatForAdapter(
  adapter: Adapter,
  env: Envelope,
): string {
  switch (adapter) {
    case "slack":   return slackBody(env);
    case "teams":   return teamsBody(env);
    case "discord": return discordBody(env);
    default:        return JSON.stringify(env);
  }
}
