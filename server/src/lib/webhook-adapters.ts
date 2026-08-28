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

// R125 F3: escape platform-specific control characters before
// interpolating attacker-controlled strings (event.data field
// values) into a chat-card body. R124 F3 clamped the NUMERIC
// attacker-controlled fields (blockedCount, blockedPayoutUsdMicros)
// before webhook fanout, but string fields like sessionExternalId
// (max 128 chars per schema) and agent (max 80 chars) still flowed
// verbatim into mrkdwn / markdown / MessageCard bodies. On the
// ingest-token-leak threat model R119 F2 / R123 F2 / R124 F3 name,
// an attacker can POST /ingest/events with
//   sessionExternalId: "`<!channel> URGENT PAYOUT $9,999,999`"
// The injected leading backtick closes the outer code span in the
// slack `text: "*${k}:*\n\`${value}\`"` shape, exposing <!channel>
// to Slack mrkdwn's channel-mention parser. On-call channel gets
// a phantom @channel ping. Same shape on Discord (@here / <@user>)
// and Teams (angle-bracket-based mentions).
//
// Distinct from R124 F3 which was about false financial impact;
// this is about the on-call NOTIFICATION VOLUME — a fabricated
// @here ping wakes the whole rotation, unaffected by numeric
// clamps. Escape early so the raw envelope adapter is unaffected
// (raw JSON isn't rendered as markdown).
function escSlackMrkdwn(s: string): string {
  // Backtick closes the code span; angle brackets frame Slack's
  // mention shorthand <!channel>, <!here>, <!everyone>, <@USERID>,
  // <#CHANNEL>. Neutralize both. Also escape bold/italic/strike
  // markers so a leading * / _ / ~ can't produce styled text.
  return s
    .replace(/`/g, "'")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/[*_~]/g, (m) => "\\" + m);
}

function escTeamsMessageCard(s: string): string {
  // Teams MessageCard facts.value pass through the connector's
  // HTML renderer; escape angle brackets to prevent tag injection
  // and the ampersand so &lt; renders literally. Backtick and
  // markdown chars aren't dangerous here (MessageCard doesn't
  // render markdown in facts) but strip them anyway for
  // consistency across adapters.
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escDiscordMarkdown(s: string): string {
  // Discord renders `<@USERID>` `<@&ROLEID>` `<#CHANNELID>` as
  // mentions in embed fields; `@everyone` / `@here` in embed
  // VALUES do NOT ping (per Discord docs) but the mention syntax
  // is still visible. Backticks close the code span the same way
  // Slack's do. Escape.
  return s
    .replace(/`/g, "'")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/@/g, "@\u200b"); // zero-width space defeats @-mention parse
}

export function slackBody(env: Envelope): string {
  const color =
    env.event === "policy.block" ? "#c9302c"
    : env.event.startsWith("webhook.") ? "#2b7be3"
    : "#5a2b8b";
  const fields = Object.entries(env.data).slice(0, 8).map(([k, v]) => ({
    type: "mrkdwn",
    text: `*${escSlackMrkdwn(k)}:*\n\`${escSlackMrkdwn(shortValue(v))}\``,
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
    name: escTeamsMessageCard(k),
    value: escTeamsMessageCard(shortValue(v)),
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
    name: escDiscordMarkdown(k),
    value: "`" + escDiscordMarkdown(shortValue(v)) + "`",
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
