/**
 * Slack / Teams Channel Integration for War Rooms
 *
 * Auto-creates incident channels (e.g. #incident-2024-001) when a war room is opened,
 * and posts timeline updates to the channel in real-time.
 *
 * Reads Slack/Teams credentials from the integration_configs table per-org.
 * If no config exists the functions are no-ops — war rooms work fine without Slack.
 */

import { storage } from "../storage";

// ── Types ──────────────────────────────────────────────────────────────────────

interface SlackConfig {
  botToken: string;
  defaultChannelPrefix?: string; // defaults to "incident"
  workspaceId?: string;
}

interface SlackChannelResult {
  channelId: string;
  channelName: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Look up an org's Slack integration config from the DB.
 * Returns null if Slack is not configured for this org.
 */
async function getSlackConfig(orgId: string): Promise<SlackConfig | null> {
  try {
    const configs = await storage.getIntegrationConfigs(orgId);
    const slackCfg = configs.find((c) => c.type === "slack" && c.status === "active");
    if (!slackCfg) return null;

    const cfg = slackCfg.config as Record<string, unknown> | null;
    const botToken = (cfg?.botToken as string) || (cfg?.bot_token as string) || "";
    if (!botToken) return null;

    return {
      botToken,
      defaultChannelPrefix: (cfg?.channelPrefix as string) || "incident",
      workspaceId: (cfg?.workspaceId as string) || undefined,
    };
  } catch {
    return null;
  }
}

/**
 * Sanitize a string into a valid Slack channel name.
 * Slack channel names must be lowercase, max 80 chars, no spaces/special chars.
 */
function toChannelName(prefix: string, name: string, incidentId: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40);

  const incidentSlug = incidentId
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 20);

  return `${prefix}-${incidentSlug}-${slug}`.slice(0, 80);
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Try to create a Slack channel for the war room.
 * Non-blocking — failures are logged but never throw to the caller.
 * Updates the war room record with slackChannelId/slackChannelName on success.
 */
export async function tryCreateSlackChannel(
  orgId: string,
  warRoomId: string,
  warRoomName: string,
  incidentId: string,
): Promise<SlackChannelResult | null> {
  const cfg = await getSlackConfig(orgId);
  if (!cfg) return null; // Slack not configured — silently skip

  const channelName = toChannelName(cfg.defaultChannelPrefix || "incident", warRoomName, incidentId);

  try {
    // Create the channel via Slack Web API
    const createRes = await fetch("https://slack.com/api/conversations.create", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${cfg.botToken}`,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({
        name: channelName,
        is_private: false,
      }),
    });

    const createData = (await createRes.json()) as {
      ok: boolean;
      channel?: { id: string; name: string };
      error?: string;
    };

    if (!createData.ok) {
      // Channel might already exist — try to find it
      if (createData.error === "name_taken") {
        const existing = await findSlackChannel(cfg.botToken, channelName);
        if (existing) {
          await storage.updateWarRoom(warRoomId, {
            slackChannelId: existing.channelId,
            slackChannelName: existing.channelName,
          });
          return existing;
        }
      }
      console.warn(`[slack] Failed to create channel: ${createData.error}`);
      return null;
    }

    const result: SlackChannelResult = {
      channelId: createData.channel!.id,
      channelName: createData.channel!.name,
    };

    // Set channel topic
    await fetch("https://slack.com/api/conversations.setTopic", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${cfg.botToken}`,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({
        channel: result.channelId,
        topic: `War Room: ${warRoomName} | Incident: ${incidentId}`,
      }),
    });

    // Post initial message
    await postSlackMessage(
      cfg.botToken,
      result.channelId,
      `:rotating_light: *War Room Activated*\n*Name:* ${warRoomName}\n*Incident:* ${incidentId}\n\nAll timeline updates will be posted here automatically.`,
    );

    // Persist channel info to the war room record
    await storage.updateWarRoom(warRoomId, {
      slackChannelId: result.channelId,
      slackChannelName: result.channelName,
    });

    return result;
  } catch (err) {
    console.warn("[slack] Channel creation error:", err);
    return null;
  }
}

/**
 * Post a message to a Slack channel.
 * Called from war room routes when timeline entries are added.
 */
export async function tryPostSlackMessage(orgId: string, channelId: string, text: string): Promise<boolean> {
  const cfg = await getSlackConfig(orgId);
  if (!cfg) return false;

  try {
    return await postSlackMessage(cfg.botToken, channelId, text);
  } catch {
    return false;
  }
}

// ── Internal helpers ───────────────────────────────────────────────────────────

async function postSlackMessage(botToken: string, channelId: string, text: string): Promise<boolean> {
  const res = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${botToken}`,
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({ channel: channelId, text }),
  });

  const data = (await res.json()) as { ok: boolean; error?: string };
  if (!data.ok) {
    console.warn(`[slack] Failed to post message: ${data.error}`);
    return false;
  }
  return true;
}

async function findSlackChannel(botToken: string, channelName: string): Promise<SlackChannelResult | null> {
  try {
    const res = await fetch(`https://slack.com/api/conversations.list?types=public_channel&limit=200`, {
      headers: { Authorization: `Bearer ${botToken}` },
    });

    const data = (await res.json()) as {
      ok: boolean;
      channels?: Array<{ id: string; name: string }>;
    };
    if (!data.ok || !data.channels) return null;

    const match = data.channels.find((c) => c.name === channelName);
    return match ? { channelId: match.id, channelName: match.name } : null;
  } catch {
    return null;
  }
}
