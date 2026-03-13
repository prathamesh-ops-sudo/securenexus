/**
 * Microsoft 365 Integration — Graph API mail security
 * Fetches, parses, and ingests emails from Microsoft 365 mailboxes
 */

import { logger } from "../routes/shared";

const log = logger.child("microsoft365");

const GRAPH_API_BASE = "https://graph.microsoft.com/v1.0";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface GraphMailMessage {
  id: string;
  internetMessageId: string;
  subject: string;
  bodyPreview: string;
  from: {
    emailAddress: { name: string; address: string };
  };
  toRecipients: Array<{ emailAddress: { name: string; address: string } }>;
  ccRecipients: Array<{ emailAddress: { name: string; address: string } }>;
  replyTo: Array<{ emailAddress: { name: string; address: string } }>;
  receivedDateTime: string;
  hasAttachments: boolean;
  internetMessageHeaders?: Array<{ name: string; value: string }>;
  conversationId: string;
  conversationIndex: string;
  isRead: boolean;
  isDraft: boolean;
  attachments?: Array<{
    id: string;
    name: string;
    contentType: string;
    size: number;
  }>;
}

export interface ParsedEmailMessage {
  messageId: string;
  internetMessageId: string;
  subject: string;
  senderAddress: string;
  senderDisplayName: string;
  recipientAddresses: string[];
  ccAddresses: string[];
  replyTo: string | null;
  returnPath: string | null;
  receivedAt: Date;
  hasAttachments: boolean;
  attachmentCount: number;
  attachmentNames: string[];
  bodyPreview: string;
  threadId: string;
  inReplyTo: string | null;
  headers: Record<string, string>;
  source: string;
}

export interface GraphApiConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  userPrincipalName?: string;
}

// ─── Token Management ───────────────────────────────────────────────────────

/**
 * Obtain an access token using OAuth2 client credentials flow.
 * In production, you would cache and refresh this token.
 */
export async function getGraphAccessToken(config: GraphApiConfig): Promise<string> {
  const tokenUrl = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`;

  const params = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.clientId,
    client_secret: config.clientSecret,
    scope: "https://graph.microsoft.com/.default",
  });

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    log.error(`Failed to get Graph access token: ${response.status} ${errorText}`);
    throw new Error(`Graph API token request failed: ${response.status}`);
  }

  const data = (await response.json()) as { access_token: string };
  return data.access_token;
}

// ─── Mail Fetching ──────────────────────────────────────────────────────────

/**
 * Fetch recent emails from a Microsoft 365 mailbox via Graph API
 */
export async function fetchMailFromGraph(
  accessToken: string,
  userPrincipalName: string,
  options: {
    top?: number;
    filter?: string;
    select?: string[];
    orderBy?: string;
    sinceDateTime?: string;
  } = {},
): Promise<GraphMailMessage[]> {
  const {
    top = 50,
    select = [
      "id",
      "internetMessageId",
      "subject",
      "bodyPreview",
      "from",
      "toRecipients",
      "ccRecipients",
      "replyTo",
      "receivedDateTime",
      "hasAttachments",
      "internetMessageHeaders",
      "conversationId",
      "conversationIndex",
      "isRead",
      "isDraft",
    ],
    orderBy = "receivedDateTime desc",
    sinceDateTime,
  } = options;

  const params = new URLSearchParams({
    $top: String(top),
    $select: select.join(","),
    $orderby: orderBy,
  });

  if (sinceDateTime) {
    params.set("$filter", `receivedDateTime ge ${sinceDateTime}`);
  }
  if (options.filter) {
    params.set("$filter", options.filter);
  }

  const url = `${GRAPH_API_BASE}/users/${encodeURIComponent(userPrincipalName)}/messages?${params.toString()}`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    log.error(`Graph API mail fetch failed: ${response.status} ${errorText}`);
    throw new Error(`Graph API mail fetch failed: ${response.status}`);
  }

  const data = (await response.json()) as { value: GraphMailMessage[] };
  return data.value || [];
}

/**
 * Fetch attachments for a specific message
 */
export async function fetchMessageAttachments(
  accessToken: string,
  userPrincipalName: string,
  messageId: string,
): Promise<Array<{ id: string; name: string; contentType: string; size: number }>> {
  const url = `${GRAPH_API_BASE}/users/${encodeURIComponent(userPrincipalName)}/messages/${messageId}/attachments?$select=id,name,contentType,size`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    log.error(`Failed to fetch attachments for message ${messageId}: ${response.status}`);
    return [];
  }

  const data = (await response.json()) as {
    value: Array<{ id: string; name: string; contentType: string; size: number }>;
  };
  return data.value || [];
}

// ─── Webhook Setup ──────────────────────────────────────────────────────────

export interface GraphSubscription {
  id: string;
  resource: string;
  changeType: string;
  notificationUrl: string;
  expirationDateTime: string;
}

/**
 * Create a webhook subscription for new mail events
 */
export async function setupGraphWebhook(
  accessToken: string,
  userPrincipalName: string,
  webhookUrl: string,
  expirationMinutes: number = 4230, // Max for mail is ~3 days
): Promise<GraphSubscription> {
  const expirationDateTime = new Date(Date.now() + expirationMinutes * 60000).toISOString();

  const response = await fetch(`${GRAPH_API_BASE}/subscriptions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      changeType: "created",
      notificationUrl: webhookUrl,
      resource: `users/${userPrincipalName}/messages`,
      expirationDateTime,
      clientState: `securenexus-m365-${Date.now()}`,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    log.error(`Failed to create Graph subscription: ${response.status} ${errorText}`);
    throw new Error(`Graph webhook setup failed: ${response.status}`);
  }

  return (await response.json()) as GraphSubscription;
}

/**
 * Renew an existing webhook subscription
 */
export async function renewGraphWebhook(
  accessToken: string,
  subscriptionId: string,
  expirationMinutes: number = 4230,
): Promise<void> {
  const expirationDateTime = new Date(Date.now() + expirationMinutes * 60000).toISOString();

  const response = await fetch(`${GRAPH_API_BASE}/subscriptions/${subscriptionId}`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ expirationDateTime }),
  });

  if (!response.ok) {
    log.error(`Failed to renew subscription ${subscriptionId}: ${response.status}`);
    throw new Error(`Graph webhook renewal failed: ${response.status}`);
  }
}

// ─── Message Parsing ────────────────────────────────────────────────────────

/**
 * Parse a Microsoft Graph mail message into our standard format
 */
export function parseGraphMail(message: GraphMailMessage): ParsedEmailMessage {
  // Extract headers into a flat map
  const headers: Record<string, string> = {};
  if (message.internetMessageHeaders) {
    for (const header of message.internetMessageHeaders) {
      headers[header.name.toLowerCase()] = header.value;
    }
  }

  const attachmentNames = message.attachments?.map((a) => a.name) || [];
  const replyToAddress = message.replyTo?.[0]?.emailAddress?.address || null;

  return {
    messageId: message.id,
    internetMessageId: message.internetMessageId,
    subject: message.subject,
    senderAddress: message.from?.emailAddress?.address || "",
    senderDisplayName: message.from?.emailAddress?.name || "",
    recipientAddresses: message.toRecipients?.map((r) => r.emailAddress.address) || [],
    ccAddresses: message.ccRecipients?.map((r) => r.emailAddress.address) || [],
    replyTo: replyToAddress,
    returnPath: headers["return-path"] || null,
    receivedAt: new Date(message.receivedDateTime),
    hasAttachments: message.hasAttachments,
    attachmentCount: attachmentNames.length,
    attachmentNames,
    bodyPreview: message.bodyPreview,
    threadId: message.conversationId,
    inReplyTo: headers["in-reply-to"] || null,
    headers,
    source: "microsoft365",
  };
}
