/**
 * Google Workspace Integration — Gmail API mail security
 * Fetches, parses, and ingests emails from Gmail mailboxes
 */

import { logger } from "../routes/shared";

const log = logger.child("google-workspace");

const GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface GmailMessage {
  id: string;
  threadId: string;
  labelIds: string[];
  snippet: string;
  historyId: string;
  internalDate: string;
  payload: {
    mimeType: string;
    headers: Array<{ name: string; value: string }>;
    body?: { size: number; data?: string };
    parts?: Array<{
      mimeType: string;
      filename: string;
      body: { size: number; attachmentId?: string };
      headers?: Array<{ name: string; value: string }>;
    }>;
  };
  sizeEstimate: number;
}

export interface GmailMessageListItem {
  id: string;
  threadId: string;
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

export interface GmailApiConfig {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  delegatedUser?: string;
}

// ─── Token Management ───────────────────────────────────────────────────────

/**
 * Obtain an access token using OAuth2 refresh token grant
 */
export async function getGmailAccessToken(config: GmailApiConfig): Promise<string> {
  const tokenUrl = "https://oauth2.googleapis.com/token";

  const params = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: config.clientId,
    client_secret: config.clientSecret,
    refresh_token: config.refreshToken,
  });

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    log.error(`Failed to get Gmail access token: ${response.status} ${errorText}`);
    throw new Error(`Gmail token request failed: ${response.status}`);
  }

  const data = (await response.json()) as { access_token: string };
  return data.access_token;
}

// ─── Mail Fetching ──────────────────────────────────────────────────────────

/**
 * List message IDs from a Gmail mailbox
 */
export async function listGmailMessages(
  accessToken: string,
  userId: string = "me",
  options: {
    maxResults?: number;
    query?: string;
    labelIds?: string[];
    pageToken?: string;
  } = {},
): Promise<{ messages: GmailMessageListItem[]; nextPageToken?: string }> {
  const { maxResults = 50, query, labelIds, pageToken } = options;

  const params = new URLSearchParams({ maxResults: String(maxResults) });
  if (query) params.set("q", query);
  if (labelIds) params.set("labelIds", labelIds.join(","));
  if (pageToken) params.set("pageToken", pageToken);

  const url = `${GMAIL_API_BASE}/users/${encodeURIComponent(userId)}/messages?${params.toString()}`;

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    const errorText = await response.text();
    log.error(`Gmail list messages failed: ${response.status} ${errorText}`);
    throw new Error(`Gmail list messages failed: ${response.status}`);
  }

  const data = (await response.json()) as {
    messages?: GmailMessageListItem[];
    nextPageToken?: string;
  };

  return {
    messages: data.messages || [],
    nextPageToken: data.nextPageToken,
  };
}

/**
 * Fetch a single Gmail message by ID with full payload
 */
export async function fetchGmailMessage(
  accessToken: string,
  messageId: string,
  userId: string = "me",
): Promise<GmailMessage> {
  const url = `${GMAIL_API_BASE}/users/${encodeURIComponent(userId)}/messages/${messageId}?format=full`;

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    const errorText = await response.text();
    log.error(`Gmail fetch message failed for ${messageId}: ${response.status} ${errorText}`);
    throw new Error(`Gmail fetch message failed: ${response.status}`);
  }

  return (await response.json()) as GmailMessage;
}

/**
 * Batch-fetch multiple Gmail messages
 */
export async function fetchMailFromGmail(
  accessToken: string,
  userId: string = "me",
  options: {
    maxResults?: number;
    query?: string;
    sinceDate?: string;
  } = {},
): Promise<GmailMessage[]> {
  const { maxResults = 50, query, sinceDate } = options;

  let q = query || "";
  if (sinceDate) {
    q = q ? `${q} after:${sinceDate}` : `after:${sinceDate}`;
  }

  const listResult = await listGmailMessages(accessToken, userId, {
    maxResults,
    query: q || undefined,
  });

  const messages: GmailMessage[] = [];
  for (const item of listResult.messages) {
    try {
      const fullMessage = await fetchGmailMessage(accessToken, item.id, userId);
      messages.push(fullMessage);
    } catch (err) {
      log.error(`Failed to fetch Gmail message ${item.id}: ${err}`);
    }
  }

  return messages;
}

// ─── Webhook / Push Notification Setup ──────────────────────────────────────

export interface GmailWatchResponse {
  historyId: string;
  expiration: string;
}

/**
 * Set up Gmail push notifications via Cloud Pub/Sub
 */
export async function setupGmailWebhook(
  accessToken: string,
  userId: string = "me",
  topicName: string,
  labelIds: string[] = ["INBOX"],
): Promise<GmailWatchResponse> {
  const url = `${GMAIL_API_BASE}/users/${encodeURIComponent(userId)}/watch`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      topicName,
      labelIds,
      labelFilterBehavior: "INCLUDE",
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    log.error(`Gmail watch setup failed: ${response.status} ${errorText}`);
    throw new Error(`Gmail watch setup failed: ${response.status}`);
  }

  return (await response.json()) as GmailWatchResponse;
}

/**
 * Stop Gmail push notifications
 */
export async function stopGmailWebhook(accessToken: string, userId: string = "me"): Promise<void> {
  const url = `${GMAIL_API_BASE}/users/${encodeURIComponent(userId)}/stop`;

  const response = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    log.error(`Gmail stop watch failed: ${response.status}`);
    throw new Error(`Gmail stop watch failed: ${response.status}`);
  }
}

// ─── Message Parsing ────────────────────────────────────────────────────────

/**
 * Extract a header value from Gmail message payload headers
 */
function getHeader(headers: Array<{ name: string; value: string }>, name: string): string {
  const found = headers.find((h) => h.name.toLowerCase() === name.toLowerCase());
  return found?.value || "";
}

/**
 * Parse a sender header like "John Doe <john@example.com>"
 */
function parseSender(fromHeader: string): { displayName: string; address: string } {
  const match = fromHeader.match(/^"?([^"<]*)"?\s*<?([^>]+)>?$/);
  if (match) {
    return {
      displayName: match[1].trim(),
      address: match[2].trim(),
    };
  }
  return { displayName: "", address: fromHeader.trim() };
}

/**
 * Parse a comma-separated list of recipients
 */
function parseRecipients(headerValue: string): string[] {
  if (!headerValue) return [];
  return headerValue.split(",").map((r) => {
    const match = r.match(/<([^>]+)>/);
    return match ? match[1].trim() : r.trim();
  });
}

/**
 * Parse a Gmail API message into our standard format
 */
export function parseGmailMail(message: GmailMessage): ParsedEmailMessage {
  const payloadHeaders = message.payload.headers || [];

  // Build headers map
  const headers: Record<string, string> = {};
  for (const h of payloadHeaders) {
    headers[h.name.toLowerCase()] = h.value;
  }

  const from = getHeader(payloadHeaders, "From");
  const sender = parseSender(from);
  const to = getHeader(payloadHeaders, "To");
  const cc = getHeader(payloadHeaders, "Cc");
  const replyTo = getHeader(payloadHeaders, "Reply-To") || null;
  const returnPath = getHeader(payloadHeaders, "Return-Path") || null;
  const subject = getHeader(payloadHeaders, "Subject");
  const inReplyTo = getHeader(payloadHeaders, "In-Reply-To") || null;
  const messageId = getHeader(payloadHeaders, "Message-ID");

  // Extract attachment info from parts
  const attachmentNames: string[] = [];
  if (message.payload.parts) {
    for (const part of message.payload.parts) {
      if (part.filename && part.body?.attachmentId) {
        attachmentNames.push(part.filename);
      }
    }
  }

  return {
    messageId: message.id,
    internetMessageId: messageId,
    subject,
    senderAddress: sender.address,
    senderDisplayName: sender.displayName,
    recipientAddresses: parseRecipients(to),
    ccAddresses: parseRecipients(cc),
    replyTo,
    returnPath,
    receivedAt: new Date(parseInt(message.internalDate, 10)),
    hasAttachments: attachmentNames.length > 0,
    attachmentCount: attachmentNames.length,
    attachmentNames,
    bodyPreview: message.snippet || "",
    threadId: message.threadId,
    inReplyTo,
    headers,
    source: "google_workspace",
  };
}
