import type { Alert } from "@shared/schema";

export interface PiiMaskResult {
  masked: boolean;
  fieldsRedacted: string[];
}

const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const IP_REGEX = /\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b/g;

function maskIp(ip: string): string {
  const parts = ip.split(".");
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
  }
  return ip;
}

function maskUserId(userId: string): string {
  if (!userId) return userId;
  const last4 = userId.slice(-4);
  return `user_***${last4}`;
}

function maskHostname(hostname: string): string {
  if (!hostname) return hostname;
  const prefix = hostname.slice(0, 3);
  return `${prefix}***`;
}

function maskEmailsInText(text: string): string {
  return text.replace(EMAIL_REGEX, "***@***");
}

function maskIpsInText(text: string): string {
  return text.replace(IP_REGEX, "$1.***");
}

export function maskPiiInAlert(alert: Alert): { maskedAlert: any; result: PiiMaskResult } {
  const maskedAlert = { ...alert };
  const fieldsRedacted: string[] = [];

  if (maskedAlert.sourceIp) {
    maskedAlert.sourceIp = maskIp(maskedAlert.sourceIp);
    fieldsRedacted.push("sourceIp");
  }

  if (maskedAlert.destIp) {
    maskedAlert.destIp = maskIp(maskedAlert.destIp);
    fieldsRedacted.push("destIp");
  }

  if (maskedAlert.userId) {
    (maskedAlert as any).userId = maskUserId(maskedAlert.userId);
    fieldsRedacted.push("userId");
  }

  if (maskedAlert.hostname) {
    maskedAlert.hostname = maskHostname(maskedAlert.hostname);
    fieldsRedacted.push("hostname");
  }

  if (maskedAlert.description) {
    let desc = maskedAlert.description;
    if (EMAIL_REGEX.test(desc)) {
      desc = maskEmailsInText(desc);
      if (!fieldsRedacted.includes("description")) fieldsRedacted.push("description");
    }
    EMAIL_REGEX.lastIndex = 0;
    if (IP_REGEX.test(desc)) {
      desc = maskIpsInText(desc);
      if (!fieldsRedacted.includes("description")) fieldsRedacted.push("description");
    }
    IP_REGEX.lastIndex = 0;
    maskedAlert.description = desc;
  }

  if (maskedAlert.analystNotes) {
    let notes = maskedAlert.analystNotes;
    if (EMAIL_REGEX.test(notes)) {
      notes = maskEmailsInText(notes);
      if (!fieldsRedacted.includes("analystNotes")) fieldsRedacted.push("analystNotes");
    }
    EMAIL_REGEX.lastIndex = 0;
    if (IP_REGEX.test(notes)) {
      notes = maskIpsInText(notes);
      if (!fieldsRedacted.includes("analystNotes")) fieldsRedacted.push("analystNotes");
    }
    IP_REGEX.lastIndex = 0;
    maskedAlert.analystNotes = notes;
  }

  return {
    maskedAlert,
    result: {
      masked: fieldsRedacted.length > 0,
      fieldsRedacted,
    },
  };
}

export function maskPiiInText(text: string): string {
  let result = text;
  result = result.replace(EMAIL_REGEX, "***@***.com");
  result = result.replace(IP_REGEX, "$1.***");
  return result;
}

export function detectPiiFields(data: Record<string, any>): string[] {
  const piiFields: string[] = [];
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  const usernameKeys = ["userId", "user_id", "username", "userName", "assignedTo", "createdBy"];
  const hostnameKeys = ["hostname", "host", "fqdn"];

  for (const [key, value] of Object.entries(data)) {
    if (value === null || value === undefined) continue;
    const strVal = String(value);
    if (usernameKeys.includes(key) && strVal.length > 0) {
      piiFields.push(key);
    } else if (hostnameKeys.includes(key) && strVal.length > 0) {
      piiFields.push(key);
    } else if (emailRegex.test(strVal)) {
      piiFields.push(key);
    } else if (ipRegex.test(strVal)) {
      piiFields.push(key);
    }
  }

  return piiFields;
}
