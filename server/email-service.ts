import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { logger } from "./logger";
import { config } from "./config";

const log = logger.child("email-service");

const FROM_ADDRESS = "noreply@aricatech.xyz";
const FROM_NAME = "SecureNexus";

let sesClient: SESv2Client | null = null;

function getSesClient(): SESv2Client {
  if (!sesClient) {
    sesClient = new SESv2Client({ region: config.aws?.region || "us-east-1" });
  }
  return sesClient;
}

export function isEmailEnabled(): boolean {
  return config.nodeEnv === "production" || config.nodeEnv === "staging";
}

export async function sendEmail(params: {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
}): Promise<boolean> {
  const recipients = Array.isArray(params.to) ? params.to : [params.to];

  if (!isEmailEnabled()) {
    log.info("Email sending skipped (non-production environment)", {
      to: recipients,
      subject: params.subject,
    });
    return true;
  }

  try {
    const client = getSesClient();
    const command = new SendEmailCommand({
      FromEmailAddress: `${FROM_NAME} <${FROM_ADDRESS}>`,
      Destination: {
        ToAddresses: recipients,
      },
      Content: {
        Simple: {
          Subject: { Data: params.subject, Charset: "UTF-8" },
          Body: {
            Html: { Data: params.html, Charset: "UTF-8" },
            ...(params.text ? { Text: { Data: params.text, Charset: "UTF-8" } } : {}),
          },
        },
      },
    });

    await client.send(command);
    log.info("Email sent successfully", { to: recipients, subject: params.subject });
    return true;
  } catch (err) {
    log.error("Failed to send email", {
      to: recipients,
      subject: params.subject,
      error: String(err),
    });
    return false;
  }
}
