const BRAND_COLOR = "#0891b2";
const BG_COLOR = "#0a0a0f";
const CARD_BG = "#111118";
const TEXT_COLOR = "#e4e4e7";
const MUTED_COLOR = "#a1a1aa";
const BORDER_COLOR = "#27272a";

function baseLayout(content: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureNexus</title>
</head>
<body style="margin:0;padding:0;background-color:${BG_COLOR};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:${BG_COLOR};padding:40px 20px;">
    <tr>
      <td align="center">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">
          <tr>
            <td style="padding-bottom:24px;">
              <span style="font-size:20px;font-weight:700;color:${BRAND_COLOR};letter-spacing:-0.5px;">SecureNexus</span>
            </td>
          </tr>
          <tr>
            <td style="background-color:${CARD_BG};border:1px solid ${BORDER_COLOR};border-radius:12px;padding:32px;">
              ${content}
            </td>
          </tr>
          <tr>
            <td style="padding-top:24px;text-align:center;">
              <p style="margin:0;font-size:12px;color:${MUTED_COLOR};">
                SecureNexus by Arica Technologies &mdash; Enterprise Security Operations Platform
              </p>
              <p style="margin:4px 0 0;font-size:12px;color:${MUTED_COLOR};">
                This is an automated message. Please do not reply directly.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function button(text: string, url: string): string {
  return `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:24px 0;">
    <tr>
      <td style="background-color:${BRAND_COLOR};border-radius:8px;">
        <a href="${url}" target="_blank" style="display:inline-block;padding:12px 28px;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;border-radius:8px;">${text}</a>
      </td>
    </tr>
  </table>`;
}

export function invitationEmail(params: {
  recipientName?: string;
  orgName: string;
  inviterName: string;
  role: string;
  acceptUrl: string;
  expiresAt: Date;
}): { subject: string; html: string; text: string } {
  const greeting = params.recipientName ? `Hi ${params.recipientName},` : "Hi,";
  const expiryStr = params.expiresAt.toLocaleDateString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  });

  const html = baseLayout(`
    <h1 style="margin:0 0 16px;font-size:22px;color:${TEXT_COLOR};">You've been invited</h1>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      ${greeting}
    </p>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      <strong>${params.inviterName}</strong> has invited you to join <strong>${params.orgName}</strong> as a
      <strong>${params.role}</strong> on SecureNexus.
    </p>
    ${button("Accept Invitation", params.acceptUrl)}
    <p style="margin:0;font-size:13px;color:${MUTED_COLOR};">
      This invitation expires on ${expiryStr}. If you didn't expect this, you can safely ignore it.
    </p>
  `);

  const text = `${greeting}\n\n${params.inviterName} has invited you to join ${params.orgName} as a ${params.role} on SecureNexus.\n\nAccept: ${params.acceptUrl}\n\nExpires: ${expiryStr}`;

  return { subject: `You're invited to ${params.orgName} on SecureNexus`, html, text };
}

export function welcomeEmail(params: { firstName?: string; email: string; loginUrl: string }): {
  subject: string;
  html: string;
  text: string;
} {
  const greeting = params.firstName ? `Welcome, ${params.firstName}!` : "Welcome!";

  const html = baseLayout(`
    <h1 style="margin:0 0 16px;font-size:22px;color:${TEXT_COLOR};">${greeting}</h1>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      Your SecureNexus account is ready. You can now sign in and start monitoring your security operations.
    </p>
    ${button("Sign In to SecureNexus", params.loginUrl)}
    <p style="margin:0;font-size:13px;color:${MUTED_COLOR};">
      Account: ${params.email}
    </p>
  `);

  const text = `${greeting}\n\nYour SecureNexus account is ready.\n\nSign in: ${params.loginUrl}\nAccount: ${params.email}`;

  return { subject: "Welcome to SecureNexus", html, text };
}

export function passwordResetEmail(params: { firstName?: string; resetUrl: string; expiresInMinutes: number }): {
  subject: string;
  html: string;
  text: string;
} {
  const greeting = params.firstName ? `Hi ${params.firstName},` : "Hi,";

  const html = baseLayout(`
    <h1 style="margin:0 0 16px;font-size:22px;color:${TEXT_COLOR};">Reset your password</h1>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      ${greeting}
    </p>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      We received a request to reset the password for your SecureNexus account. Click the button below to create a new password.
    </p>
    ${button("Reset Password", params.resetUrl)}
    <p style="margin:0 0 8px;font-size:13px;color:${MUTED_COLOR};">
      This link expires in ${params.expiresInMinutes} minutes. If you didn't request a password reset, you can safely ignore this email.
    </p>
    <p style="margin:0;font-size:13px;color:${MUTED_COLOR};">
      For security, do not share this link with anyone.
    </p>
  `);

  const text = `${greeting}\n\nWe received a request to reset your SecureNexus password.\n\nReset: ${params.resetUrl}\n\nThis link expires in ${params.expiresInMinutes} minutes. If you didn't request this, ignore this email.`;

  return { subject: "Reset your SecureNexus password", html, text };
}

export function paymentFailedEmail(params: {
  orgName: string;
  amountDue: string;
  retryDate?: string;
  billingUrl: string;
}): { subject: string; html: string; text: string } {
  const html = baseLayout(`
    <h1 style="margin:0 0 16px;font-size:22px;color:#ef4444;">Payment Failed</h1>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      We were unable to process the payment of <strong>${params.amountDue}</strong> for <strong>${params.orgName}</strong>.
    </p>
    ${params.retryDate ? `<p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">We will automatically retry on <strong>${params.retryDate}</strong>.</p>` : ""}
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      Please update your payment method to avoid service interruption.
    </p>
    ${button("Update Payment Method", params.billingUrl)}
  `);

  const text = `Payment of ${params.amountDue} for ${params.orgName} failed.\n\n${params.retryDate ? `Retry date: ${params.retryDate}\n\n` : ""}Update payment: ${params.billingUrl}`;

  return { subject: `Payment failed for ${params.orgName}`, html, text };
}

export function trialEndingEmail(params: { orgName: string; trialEndDate: string; billingUrl: string }): {
  subject: string;
  html: string;
  text: string;
} {
  const html = baseLayout(`
    <h1 style="margin:0 0 16px;font-size:22px;color:${TEXT_COLOR};">Your trial is ending soon</h1>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      The trial for <strong>${params.orgName}</strong> ends on <strong>${params.trialEndDate}</strong>.
    </p>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      To continue using SecureNexus without interruption, choose a plan before your trial expires.
    </p>
    ${button("Choose a Plan", params.billingUrl)}
  `);

  const text = `Your trial for ${params.orgName} ends on ${params.trialEndDate}.\n\nChoose a plan: ${params.billingUrl}`;

  return { subject: `Your ${params.orgName} trial ends on ${params.trialEndDate}`, html, text };
}

export function subscriptionCancelledEmail(params: { orgName: string; accessEndDate: string; reactivateUrl: string }): {
  subject: string;
  html: string;
  text: string;
} {
  const html = baseLayout(`
    <h1 style="margin:0 0 16px;font-size:22px;color:${TEXT_COLOR};">Subscription cancelled</h1>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      The subscription for <strong>${params.orgName}</strong> has been cancelled. You will retain access to all features until <strong>${params.accessEndDate}</strong>.
    </p>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      After that date, your organization will be downgraded to the Free plan with reduced limits.
    </p>
    ${button("Reactivate Subscription", params.reactivateUrl)}
  `);

  const text = `Subscription for ${params.orgName} has been cancelled.\n\nAccess until: ${params.accessEndDate}\n\nReactivate: ${params.reactivateUrl}`;

  return { subject: `${params.orgName} subscription cancelled`, html, text };
}

export function memberSuspendedEmail(params: { memberName?: string; orgName: string; reason?: string }): {
  subject: string;
  html: string;
  text: string;
} {
  const greeting = params.memberName ? `Hi ${params.memberName},` : "Hi,";

  const html = baseLayout(`
    <h1 style="margin:0 0 16px;font-size:22px;color:#ef4444;">Account Suspended</h1>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      ${greeting}
    </p>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      Your access to <strong>${params.orgName}</strong> on SecureNexus has been suspended${params.reason ? `: ${params.reason}` : "."}.
    </p>
    <p style="margin:0;font-size:13px;color:${MUTED_COLOR};">
      Contact your organization administrator for more information.
    </p>
  `);

  const text = `${greeting}\n\nYour access to ${params.orgName} has been suspended${params.reason ? `: ${params.reason}` : "."}\n\nContact your organization administrator for more information.`;

  return { subject: `Your access to ${params.orgName} has been suspended`, html, text };
}

export function memberRoleChangedEmail(params: {
  memberName?: string;
  orgName: string;
  oldRole: string;
  newRole: string;
}): { subject: string; html: string; text: string } {
  const greeting = params.memberName ? `Hi ${params.memberName},` : "Hi,";

  const html = baseLayout(`
    <h1 style="margin:0 0 16px;font-size:22px;color:${TEXT_COLOR};">Role Updated</h1>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      ${greeting}
    </p>
    <p style="margin:0 0 16px;font-size:15px;color:${TEXT_COLOR};line-height:1.6;">
      Your role in <strong>${params.orgName}</strong> has been changed from <strong>${params.oldRole}</strong> to <strong>${params.newRole}</strong>.
    </p>
    <p style="margin:0;font-size:13px;color:${MUTED_COLOR};">
      Your permissions have been updated accordingly.
    </p>
  `);

  const text = `${greeting}\n\nYour role in ${params.orgName} has been changed from ${params.oldRole} to ${params.newRole}.`;

  return { subject: `Your role in ${params.orgName} has been updated`, html, text };
}
