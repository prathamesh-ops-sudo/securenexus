/**
 * Code Signing Configuration
 *
 * For production builds, set these environment variables:
 *
 * Windows (EV Code Signing):
 *   CSC_LINK        — path to .pfx certificate file
 *   CSC_KEY_PASSWORD — certificate password
 *
 * macOS (Apple Developer):
 *   CSC_LINK               — path to .p12 certificate
 *   CSC_KEY_PASSWORD        — certificate password
 *   APPLE_ID               — Apple Developer account email
 *   APPLE_APP_SPECIFIC_PASSWORD — app-specific password for notarization
 *   APPLE_TEAM_ID           — Apple Developer Team ID
 *
 * Linux (GPG):
 *   GPG_KEY_ID — GPG key ID for signing .deb/.rpm packages
 */

exports.default = async function sign(configuration) {
  // In CI/CD, actual signing happens via electron-builder's built-in support
  // This file is a placeholder for custom signing logic if needed
  console.log(`[sign] Signing ${configuration.path || "application"}...`);

  if (!process.env.CSC_LINK) {
    console.log("[sign] No CSC_LINK set — skipping code signing (development build)");
    return;
  }

  // electron-builder handles the actual signing when CSC_LINK is set
  console.log("[sign] Certificate found — electron-builder will handle signing");
};
