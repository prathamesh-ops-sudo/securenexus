import { createHash, createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { config } from "./config";

const ALGO = "aes-256-gcm" as const;
const IV_LEN = 12;
const TAG_LEN = 16;

function deriveKey(): Buffer {
  return createHash("sha256").update(config.session.secret).digest();
}

export function encryptSsoSecret(plaintext: string): string {
  const key = deriveKey();
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

export function decryptSsoSecret(ciphertext: string): string {
  const key = deriveKey();
  const buf = Buffer.from(ciphertext, "base64");
  if (buf.length < IV_LEN + TAG_LEN + 1) {
    throw new Error("Invalid SSO ciphertext: too short");
  }
  const iv = buf.subarray(0, IV_LEN);
  const tag = buf.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const encrypted = buf.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(encrypted).toString("utf8") + decipher.final("utf8");
}
