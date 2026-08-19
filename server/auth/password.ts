import { randomBytes, scrypt, timingSafeEqual } from "crypto";
import { promisify } from "util";

const scryptAsync = promisify(scrypt);

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

export async function comparePasswords(supplied: string, stored: string): Promise<boolean> {
  try {
    const [hashedPassword, salt, ...extraParts] = stored.split(".");
    if (!hashedPassword || !salt || extraParts.length > 0 || !/^[0-9a-f]+$/i.test(hashedPassword)) {
      return false;
    }
    const buf = (await scryptAsync(supplied, salt, 64)) as Buffer;
    const expected = Buffer.from(hashedPassword, "hex");
    if (expected.length !== buf.length) return false;
    return timingSafeEqual(expected, buf);
  } catch {
    return false;
  }
}
