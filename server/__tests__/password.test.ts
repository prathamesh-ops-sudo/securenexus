import { describe, expect, it } from "vitest";
import { comparePasswords, hashPassword } from "../auth/password";

describe("password hashing", () => {
  it("uses timing-safe comparison for valid hashes", async () => {
    const stored = await hashPassword("correct horse battery staple");

    await expect(comparePasswords("correct horse battery staple", stored)).resolves.toBe(true);
    await expect(comparePasswords("wrong password", stored)).resolves.toBe(false);
  });

  it("returns false for malformed stored hashes without throwing", async () => {
    for (const stored of ["", "missing-salt", ".salt", "abcd.", "not-hex.salt", "abcd.salt.extra"]) {
      await expect(comparePasswords("password", stored)).resolves.toBe(false);
    }
  });
});
