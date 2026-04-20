/**
 * Error narrowing helpers used across catch blocks.
 *
 * TypeScript's `useUnknownInCatchVariables` correctly types catch variables as
 * `unknown` because the runtime can throw anything (an Error, a string, a
 * rejected promise value, etc.). Use `errorMessage()` to safely extract a
 * human-readable message and `isError()` when you specifically need to access
 * `Error`-only properties (`stack`, `cause`, `name`).
 */

export function isError(err: unknown): err is Error {
  return err instanceof Error;
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  if (err && typeof err === "object" && "message" in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === "string") return m;
  }
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

export function errorStack(err: unknown): string | undefined {
  return err instanceof Error ? err.stack : undefined;
}
