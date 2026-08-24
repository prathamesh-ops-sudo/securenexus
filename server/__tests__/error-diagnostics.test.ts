import { describe, expect, it } from "vitest";
import { getDatabaseErrorDiagnostics } from "../error-diagnostics";

describe("database error diagnostics", () => {
  it("extracts driver fields from a wrapped error without logging enrollment secrets", () => {
    const error = Object.assign(new Error("Failed query with token=snx_secret"), {
      cause: Object.assign(new Error("database rejected write"), {
        code: "23514",
        detail: "Failing row contains (api_key=snx_secret, basis=multiple).",
        constraint: "native_sensors_supersession_match_basis_check",
        column: "supersession_match_basis",
      }),
    });

    expect(getDatabaseErrorDiagnostics(error)).toEqual({
      code: "23514",
      detail: "Failing row contains [REDACTED].",
      constraint: "native_sensors_supersession_match_basis_check",
      column: "supersession_match_basis",
    });
  });

  it("returns an empty diagnostic object for non-database errors", () => {
    expect(getDatabaseErrorDiagnostics(new Error("not a database error"))).toEqual({});
  });
});
