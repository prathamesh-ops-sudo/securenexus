import { describe, expect, it } from "vitest";
import { ApiShapeError, isArrayOf, isRecord, parseApiData } from "./queryClient";

describe("parseApiData", () => {
  it("unwraps and validates canonical API envelopes", () => {
    const result = parseApiData(
      { data: { count: 3 }, meta: { requestId: "request-1" }, errors: null },
      (value): value is { count: number } => isRecord(value) && typeof value.count === "number",
      "/api/example",
    );

    expect(result).toEqual({ count: 3 });
  });

  it("rejects a payload that does not satisfy the endpoint shape", () => {
    expect(() =>
      parseApiData(
        { data: { items: "not-an-array" }, meta: {}, errors: null },
        (value): value is { items: unknown[] } => isRecord(value) && isArrayOf(value.items),
        "/api/example",
      ),
    ).toThrow(ApiShapeError);
  });

  it("does not turn malformed payloads into empty values", () => {
    expect(() =>
      parseApiData(
        { data: { items: null }, meta: {}, errors: null },
        (value): value is { items: unknown[] } => isRecord(value) && isArrayOf(value.items),
        "/api/example",
      ),
    ).toThrow("/api/example: returned an unexpected response shape");
  });

  it("does not unwrap non-canonical legacy envelopes", () => {
    expect(() =>
      parseApiData(
        { ok: true, data: { count: 3 } },
        (value): value is { count: number } => isRecord(value) && typeof value.count === "number",
        "/api/example",
      ),
    ).toThrow(ApiShapeError);
  });
});
