import { describe, expect, it, vi } from "vitest";
import { ConnectorHttpError, httpRequest } from "../connectors/connector-plugin";
import { elasticPlugin } from "../connectors/elastic";

describe("connector HTTP boundary", () => {
  it("raises a structured error for non-success responses instead of returning an empty result", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response("credentials expired", {
        status: 401,
        headers: { "retry-after": "30" },
      });
    });

    const rejection = httpRequest("https://vendor.example/alerts", {});
    await expect(rejection).rejects.toMatchObject({
      name: "ConnectorHttpError",
      status: 401,
      responseBody: "credentials expired",
      retryAfter: "30",
    });
    await expect(rejection).rejects.toBeInstanceOf(ConnectorHttpError);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    fetchMock.mockRestore();
  });

  it("makes plugin fetches reject on authentication failures", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response("expired credentials", {
        status: 401,
      });
    });

    await expect(
      elasticPlugin.fetch({
        baseUrl: "https://vendor.example",
        apiKey: "expired",
      }),
    ).rejects.toMatchObject({ name: "ConnectorHttpError", status: 401 });
    expect(await elasticPlugin.test({ baseUrl: "https://vendor.example", apiKey: "expired" })).toMatchObject({
      success: false,
      message: "Authentication failed — verify vendor credentials.",
    });

    fetchMock.mockRestore();
  });

  it("returns parsed data for successful responses", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    await expect(httpRequest("https://vendor.example/alerts", {})).resolves.toEqual({
      status: 200,
      data: { alerts: [] },
    });

    fetchMock.mockRestore();
  });
});
