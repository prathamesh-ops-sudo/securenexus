import { describe, expect, it, vi } from "vitest";

const { query } = vi.hoisted(() => ({ query: vi.fn() }));
vi.mock("../db", () => ({ pool: { query } }));

import { getFewShotExamples } from "../ai/active-learning";

describe("AI few-shot tenant isolation", () => {
  it("queries only the requested organization", async () => {
    query.mockImplementation(async (_sql: string, params: string[]) => ({
      rows: [
        {
          id: params[1] === "org-a" ? "a" : "b",
          org_id: params[1],
          domain: "triage",
          input: params[1] === "org-a" ? "A feedback" : "B feedback",
          incorrect_output: "bad",
          correct_output: "good",
          lesson: "lesson",
          active: true,
        },
      ],
    }));

    const first = await getFewShotExamples("triage", "org-a");
    const second = await getFewShotExamples("triage", "org-b");

    expect(first[0]?.input).toBe("A feedback");
    expect(second[0]?.input).toBe("B feedback");
    expect(query.mock.calls[0]?.[0]).toContain("org_id = $2");
    expect(query.mock.calls[0]?.[1]).toEqual(["triage", "org-a", 10]);
  });
});
