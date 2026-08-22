import { describe, expect, it } from "vitest";
import { generateAdvancedPdf } from "../reporting/pdf-generator";

describe("advanced report PDF generation", () => {
  it("generates a PDF without relying on CommonJS __dirname", async () => {
    const pdf = await generateAdvancedPdf({
      title: "Board Summary",
      subtitle: "Tenant security posture",
      generatedAt: "2026-01-01T00:00:00.000Z",
      reportType: "board_weekly",
      orgId: "org-1",
      sections: [
        {
          title: "Summary",
          type: "text",
          text: "No critical incidents require immediate board attention.",
        },
      ],
    });

    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.length).toBeGreaterThan(100);
  });
});
