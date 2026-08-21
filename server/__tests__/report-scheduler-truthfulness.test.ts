import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getReportTemplate: vi.fn(),
  createReportRun: vi.fn(),
  updateReportRun: vi.fn(),
  updateReportSchedule: vi.fn(),
  generateReportData: vi.fn(),
  uploadFile: vi.fn(),
  isEmailEnabled: vi.fn(),
  sendEmail: vi.fn(),
}));

vi.mock("../storage", () => ({
  storage: {
    getReportTemplate: mocks.getReportTemplate,
    createReportRun: mocks.createReportRun,
    updateReportRun: mocks.updateReportRun,
    updateReportSchedule: mocks.updateReportSchedule,
  },
}));
vi.mock("../report-engine", () => ({
  generateReportData: mocks.generateReportData,
  formatAsCSV: (data: unknown) => JSON.stringify(data),
}));
vi.mock("../report-pdf", () => ({
  generatePdfReport: vi.fn(),
  CONFIDENTIAL_REPORT_TYPES: [],
}));
vi.mock("../s3", () => ({ uploadFile: mocks.uploadFile }));
vi.mock("../logger", () => ({
  logger: { child: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() }) },
}));
vi.mock("../email-service", () => ({
  sendEmail: mocks.sendEmail,
  isEmailEnabled: mocks.isEmailEnabled,
}));

describe("scheduled report delivery truthfulness", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    mocks.getReportTemplate.mockResolvedValue({
      id: "template-1",
      orgId: "org-1",
      reportType: "security",
      format: "csv",
    });
    mocks.createReportRun.mockResolvedValue({ id: "run-1" });
    mocks.updateReportRun.mockResolvedValue({});
    mocks.updateReportSchedule.mockResolvedValue({});
    mocks.generateReportData.mockResolvedValue({ findings: [] });
    mocks.isEmailEnabled.mockReturnValue(false);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("persists generation success and delivery failure when no target exists", async () => {
    const { executeScheduledReport } = await import("../report-scheduler");

    await executeScheduledReport({
      id: "schedule-1",
      orgId: "org-1",
      templateId: "template-1",
      name: "Security report",
      cadence: "weekly",
      deliveryTargets: "[]",
    });

    expect(mocks.getReportTemplate).toHaveBeenCalledWith("template-1", "org-1");
    expect(mocks.generateReportData).toHaveBeenCalledWith("security", "org-1");
    expect(mocks.updateReportRun).toHaveBeenLastCalledWith(
      "run-1",
      expect.objectContaining({
        status: "failed",
        generationStatus: "completed",
        deliveryStatus: "failed",
        outputLocation: null,
      }),
    );
    expect(mocks.updateReportRun.mock.calls.at(-1)?.[1].deliveryReason).toContain("No usable delivery target");
  });

  it("treats a non-2xx webhook response as delivery failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 500 })));
    const { executeScheduledReport } = await import("../report-scheduler");

    await executeScheduledReport({
      id: "schedule-1",
      orgId: "org-1",
      templateId: "template-1",
      name: "Security report",
      cadence: "weekly",
      deliveryTargets: JSON.stringify([{ type: "webhook", url: "https://reports.example.test/hook" }]),
    });

    expect(mocks.updateReportRun).toHaveBeenLastCalledWith(
      "run-1",
      expect.objectContaining({ status: "failed", deliveryStatus: "failed" }),
    );
    expect(mocks.updateReportRun.mock.calls.at(-1)?.[1].deliveryReason).toContain("HTTP 500");
  });

  it("preserves S3 delivery failure without a local delivery location", async () => {
    mocks.uploadFile.mockRejectedValue(new Error("S3 unavailable"));
    const { executeScheduledReport } = await import("../report-scheduler");

    await executeScheduledReport({
      id: "schedule-1",
      orgId: "org-1",
      templateId: "template-1",
      name: "Security report",
      cadence: "weekly",
      deliveryTargets: JSON.stringify([{ type: "s3" }]),
    });

    expect(mocks.updateReportRun).toHaveBeenLastCalledWith(
      "run-1",
      expect.objectContaining({
        status: "failed",
        generationStatus: "completed",
        deliveryStatus: "failed",
        outputLocation: null,
      }),
    );
    expect(mocks.updateReportRun.mock.calls.at(-1)?.[1].deliveryReason).toContain("S3 unavailable");
  });

  it("reports disabled email as delivery failure", async () => {
    const { executeScheduledReport } = await import("../report-scheduler");

    await executeScheduledReport({
      id: "schedule-1",
      orgId: "org-1",
      templateId: "template-1",
      name: "Security report",
      cadence: "weekly",
      deliveryTargets: JSON.stringify([{ type: "email", address: "security@example.test" }]),
    });

    expect(mocks.sendEmail).not.toHaveBeenCalled();
    expect(mocks.updateReportRun.mock.calls.at(-1)?.[1]).toEqual(
      expect.objectContaining({ status: "failed", deliveryStatus: "failed" }),
    );
    expect(mocks.updateReportRun.mock.calls.at(-1)?.[1].deliveryReason).toContain("not configured");
  });

  it("preserves email delivery failure", async () => {
    mocks.isEmailEnabled.mockReturnValue(true);
    mocks.sendEmail.mockRejectedValue(new Error("SES rejected message"));
    const { executeScheduledReport } = await import("../report-scheduler");

    await executeScheduledReport({
      id: "schedule-1",
      orgId: "org-1",
      templateId: "template-1",
      name: "Security report",
      cadence: "weekly",
      deliveryTargets: JSON.stringify([{ type: "email", address: "security@example.test" }]),
    });

    expect(mocks.updateReportRun.mock.calls.at(-1)?.[1]).toEqual(
      expect.objectContaining({ status: "failed", deliveryStatus: "failed" }),
    );
    expect(mocks.updateReportRun.mock.calls.at(-1)?.[1].deliveryReason).toContain("SES rejected message");
  });

  it("refuses a template that is unavailable for the schedule organization", async () => {
    mocks.getReportTemplate.mockResolvedValue(undefined);
    const { executeScheduledReport } = await import("../report-scheduler");

    await executeScheduledReport({
      id: "schedule-1",
      orgId: "org-2",
      templateId: "template-from-org-1",
      name: "Security report",
      cadence: "weekly",
      deliveryTargets: "[]",
    });

    expect(mocks.getReportTemplate).toHaveBeenCalledWith("template-from-org-1", "org-2");
    expect(mocks.createReportRun).not.toHaveBeenCalled();
    expect(mocks.generateReportData).not.toHaveBeenCalled();
  });
});
