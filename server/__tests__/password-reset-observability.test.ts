import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getUserByEmail: vi.fn(),
  createPasswordResetToken: vi.fn(),
  sendEmailWithStatus: vi.fn(),
  passwordResetEmail: vi.fn(() => ({
    subject: "Reset password",
    html: "<p>Reset password</p>",
    text: "Reset password",
  })),
  info: vi.fn(),
  error: vi.fn(),
}));

vi.mock("../routes/shared", () => ({
  logger: { child: () => ({ info: mocks.info, error: mocks.error }) },
  storage: { createPasswordResetToken: mocks.createPasswordResetToken },
}));
vi.mock("../auth/storage", () => ({
  authStorage: { getUserByEmail: mocks.getUserByEmail },
}));
vi.mock("../auth/session", () => ({
  hashPassword: vi.fn(),
}));
vi.mock("../email-service", () => ({
  sendEmailWithStatus: mocks.sendEmailWithStatus,
}));
vi.mock("../email-templates", () => ({
  passwordResetEmail: mocks.passwordResetEmail,
}));
vi.mock("../api-response", () => ({
  reply: vi.fn((res: TestResponse, data: unknown) => {
    res.status(200).json({ data });
    return res;
  }),
  replyValidation: vi.fn(),
  replyBadRequest: vi.fn(),
  replyInternal: vi.fn(),
}));
vi.mock("../middleware/auth-rate-limit", () => ({
  forgotPasswordRateLimit: (_req: unknown, _res: unknown, next: () => void) => next(),
}));
vi.mock("../middleware/security-policy-enforcement", () => ({
  validatePasswordComplexity: vi.fn(),
}));

import { registerPasswordResetRoutes } from "../routes/password-reset";

interface TestResponse {
  status: (status: number) => TestResponse;
  json: (body: unknown) => TestResponse;
}

type Handler = (req: Record<string, unknown>, res: TestResponse) => Promise<unknown> | unknown;

function captureForgotPasswordHandler(): Handler {
  let handler: Handler | undefined;
  const app = {
    post: (path: string, ...handlers: Handler[]) => {
      if (path === "/api/auth/forgot-password") handler = handlers[handlers.length - 1];
    },
    get: () => undefined,
  };
  registerPasswordResetRoutes(app as never);
  if (!handler) throw new Error("forgot-password handler was not registered");
  return handler;
}

function response() {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as TestResponse & {
    status: ReturnType<typeof vi.fn>;
    json: ReturnType<typeof vi.fn>;
  };
}

const user = {
  id: "user-1",
  email: "user@example.com",
  firstName: "Test",
  passwordHash: "hash",
};

describe("forgot-password observability", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getUserByEmail.mockResolvedValue(user);
    mocks.createPasswordResetToken.mockResolvedValue({});
    mocks.sendEmailWithStatus.mockResolvedValue({ accepted: true, status: "accepted" });
  });

  it("does not claim delivery and records accepted delivery", async () => {
    const res = response();
    await captureForgotPasswordHandler()({ body: { email: user.email } }, res);

    expect(res.json).toHaveBeenCalledWith({
      data: {
        message:
          "If an account with that email exists, password reset instructions will be sent if delivery is available.",
      },
    });
    await vi.waitFor(() => {
      expect(mocks.info).toHaveBeenCalledWith("Forgot-password reset token persisted", expect.any(Object));
      expect(mocks.info).toHaveBeenCalledWith("Forgot-password email delivery started", expect.any(Object));
      expect(mocks.info).toHaveBeenCalledWith("Password reset email accepted", expect.any(Object));
    });
  });

  it("logs skipped delivery as a failure", async () => {
    mocks.sendEmailWithStatus.mockResolvedValue({ accepted: false, status: "not_attempted" });

    await captureForgotPasswordHandler()({ body: { email: user.email } }, response());

    await vi.waitFor(() => {
      expect(mocks.error).toHaveBeenCalledWith(
        "Forgot-password email delivery failed",
        expect.objectContaining({ status: "not_attempted" }),
      );
    });
  });

  it("logs provider delivery failures as a failure", async () => {
    mocks.sendEmailWithStatus.mockResolvedValue({ accepted: false, status: "failed" });

    await captureForgotPasswordHandler()({ body: { email: user.email } }, response());

    await vi.waitFor(() => {
      expect(mocks.error).toHaveBeenCalledWith(
        "Forgot-password email delivery failed",
        expect.objectContaining({ status: "failed" }),
      );
    });
  });

  it("logs token persistence errors and does not attempt delivery", async () => {
    mocks.createPasswordResetToken.mockRejectedValue(new Error("database unavailable"));

    await captureForgotPasswordHandler()({ body: { email: user.email } }, response());

    await vi.waitFor(() => {
      expect(mocks.error).toHaveBeenCalledWith(
        "Background forgot-password failed",
        expect.objectContaining({ error: "Error: database unavailable" }),
      );
    });
    expect(mocks.sendEmailWithStatus).not.toHaveBeenCalled();
  });

  it("logs skipped reset requests for accounts without a local password", async () => {
    mocks.getUserByEmail.mockResolvedValue({ ...user, passwordHash: null });

    await captureForgotPasswordHandler()({ body: { email: user.email } }, response());

    await vi.waitFor(() => {
      expect(mocks.info).toHaveBeenCalledWith(
        "Forgot-password reset skipped",
        expect.objectContaining({ reason: "no_local_password" }),
      );
    });
    expect(mocks.createPasswordResetToken).not.toHaveBeenCalled();
    expect(mocks.sendEmailWithStatus).not.toHaveBeenCalled();
  });
});
