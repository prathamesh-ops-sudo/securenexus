import { describe, expect, it } from "vitest";
import ForcedPasswordChangePage from "@/pages/forced-password-change";
import { ApiRequestError } from "@/lib/queryClient";
import { ErrorBoundary, isPasswordChangeRequiredError } from "./error-boundary";

describe("forced password-change error handling", () => {
  it("recognizes the structured password-change-required API error", () => {
    const error = new ApiRequestError(
      403,
      "Password change required before using SecureNexus.",
      "PASSWORD_CHANGE_REQUIRED",
    );

    expect(isPasswordChangeRequiredError(error)).toBe(true);
  });

  it("renders the forced-password-change page instead of the generic error state", () => {
    const boundary = new ErrorBoundary({ children: null });
    boundary.state = ErrorBoundary.getDerivedStateFromError(
      new ApiRequestError(403, "Password change required before using SecureNexus.", "PASSWORD_CHANGE_REQUIRED"),
    );

    const rendered = boundary.render();

    expect(rendered).toEqual(expect.objectContaining({ type: ForcedPasswordChangePage }));
  });
});
