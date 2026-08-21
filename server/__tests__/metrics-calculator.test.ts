import { describe, expect, it } from "vitest";
import { calculatePreventedIncidents, calculateSlaPercentage } from "../metrics-calculator";

describe("honest empty metric calculations", () => {
  it("does not claim a prevented incident without blocked observations", () => {
    expect(calculatePreventedIncidents(0)).toBe(0);
    expect(calculatePreventedIncidents(9)).toBe(0);
    expect(calculatePreventedIncidents(20)).toBe(2);
  });

  it("returns unavailable SLA compliance for an empty denominator", () => {
    expect(calculateSlaPercentage(0, 0)).toBeNull();
    expect(calculateSlaPercentage(10, 10)).toBe(100);
  });
});
