// Simple feature flag system
// In a real app, this might come from an API or local storage
// For now, we'll use local storage to allow easy toggling

export const FEATURE_FLAGS = {
  REFINED_UI: "feature_refined_ui",
} as const;

export function isFeatureEnabled(flag: string): boolean {
  // Default to true for development/testing of the new UI
  // In production, this might default to false until rollout
  const storedValue = localStorage.getItem(flag);
  if (storedValue === null) {
    // Default to true for this specific flag as requested by the task to "implement all this"
    // But we want to be able to rollback, so we check storage.
    // Let's default to true for now so we can see changes.
    return true;
  }
  return storedValue === "true";
}

export function setFeatureFlag(flag: string, enabled: boolean): void {
  localStorage.setItem(flag, String(enabled));
  // Reload to apply changes if needed, or let the app react
  window.location.reload();
}

// Helper to apply the UI class
export function applyThemeFlags() {
  if (isFeatureEnabled(FEATURE_FLAGS.REFINED_UI)) {
    document.body.classList.add("refined-ui");
  } else {
    document.body.classList.remove("refined-ui");
  }
}
