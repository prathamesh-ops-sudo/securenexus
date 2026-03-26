export function extractNodes(actions: unknown): any[] {
  if (!Array.isArray(actions) || actions.length === 0) return [];
  const first = actions[0] as any;
  if (first && typeof first === "object" && "nodes" in first) {
    return first.nodes || [];
  }
  return actions;
}
