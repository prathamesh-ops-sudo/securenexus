import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { applyThemeFlags } from "./lib/feature-flags";

// Apply feature flags (like refined UI class) before rendering
applyThemeFlags();

createRoot(document.getElementById("root")!).render(<App />);
