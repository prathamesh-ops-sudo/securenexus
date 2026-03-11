import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { applyThemeFlags } from "./lib/feature-flags";

// Apply feature flags (like refined UI class) before rendering
applyThemeFlags();

// Remove the pre-React loading screen before mounting
const initLoader = document.getElementById("initial-loader");
if (initLoader) initLoader.remove();
if ((window as any).__stopInitLoader) (window as any).__stopInitLoader();

createRoot(document.getElementById("root")!).render(<App />);
