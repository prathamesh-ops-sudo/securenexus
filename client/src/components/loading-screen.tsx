import { useEffect, useState } from "react";

export function LoadingScreen() {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) return 0;
        // Slow down as it approaches completion for realistic feel
        const increment = prev < 30 ? 3 : prev < 60 ? 2 : prev < 85 ? 1 : 0.5;
        return Math.min(prev + increment, 100);
      });
    }, 50);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="loading-screen">
      <div className="loading-screen-content">
        <img src="/ats-logo.png" alt="ATS" className="loading-screen-logo" />
        <div className="loading-screen-bar-track">
          <div className="loading-screen-bar-fill" style={{ width: `${progress}%` }} />
        </div>
      </div>
    </div>
  );
}
