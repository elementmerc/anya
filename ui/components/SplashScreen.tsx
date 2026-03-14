import { useEffect, useRef } from "react";

interface SplashScreenProps {
  onComplete: () => void;
  className?: string;
  appReady: boolean;
}

export function SplashScreen({ onComplete, className, appReady }: SplashScreenProps) {
  const calledRef = useRef(false);
  const startTime = useRef(Date.now());

  useEffect(() => {
    if (!appReady) return;

    const elapsed = Date.now() - startTime.current;
    const minimumDisplay = 2200;
    const remaining = Math.max(0, minimumDisplay - elapsed);

    const timer = setTimeout(() => {
      if (!calledRef.current) {
        calledRef.current = true;
        onComplete();
      }
    }, remaining);

    return () => clearTimeout(timer);
  }, [appReady, onComplete]);

  return (
    <div className={`splash-overlay${className ? ` ${className}` : ""}`}>
      <div className="splash-content">
        <svg
          className="splash-svg"
          viewBox="0 0 200 180"
          xmlns="http://www.w3.org/2000/svg"
        >
          <line
            className="splash-leg-left"
            x1="36" y1="158" x2="100" y2="22"
            stroke="#e8e5dc"
            strokeWidth="14"
            strokeLinecap="round"
          />
          <line
            className="splash-leg-right"
            x1="164" y1="158" x2="100" y2="22"
            stroke="#e8e5dc"
            strokeWidth="14"
            strokeLinecap="round"
          />
          <line
            className="splash-bar"
            x1="58" y1="96" x2="142" y2="96"
            stroke="#EF9F27"
            strokeWidth="12"
            strokeLinecap="round"
          />
        </svg>
        <span className="splash-wordmark">ANYA</span>
      </div>
    </div>
  );
}
