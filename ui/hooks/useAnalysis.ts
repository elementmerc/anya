import { useState, useCallback } from "react";
import { analyzeFile } from "@/lib/tauri-bridge";
import { storeAnalysis } from "@/lib/db";
import type { AnalysisResult, AnalyzeResponse } from "@/types/analysis";

interface AnalysisState {
  result: AnalysisResult | null;
  riskScore: number;
  isSuspicious: boolean;
  isLoading: boolean;
  error: string | null;
}

const INITIAL: AnalysisState = {
  result: null,
  riskScore: 0,
  isSuspicious: false,
  isLoading: false,
  error: null,
};

/** Analysis timeout in ms — prevents spinner running forever */
const TIMEOUT_MS = 60_000;

export function useAnalysis() {
  const [state, setState] = useState<AnalysisState>(INITIAL);

  const analyse = useCallback(async (filePath: string) => {
    setState({ ...INITIAL, isLoading: true });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const timeoutPromise = new Promise<never>((_, reject) =>
        controller.signal.addEventListener("abort", () =>
          reject(new Error("Analysis timed out after 60 seconds"))
        )
      );
      const response: AnalyzeResponse = await Promise.race([
        analyzeFile(filePath),
        timeoutPromise,
      ]);

      clearTimeout(timer);

      // Persist to SQLite (fire-and-forget, non-blocking)
      storeAnalysis(response.result, response.risk_score).catch(console.error);

      setState({
        result: response.result,
        riskScore: response.risk_score,
        isSuspicious: response.is_suspicious,
        isLoading: false,
        error: null,
      });
    } catch (err) {
      clearTimeout(timer);
      setState({
        ...INITIAL,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }, []);

  const reset = useCallback(() => setState(INITIAL), []);

  return { ...state, analyse, reset };
}
