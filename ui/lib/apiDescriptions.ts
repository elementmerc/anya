/**
 * API descriptions for known suspicious / noteworthy Windows APIs.
 * Loaded from ui/data/function_explanations.json — single source of truth.
 */
import fnExplanations from "@/data/function_explanations.json";

const API_DESCRIPTIONS: Record<string, string> = fnExplanations;

/** Returns the description for a given API name, or undefined if unknown. */
export function getApiDescription(name: string): string | undefined {
  return API_DESCRIPTIONS[name] ?? API_DESCRIPTIONS[name + "A"] ?? API_DESCRIPTIONS[name + "W"];
}
