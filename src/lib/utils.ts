import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRiskScore(score: number) {
  if (score >= 80) return { label: "Critical", color: "text-red-500" };
  if (score >= 60) return { label: "High", color: "text-orange-500" };
  if (score >= 40) return { label: "Medium", color: "text-yellow-500" };
  return { label: "Low", color: "text-green-500" };
}
