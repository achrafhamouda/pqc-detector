export type Severity = "none" | "low" | "medium" | "high" | "critical";

export interface Finding {
  weakness_type: string;
  severity: Severity;
  title: string;
  line: number | null;
  evidence: string;
  suggestion: string;
}

export interface ModelPrediction {
  label?: string;
  scores?: Record<string, number>;
  error?: string;
}

export interface Report {
  file: string;
  model: ModelPrediction | null;
  findings: Finding[];
  summary: {
    total_findings: number;
    max_severity: Severity;
    verdict: "vulnerable" | "clean";
  };
}

export interface Features {
  file: string;
  loc: number;
  imports: { module?: string; name?: string; line: number }[];
  imported_modules: string[];
  randomness: {
    uses_random: boolean;
    uses_os_urandom: boolean;
    uses_secrets: boolean;
    weak_random_calls: string[];
    secure_random_calls: string[];
  };
}

export interface AnalyzeResponse {
  report: Report;
  features: Features;
}
