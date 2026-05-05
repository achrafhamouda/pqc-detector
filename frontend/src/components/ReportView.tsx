import type { AnalyzeResponse, Finding, Severity } from "../types";

const SEVERITY_LABEL: Record<Severity, string> = {
  none: "none",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

export default function ReportView({ data }: { data: AnalyzeResponse }) {
  const { report, features } = data;
  const verdictClass = report.summary.verdict === "vulnerable" ? "vulnerable" : "clean";

  return (
    <section className="report">
      <div className={`verdict ${verdictClass}`}>
        <span className="verdict-label">{report.summary.verdict.toUpperCase()}</span>
        <span className="verdict-detail">
          {report.summary.total_findings} finding(s)
          {report.summary.total_findings > 0 &&
            ` · highest severity: ${SEVERITY_LABEL[report.summary.max_severity]}`}
        </span>
      </div>

      <div className="meta">
        <div>
          <strong>File:</strong> <code>{report.file}</code>
        </div>
        <div>
          <strong>LOC:</strong> {features.loc} ·{" "}
          <strong>Imports:</strong> {features.imported_modules.join(", ") || "none"}
        </div>
        <div>
          <strong>Randomness:</strong>{" "}
          <Flag on={features.randomness.uses_random} label="random" />
          <Flag on={features.randomness.uses_os_urandom} label="os.urandom" />
          <Flag on={features.randomness.uses_secrets} label="secrets" />
        </div>
        {report.model && !report.model.error && (
          <div>
            <strong>Model:</strong> {report.model.label}{" "}
            {report.model.scores && (
              <span className="muted">
                ({Object.entries(report.model.scores)
                  .map(([k, v]) => `${k}=${v.toFixed(3)}`)
                  .join(", ")})
              </span>
            )}
          </div>
        )}
        {report.model?.error && (
          <div className="muted">Model: {report.model.error}</div>
        )}
        {report.model === null && (
          <div className="muted">Model: not loaded (rule-based detection only)</div>
        )}
      </div>

      <h2>Findings</h2>
      {report.findings.length === 0 ? (
        <p className="empty">No vulnerabilities detected by static rules.</p>
      ) : (
        <ul className="findings">
          {report.findings.map((f, i) => (
            <FindingCard key={i} finding={f} />
          ))}
        </ul>
      )}
    </section>
  );
}

function Flag({ on, label }: { on: boolean; label: string }) {
  return (
    <span className={on ? "flag on" : "flag off"} title={`${label}: ${on}`}>
      {label}
    </span>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <li className={`finding sev-${finding.severity}`}>
      <header>
        <span className={`severity-badge sev-${finding.severity}`}>
          {finding.severity.toUpperCase()}
        </span>
        <span className="finding-title">{finding.title}</span>
        {finding.line !== null && (
          <span className="finding-line">line {finding.line}</span>
        )}
      </header>
      <dl>
        <dt>Weakness type</dt>
        <dd><code>{finding.weakness_type}</code></dd>
        <dt>Evidence</dt>
        <dd><code>{finding.evidence}</code></dd>
        <dt>Suggested fix</dt>
        <dd>{finding.suggestion}</dd>
      </dl>
    </li>
  );
}
