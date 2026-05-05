import { useState } from "react";
import type { AnalyzeResponse } from "./types";
import { analyzeCode, analyzeFile } from "./api";
import ReportView from "./components/ReportView";

type Mode = "paste" | "upload";

export default function App() {
  const [mode, setMode] = useState<Mode>("paste");
  const [code, setCode] = useState<string>(SAMPLE_CODE);
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onAnalyze() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = mode === "paste"
        ? await analyzeCode(code, "pasted.py")
        : await analyzeFile(file!);
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  const canAnalyze = mode === "paste" ? code.trim().length > 0 : file !== null;

  return (
    <div className="app">
      <header>
        <h1>PQC Detector</h1>
        <p className="subtitle">
          Static analyzer for post-quantum cryptography misuse in Python.
        </p>
      </header>

      <div className="tabs" role="tablist">
        <button
          role="tab"
          aria-selected={mode === "paste"}
          className={mode === "paste" ? "tab active" : "tab"}
          onClick={() => setMode("paste")}
        >
          Paste code
        </button>
        <button
          role="tab"
          aria-selected={mode === "upload"}
          className={mode === "upload" ? "tab active" : "tab"}
          onClick={() => setMode("upload")}
        >
          Upload .py file
        </button>
      </div>

      <section className="input-pane">
        {mode === "paste" ? (
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            spellCheck={false}
            placeholder="Paste Python code here..."
            rows={16}
          />
        ) : (
          <div className="upload-pane">
            <input
              type="file"
              accept=".py"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
            {file && (
              <p className="file-info">
                Selected: <code>{file.name}</code> ({file.size} bytes)
              </p>
            )}
          </div>
        )}

        <div className="actions">
          <button
            className="primary"
            onClick={onAnalyze}
            disabled={!canAnalyze || loading}
          >
            {loading ? "Analyzing..." : "Analyze"}
          </button>
        </div>
      </section>

      {error && (
        <div className="error" role="alert">
          Error: {error}
        </div>
      )}

      {result && <ReportView data={result} />}
    </div>
  );
}

const SAMPLE_CODE = `import random
from kyber_py.kyber import Kyber768

def derive_seed(length=32):
    return bytes(random.randint(0, 255) for _ in range(length))

seed = derive_seed()
pk, sk = Kyber768.keygen_derand(seed)
`;
