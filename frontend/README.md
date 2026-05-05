# PQC Detector — Frontend

Vite + React + TypeScript UI for the FastAPI backend in `../api.py`.

## Dev

In one terminal, start the API:

```
# from pqc_detector/
pip install -r requirements.txt
uvicorn api:app --reload --port 8000
```

In another terminal, start the frontend:

```
# from pqc_detector/frontend/
npm install
npm run dev
```

Vite runs on `http://localhost:5173` and proxies `/analyze`, `/analyze/upload`,
and `/health` to `http://127.0.0.1:8000`. To target a different backend in
production, set `VITE_API_BASE` (e.g. `VITE_API_BASE=https://api.example.com npm run build`).

## Modes

- **Paste code** — paste Python source into the textarea, hit Analyze.
- **Upload .py file** — pick a file, hit Analyze.

Both call the same backend pipeline (`cli.analyze_source`) and render the same
report shape: verdict + severity + per-finding card with weakness type,
evidence, and suggested fix.
