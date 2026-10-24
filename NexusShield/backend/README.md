# NEXUS SHIELD backend

## Run locally

From the repository root, install the root `requirements.txt`, then run:

```powershell
uvicorn app.main:app --reload --app-dir backend
.\.venv\Scripts\python.exe -m pytest backend\tests -q
```

The API is served under `/api`. Local Vite origins on port 5173 are allowed by
default; configure `NEXUS_CORS_ORIGINS` as a comma-separated list if needed.
SQLite data and extracted document text are stored locally under `backend/data`
by default. TXT/PDF uploads are parsed locally and never executed or fetched.
Scan history stores only scan type, heuristic score, verdict and timestamp by
default; submitted scan content is not included in history responses.

## Scan-content privacy

`GET /api/settings` returns the persisted `save_scan_content` preference,
which defaults to `false`. `PUT /api/settings` accepts
`{"save_scan_content": true|false}`. A message, URL, or email scan persists its
full submitted content only when **both** the saved preference is `true` and
that individual request includes `"save_content": true`. The per-request field
defaults to `false`; the API response's `content_saved` confirms whether it
was stored. History never returns scan content.

Message scans accept `{"text": "..."}`, URL scans accept `{"url": "..."}`, and
email scans accept `subject`, `body`, `sender`, `reply_to`, and `link_text`
fields. Analysis responses include `risk_score`, `risk_level`,
`detected_signals`, `evidence`, `explanation`, `recommended_actions`, and
`analysis_limitations`. The score is a heuristic, not a probability.

`GET /api/history` lists privacy-minimized records and `DELETE /api/history`
clears them. Approved notes use `GET/POST /api/notes` and
`DELETE /api/notes/{id}`. Indexed documents can be viewed with
`GET /api/documents` and removed with `DELETE /api/documents/{id}`.

## Optional supervised evaluation

`POST /api/ml/evaluate` and `/api/ml/train` accept a CSV upload with `text` and
`label` columns. Labels must be `scam` or `legitimate`, with at least 10
examples and at least two per class. Supply genuine, appropriately collected
and labeled data only. No synthetic or placeholder dataset is bundled or
generated. Training/evaluation is in memory, uses a deterministic split, and
does not retain the model or dataset.

The same holdout evaluation can run locally without the API:

```powershell
.\.venv\Scripts\python.exe backend\app\ml.py C:\path\to\licensed-data.csv
```

Results include per-class precision, recall, F1-score, and a confusion matrix.
