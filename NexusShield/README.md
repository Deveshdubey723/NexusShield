# NEXUS SHIELD

A privacy-first cybersecurity learning project that helps users inspect suspicious messages, URLs, and emails; search their own authorized documents; and understand the indicators behind each result. The local rule-based scanner works without paid services or an AI model.

> **Important:** Results are estimates, not guarantees or proof of fraud. A low-risk result does not prove that something is safe. HTTPS encrypts a connection; it does not establish that a website is trustworthy. Never use this project as a substitute for an organization's incident-response process.

## Features

- Deterministic message, URL, and email analysis with a score, risk level, evidence, explanation, next steps, and limitations.
- URL structure checks without opening or resolving the submitted URL. No live reputation check is required.
- Local SQLite scan history and dashboard counts. Submitted content is not stored by default.
- Local TXT/PDF document indexing and search with source attribution where available. Document text is treated as untrusted reference material.
- React dashboard with history deletion, privacy controls, security guidance, and scan-activity/risk summaries.
- An independent scikit-learn training/evaluation pipeline that requires a real, labeled dataset; no model is trained from invented examples.
- Optional Ollama integration is not required for core functionality. This starter version uses local rules and document search without sending data to an LLM.

## Technology

- Frontend: React 18, Vite, JavaScript, CSS, Recharts, Lucide React
- Backend: Python, FastAPI, Pydantic, Uvicorn
- Data: SQLite; scikit-learn, pandas, TF-IDF for the optional trained classifier; local PDF text extraction

## Architecture

```text
Browser (Vite :5173)
    └── JSON / multipart requests ──> FastAPI (:8000)
                                      ├── Rule-based analyzers
                                      ├── SQLite scan history / document index
                                      ├── Local TXT/PDF extraction and search
                                      └── Separate, opt-in dataset training pipeline
```

See [docs/architecture.md](docs/architecture.md) for data flow and safety boundaries.
See [docs/risk-scoring.md](docs/risk-scoring.md) for the deterministic rule weights and category cutoffs.

## Folder structure

```text
NexusShield/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI routes and local document search
│   │   ├── analyzers.py     # Deterministic message, URL, and email rules
│   │   ├── database.py      # SQLite history, settings, and approved notes
│   │   ├── schemas.py       # Pydantic request/response models
│   │   └── ml.py            # Optional labeled-dataset evaluation and CLI
│   ├── tests/               # Backend tests
│   └── data/                # Local SQLite and uploaded documents (gitignored)
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   └── services/
│   ├── package.json
│   └── vite.config.js
├── docs/
│   ├── architecture.md
│   └── setup.md
├── requirements.txt
└── README.md
```

## Requirements

- Windows 10/11 with PowerShell
- Python 3.10 or later (64-bit recommended)
- Node.js 18 or later and npm

## Setup on Windows PowerShell

Open two PowerShell terminals in the `NexusShield` folder.

### 1. Backend environment and dependencies

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

If PowerShell blocks environment activation, use `.\.venv\Scripts\python.exe` and `.\.venv\Scripts\pip.exe` instead, or allow scripts for the current user according to your device policy.

### 2. Start the backend

From the project root, with the virtual environment active:

```powershell
uvicorn app.main:app --reload --app-dir backend
```

The API is available at `http://127.0.0.1:8000`; interactive API documentation is at `http://127.0.0.1:8000/docs`.

### 3. Start the frontend

In a second terminal:

```powershell
Set-Location .\frontend
npm install
Copy-Item .env.example .env.local
npm run dev
```

Open the local URL printed by Vite (normally `http://127.0.0.1:5173`). The API base URL can be changed with `VITE_API_BASE_URL` in `frontend\.env.local`, then restart Vite.

### 4. Run tests and build

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -q
```

For the frontend production build:

```powershell
Set-Location .\frontend
npm run build
```

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Service readiness |
| `POST /api/analyze/message` | Analyze pasted message text |
| `POST /api/analyze/url` | Inspect URL structure only; never visits it |
| `POST /api/analyze/email` | Analyze email subject/body/sender/link text |
| `GET /api/history` | List local scan records |
| `DELETE /api/history` | Delete scan history |
| `GET/PUT /api/settings` | Read or update explicit content-retention preference |
| `GET/POST /api/notes`, `DELETE /api/notes/{id}` | Manage user-approved local security notes |
| `POST /api/documents/upload` | Upload and locally index an authorized TXT/PDF |
| `GET /api/documents`, `DELETE /api/documents/{id}` | List and remove indexed documents |
| `GET/POST /api/documents/search` | Search local document passages |
| `GET /api/dashboard/stats` | Aggregate local scan and document statistics |
| `POST /api/ml/evaluate` | Evaluate a supplied, real labeled CSV dataset |

Refer to the FastAPI OpenAPI page at `/docs` for the exact request/response schemas.
Analysis results include a heuristic `risk_score` and `risk_level`, matched
`detected_signals`, human-readable `evidence`, `explanation`,
`recommended_actions`, and `analysis_limitations`. The score is not a probability.

## Machine-learning dataset

The rule-based engine is the default and does not depend on a trained model. Training is a separate, optional workflow. Do not interpret an uncalibrated classifier score as a probability or replace the rule baseline without evaluation.

Use a legitimate dataset that you are permitted to use and that has clear label definitions. Keep it out of source control if its license or contents require that. The training script expects the documented CSV schema and requires enough examples per class for a stratified holdout split. It splits data before fitting TF-IDF to avoid vocabulary leakage. Evaluation reports precision, recall, F1-score, and a confusion matrix. Record dataset provenance, license, labeling process, split seed, and class balance when reporting model results.

No sample or synthetic dataset is bundled or silently used. The optional
command-line evaluator accepts a CSV with `text,label` columns:

```powershell
.\.venv\Scripts\python.exe backend\app\ml.py C:\path\to\your-labeled-data.csv
```

It reports precision, recall, F1-score, accuracy, and a confusion matrix on a
stratified holdout split. The API provides the same workflow at
`POST /api/ml/evaluate`. No model or dataset is retained.

## Optional Ollama

The MVP does not require Ollama and does not send user content to an external AI service. Local document search returns matching passages instead of claiming to have generated an answer. If adding a local Ollama model later, keep it opt-in, use a clear timeout and error state, and provide the retrieved passages as untrusted data rather than instructions.

## Privacy and safety notes

- Submitted URLs are parsed as strings; they are never fetched, opened, or passed to a reputation service.
- Only TXT and PDF files are accepted for document search. Uploaded files are not executed. Keep document uploads small and use files you are authorized to process.
- Indexed documents can be listed and removed in the Document Intelligence page; deleting a document removes its extracted text from the local index.
- Scans are stored in SQLite without full submitted text by default. History can be deleted from the dashboard.
- Document search is local keyword retrieval and may miss relevant material. It is not a source of authoritative policy or legal advice.
- Never paste passwords, one-time codes, recovery phrases, API keys, or other secrets into the app.
- The scanner detects signals that can appear in legitimate messages too. Independently verify important requests through a known contact channel.

## Troubleshooting

- **Frontend says API unreachable:** start the backend and confirm it is listening on port 8000. Check `frontend\.env.local` and restart Vite after changing it.
- **CORS/browser request error:** use the local Vite origin and backend configuration documented in `.env.example`; do not expose the development server to a public network.
- **`py` is not recognized:** install Python and enable the Python launcher, or replace `py -3` with `python`.
- **PDF has no indexed text:** scanned/image-only PDFs need OCR, which is not enabled in this MVP. Try a text-based PDF or TXT.
- **Upload rejected:** confirm the file is TXT or PDF and under the configured size limit.
- **Port is already in use:** stop the other development process or configure a free local port and update the API URL.

## Known limitations

- Rule matches are deterministic indicators, not calibrated probabilities or proof of malicious activity.
- There are no live domain reputation, DNS, WHOIS, certificate, or threat-feed checks.
- Sender identity is not independently authenticated.
- Local document retrieval uses keyword matching; semantic retrieval, OCR, and generated answers are not enabled.
- Approved notes and document indexes are stored locally; delete them through the Privacy Settings and Document Intelligence pages when no longer needed.
- The optional ML module is not trained until the user supplies a properly licensed, labeled dataset.

## Future improvements

- Add explicit document removal and user-approved security notes with deletion controls.
- Add optional calibrated ML inference after dataset review and held-out validation.
- Add local semantic retrieval and opt-in Ollama explanations with evidence citations.
- Add exportable, privacy-preserving reports and broader accessibility testing.
- Add URL reputation checks only as a separate, explicit opt-in with clear external data-sharing disclosure.
