# Architecture and trust boundaries

## Components

- **React/Vite client:** navigation, form validation, results, dashboard visualizations, document upload/search, and history deletion.
- **FastAPI service:** request validation, rule-based analysis endpoints, document API, dashboard aggregation, and local persistence.
- **Rule engine:** deterministic indicators and evidence. Risk score is a heuristic severity score—not a probability, confidence measure, or finding of fact.
- **SQLite:** locally records scan metadata, risk outcomes, explicit privacy settings, approved notes, and indexed document text. Full scan content is excluded unless the user enables retention and explicitly opts in on that scan.
- **Document index:** extracts text from user-selected TXT/PDF files and supports local keyword retrieval with source attribution when possible.
- **ML tools:** separate training/evaluation workflow. No model or data is presumed available.

## Data flow

1. User submits text, email fields, or a URL to the local API.
2. API validates type and length. The URL analyzer inspects the supplied string; it does not make network requests.
3. Rule engine returns `risk_score`, `risk_level`, `detected_signals`, `evidence`, `explanation`, `recommended_actions`, and `analysis_limitations`.
4. The API persists a privacy-minimized history record and responds with the analysis result.
5. For documents, the user chooses a TXT/PDF file. The backend extracts text without executing it, stores/indexes the extracted material locally, and search returns source passages plus page numbers for PDFs when available. Users can list and delete indexed documents. Text found in documents is untrusted content, not application instruction.

## Security and privacy boundaries

- Never open or resolve user-provided URLs from the backend.
- Never execute uploads, macros, or attachments.
- Limit accepted file types and file size; generate server-side storage names rather than trusting submitted paths.
- Do not send content to a remote LLM, reputation service, or analytics endpoint by default.
- Validate inputs and return safe API errors without stack traces.
- Treat results as triage guidance. Matched indicators can have benign explanations.
- Risk-score weights and category cutoffs are documented in [risk-scoring.md](risk-scoring.md).

## Local deployment

The development API binds to loopback by default and the frontend uses `VITE_API_BASE_URL`, defaulting to `http://127.0.0.1:8000`. Keep both development servers on the local device.
