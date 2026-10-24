from __future__ import annotations

import io
import json
import re
import uuid
from contextlib import asynccontextmanager
from datetime import date, timedelta
from pathlib import PurePath

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.analyzers import analyze_email, analyze_message, analyze_url, is_valid_url
from app.config import settings
from app.database import (
    connect,
    get_save_scan_content,
    initialize_database,
    save_scan,
    set_save_scan_content,
)
from app.ml import DatasetError, evaluate_dataset
from app.schemas import (
    AnalysisResult,
    EmailRequest,
    DocumentSearchRequest,
    DashboardStats,
    DocumentSearchResult,
    HistoryItem,
    IndexedDocument,
    MessageRequest,
    PrivacySettings,
    SecurityNote,
    SecurityNoteRequest,
    URLRequest,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="NEXUS SHIELD API",
    description="Defensive, heuristic scam detection and local document search.",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _analyze(content: str, scan_type: str, save_content: bool = False) -> AnalysisResult:
    result = {
        "message": analyze_message,
        "url": analyze_url,
        "email": analyze_email,
    }[scan_type](content)
    content_saved = save_content and get_save_scan_content()
    result.content_saved = content_saved
    result.scan_id = save_scan(
        scan_type,
        result.risk_score,
        result.verdict,
        content if content_saved else None,
    )
    return result


@app.post("/api/analyze/message", response_model=AnalysisResult)
def analyze_message_endpoint(request: MessageRequest) -> AnalysisResult:
    return _analyze(request.text, "message", request.save_content)


@app.post("/api/analyze/url", response_model=AnalysisResult)
def analyze_url_endpoint(request: URLRequest) -> AnalysisResult:
    if not is_valid_url(request.url):
        raise HTTPException(status_code=422, detail="Provide a valid HTTP or HTTPS URL.")
    return _analyze(request.url, "url", request.save_content)


@app.post("/api/analyze/email", response_model=AnalysisResult)
def analyze_email_endpoint(request: EmailRequest) -> AnalysisResult:
    parts = []
    if request.sender.strip():
        parts.append(f"From: {request.sender.strip()}")
    if request.reply_to.strip():
        parts.append(f"Reply-To: {request.reply_to.strip()}")
    if request.subject.strip():
        parts.append(f"Subject: {request.subject.strip()}")
    if request.body.strip():
        parts.append(request.body.strip())
    if request.link_text.strip():
        parts.append(f"Link: {request.link_text.strip()}")
    return _analyze("\n".join(parts), "email", request.save_content)


@app.get("/api/settings", response_model=PrivacySettings)
def get_settings() -> PrivacySettings:
    return PrivacySettings(save_scan_content=get_save_scan_content())


@app.put("/api/settings", response_model=PrivacySettings)
def update_settings(settings_update: PrivacySettings) -> PrivacySettings:
    set_save_scan_content(settings_update.save_scan_content)
    return settings_update


@app.get("/api/history", response_model=list[HistoryItem])
def history(limit: int = Query(default=50, ge=1, le=200)) -> list[HistoryItem]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT id, scan_type, risk_score, verdict, created_at "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        HistoryItem(
            **dict(row),
            risk_level=(
                "high" if row["risk_score"] >= 60
                else "medium" if row["risk_score"] >= 30
                else "low"
            ),
        )
        for row in rows
    ]


@app.delete("/api/history")
def delete_history() -> dict[str, int]:
    with connect() as connection:
        cursor = connection.execute("DELETE FROM scans")
    return {"deleted": cursor.rowcount}


@app.get("/api/dashboard/stats", response_model=DashboardStats)
def dashboard_stats() -> DashboardStats:
    with connect() as connection:
        rows = connection.execute(
            "SELECT scan_type, verdict, COUNT(*) AS count FROM scans GROUP BY scan_type, verdict"
        ).fetchall()
        daily_rows = connection.execute(
            "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count FROM scans "
            "WHERE created_at >= ? GROUP BY substr(created_at, 1, 10)",
            ((date.today() - timedelta(days=6)).isoformat(),),
        ).fetchall()
        document_row = connection.execute("SELECT COUNT(*) AS count FROM documents").fetchone()
    by_type: dict[str, int] = {}
    by_verdict = {"high_risk": 0, "suspicious": 0, "low_risk": 0}
    total = 0
    for row in rows:
        count = int(row["count"])
        total += count
        by_type[row["scan_type"]] = by_type.get(row["scan_type"], 0) + count
        by_verdict[row["verdict"]] = by_verdict.get(row["verdict"], 0) + count
    return DashboardStats(
        total_scans=total,
        high_risk_scans=by_verdict["high_risk"],
        suspicious_scans=by_verdict["suspicious"],
        low_risk_scans=by_verdict["low_risk"],
        scans_by_type=by_type,
        indexed_documents=int(document_row["count"]),
        trend=[
            {
                "date": (date.today() - timedelta(days=offset)).strftime("%b %d"),
                "count": next(
                    (int(row["count"]) for row in daily_rows
                     if row["day"] == (date.today() - timedelta(days=offset)).isoformat()),
                    0,
                ),
            }
            for offset in range(6, -1, -1)
        ],
    )


def _safe_filename(filename: str | None) -> str:
    base = PurePath((filename or "upload").replace("\\", "/")).name
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")
    return (base or "upload")[:120]


async def _read_limited(upload: UploadFile) -> bytes:
    content = await upload.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Upload exceeds the allowed size.")
    return content


def _extract_text(filename: str, data: bytes) -> tuple[str, list[dict[str, int]]]:
    extension = PurePath(filename).suffix.lower()
    page_map: list[dict[str, int]] = []
    try:
        if extension == ".txt":
            text = data.decode("utf-8-sig")
        elif extension == ".pdf":
            reader = PdfReader(io.BytesIO(data), strict=True)
            if len(reader.pages) > 100:
                raise HTTPException(status_code=413, detail="PDF exceeds the 100-page limit.")
            parts: list[str] = []
            offset = 0
            for page_number, page in enumerate(reader.pages, start=1):
                page_text = page.extract_text() or ""
                parts.append(page_text)
                page_map.append(
                    {"start": offset, "end": offset + len(page_text), "page": page_number}
                )
                offset += len(page_text) + 1
            text = "\n".join(parts)
        else:
            raise HTTPException(status_code=415, detail="Only TXT and PDF files are accepted.")
    except HTTPException:
        raise
    except (PdfReadError, UnicodeDecodeError, ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail="File could not be safely read.") from exc
    if not text.strip():
        raise HTTPException(status_code=400, detail="No searchable text was found.")
    text = text[:2_000_000]
    page_map = [
        {
            **page,
            "end": min(page["end"], len(text)),
        }
        for page in page_map
        if page["start"] < len(text)
    ]
    return text, page_map


@app.post("/api/documents/upload")
async def upload_document(file: UploadFile = File(...)) -> dict[str, str]:
    filename = _safe_filename(file.filename)
    data = await _read_limited(file)
    text, page_map = _extract_text(filename, data)
    document_id = str(uuid.uuid4())
    # Store extracted text only for the explicit local document indexing feature.
    with connect() as connection:
        connection.execute(
            "INSERT INTO documents (id, filename, content, page_map) VALUES (?, ?, ?, ?)",
            (document_id, filename, text, json.dumps(page_map)),
        )
    return {"document_id": document_id, "filename": filename, "status": "indexed"}


@app.get("/api/documents", response_model=list[IndexedDocument])
def list_documents() -> list[IndexedDocument]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT id, filename, created_at FROM documents ORDER BY created_at DESC"
        ).fetchall()
    return [IndexedDocument(**dict(row)) for row in rows]


@app.delete("/api/documents/{document_id}")
def delete_document(document_id: str) -> dict[str, bool]:
    with connect() as connection:
        cursor = connection.execute("DELETE FROM documents WHERE id = ?", (document_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Indexed document not found.")
    return {"deleted": True}


def _search_documents(query: str, limit: int) -> list[DocumentSearchResult]:
    terms = [term.lower() for term in re.findall(r"[A-Za-z0-9@._-]{2,}", query)[:10]]
    if not terms:
        return []
    with connect() as connection:
        rows = connection.execute(
            "SELECT id, filename, content, page_map FROM documents"
        ).fetchall()
    ranked: list[tuple[int, str, str, str, int | None]] = []
    for row in rows:
        content = row["content"]
        lowered = content.lower()
        rank = sum(lowered.count(term) for term in terms)
        if rank:
            first = min((lowered.find(term) for term in terms if term in lowered), default=0)
            start = max(0, first - 100)
            snippet = re.sub(r"\s+", " ", content[start : start + 260]).strip()
            page_number = next(
                (
                    int(page["page"])
                    for page in json.loads(row["page_map"] or "[]")
                    if page["start"] <= first < page["end"]
                ),
                None,
            )
            ranked.append((rank, row["id"], row["filename"], snippet, page_number))
    ranked.sort(key=lambda match: (-match[0], match[2].lower()))
    return [
        DocumentSearchResult(
            document_id=document_id,
            filename=filename,
            snippet=snippet,
            rank=rank,
            page_number=page_number,
        )
        for rank, document_id, filename, snippet, page_number in ranked[:limit]
    ]


@app.get("/api/documents/search", response_model=list[DocumentSearchResult])
def search_documents(
    q: str = Query(min_length=1, max_length=200),
    limit: int = Query(default=10, ge=1, le=50),
) -> list[DocumentSearchResult]:
    return _search_documents(q, limit)


@app.post("/api/documents/search", response_model=list[DocumentSearchResult])
def search_documents_post(request: DocumentSearchRequest) -> list[DocumentSearchResult]:
    return _search_documents(request.query, 10)


@app.get("/api/notes", response_model=list[SecurityNote])
def list_security_notes() -> list[SecurityNote]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT id, note, created_at FROM security_notes ORDER BY id DESC"
        ).fetchall()
    return [SecurityNote(**dict(row)) for row in rows]


@app.post("/api/notes", response_model=SecurityNote)
def save_security_note(request: SecurityNoteRequest) -> SecurityNote:
    with connect() as connection:
        cursor = connection.execute(
            "INSERT INTO security_notes (note) VALUES (?)", (request.note.strip(),)
        )
        row = connection.execute(
            "SELECT id, note, created_at FROM security_notes WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    return SecurityNote(**dict(row))


@app.delete("/api/notes/{note_id}")
def delete_security_note(note_id: int) -> dict[str, bool]:
    with connect() as connection:
        cursor = connection.execute("DELETE FROM security_notes WHERE id = ?", (note_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Security note not found.")
    return {"deleted": True}


@app.post("/api/ml/evaluate")
async def ml_evaluate(file: UploadFile = File(...)) -> dict:
    filename = _safe_filename(file.filename)
    if PurePath(filename).suffix.lower() != ".csv":
        raise HTTPException(status_code=415, detail="Upload a labeled CSV dataset.")
    raw = await _read_limited(file)
    try:
        csv_text = raw.decode("utf-8-sig")
        return evaluate_dataset(csv_text)
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Dataset must be UTF-8 encoded CSV.") from exc
    except DatasetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/ml/train")
async def ml_train(file: UploadFile = File(...)) -> dict:
    # The MVP deliberately evaluates a real uploaded dataset and does not retain a model.
    result = await ml_evaluate(file)
    return {"status": "trained_and_evaluated_in_memory", **result}
