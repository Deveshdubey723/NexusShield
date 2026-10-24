import io

from fastapi.testclient import TestClient

from app import main


def test_api_validation_history_and_content_minimization(monkeypatch, tmp_path):
    database = tmp_path / "test.sqlite3"
    monkeypatch.setattr(main.settings, "database_path", database)
    monkeypatch.setattr(main.settings, "upload_dir", tmp_path / "uploads")
    with TestClient(main.app) as client:
        assert client.get("/api/health").json() == {"status": "ok"}
        assert client.post("/api/analyze/message", json={"text": ""}).status_code == 422
        assert client.post("/api/analyze/url", json={"url": "not a url"}).status_code == 422
        result = client.post(
            "/api/analyze/message",
            json={"text": "URGENT verify your account, send password"},
        )
        assert result.status_code == 200
        assert result.json()["verdict"] == "high_risk"
        assert result.json()["risk_level"] == "high"
        for field in (
            "risk_score", "risk_level", "detected_signals", "evidence",
            "explanation", "recommended_actions", "analysis_limitations",
        ):
            assert field in result.json()
        history = client.get("/api/history").json()
        assert len(history) == 1
        assert "content" not in history[0]
        with database.open("rb") as db_file:
            assert b"URGENT verify your account" not in db_file.read()
        assert result.json()["content_saved"] is False
        assert client.get("/api/dashboard/stats").json()["total_scans"] == 1
        assert client.delete("/api/history").json()["deleted"] == 1
        assert client.get("/api/history").json() == []


def test_scan_content_requires_request_and_persisted_preference(monkeypatch, tmp_path):
    database = tmp_path / "test.sqlite3"
    monkeypatch.setattr(main.settings, "database_path", database)
    monkeypatch.setattr(main.settings, "upload_dir", tmp_path / "uploads")
    secret_text = "Sensitive sample message that should only persist when opted in."
    with TestClient(main.app) as client:
        assert client.get("/api/settings").json() == {"save_scan_content": False}
        denied = client.post(
            "/api/analyze/message", json={"text": secret_text, "save_content": True}
        )
        assert denied.json()["content_saved"] is False
        assert client.put(
            "/api/settings", json={"save_scan_content": True}
        ).json()["save_scan_content"] is True
        opted_out = client.post(
            "/api/analyze/message", json={"text": secret_text}
        )
        assert opted_out.json()["content_saved"] is False
        opted_in = client.post(
            "/api/analyze/message",
            json={"text": secret_text, "save_content": True},
        )
        assert opted_in.json()["content_saved"] is True
        with database.open("rb") as db_file:
            assert secret_text.encode() in db_file.read()
        client.put("/api/settings", json={"save_scan_content": False})
        denied_again = client.post(
            "/api/analyze/message", json={"text": secret_text, "save_content": True}
        )
        assert denied_again.json()["content_saved"] is False


def test_document_upload_and_search(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "database_path", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main.settings, "upload_dir", tmp_path / "uploads")
    with TestClient(main.app) as client:
        response = client.post(
            "/api/documents/upload",
            files={"file": ("../safe-notes.txt", io.BytesIO(b"Never share your one-time code."), "text/plain")},
        )
        assert response.status_code == 200
        assert response.json()["filename"] == "safe-notes.txt"
        results = client.get("/api/documents/search", params={"q": "one-time code"}).json()
        assert results[0]["filename"] == "safe-notes.txt"
        post_results = client.post(
            "/api/documents/search", json={"query": "one-time code"}
        ).json()
        assert post_results[0]["snippet"] == results[0]["snippet"]
        indexed = client.get("/api/documents").json()
        assert len(indexed) == 1
        assert client.delete(f"/api/documents/{indexed[0]['id']}").json() == {"deleted": True}
        assert client.get("/api/documents").json() == []


def test_upload_rejects_unsupported_extension(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "database_path", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main.settings, "upload_dir", tmp_path / "uploads")
    with TestClient(main.app) as client:
        response = client.post(
            "/api/documents/upload", files={"file": ("script.exe", b"not executed", "application/octet-stream")}
        )
        assert response.status_code == 415


def test_ml_requires_labeled_real_dataset_upload(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "database_path", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main.settings, "upload_dir", tmp_path / "uploads")
    with TestClient(main.app) as client:
        response = client.post(
            "/api/ml/evaluate",
            files={"file": ("data.csv", b"text,label\nexample,scam\n", "text/csv")},
        )
        assert response.status_code == 422
        assert "At least 10" in response.json()["detail"]
        empty = client.post(
            "/api/ml/evaluate",
            files={"file": ("empty.csv", b"", "text/csv")},
        )
        assert empty.status_code == 422


def test_email_fields_and_user_approved_notes(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "database_path", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main.settings, "upload_dir", tmp_path / "uploads")
    with TestClient(main.app) as client:
        assert client.post("/api/analyze/email", json={}).status_code == 422
        result = client.post(
            "/api/analyze/email",
            json={
                "sender": "support@bank.example",
                "reply_to": "attacker@other.example",
                "subject": "Urgent account suspended",
                "body": "Send your OTP to restore access.",
                "link_text": "http://bit.ly/account",
            },
        )
        assert result.status_code == 200
        assert "reply_to_mismatch" in result.json()["detected_signals"]
        assert result.json()["risk_score"] > 0

        assert client.get("/api/notes").json() == []
        note = client.post(
            "/api/notes", json={"note": "Call the bank using the number on my card."}
        )
        assert note.status_code == 200
        note_id = note.json()["id"]
        assert len(client.get("/api/notes").json()) == 1
        assert client.delete(f"/api/notes/{note_id}").json() == {"deleted": True}
        assert client.get("/api/notes").json() == []
