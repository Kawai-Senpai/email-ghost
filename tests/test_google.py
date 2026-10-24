import asyncio
import base64

import httpx

from email_ghost import google


def test_google_never_requests_without_credentials(monkeypatch):
    monkeypatch.delenv("GHOST_GMAIL_ACCESS_TOKEN", raising=False)
    assert not asyncio.run(google.gmail_message("123abc"))["available"]


def test_gmail_import_reads_labels_without_inventing_inbox(monkeypatch):
    real_client = httpx.AsyncClient
    monkeypatch.setenv("GHOST_GMAIL_ACCESS_TOKEN", "not-a-real-token")
    labels = ["SPAM"]

    def handler(request):
        assert request.url.host == "gmail.googleapis.com"
        assert request.headers["authorization"] == "Bearer not-a-real-token"
        return httpx.Response(200, json={"raw": base64.urlsafe_b64encode(b"Subject: observation\n\nBody").decode(), "labelIds": labels})

    monkeypatch.setattr(google.httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler)))
    result = asyncio.run(google.gmail_message("123abc"))
    assert result["raw"].startswith(b"Subject:")
    assert result["observed_label"] == "spam"
    labels[:] = ["SENT"]
    assert asyncio.run(google.gmail_message("123abc"))["observed_label"] is None


def test_postmaster_domain_cannot_escape_google_path():
    import pytest
    for invalid in ("../evil", "example.com/../../users", "http://example.com", "a@b.com"):
        with pytest.raises(ValueError):
            google.domain_name(invalid)
    assert google.domain_name("Example.COM") == "example.com"
