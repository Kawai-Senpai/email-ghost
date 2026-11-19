from email.message import EmailMessage
from email.utils import formatdate

from email_ghost.analysis import audit_local, parse, preview
from email_ghost.store import Store


def test_saved_audit_assertions_do_not_rescan_and_still_check_mime(client, monkeypatch):
    import importlib
    module = importlib.import_module("email_ghost.app")
    ident = client.post("/v1/compose", json={"subject": "Saved", "text": "Exact body"}).json()["id"]
    report = client.post(f"/v1/messages/{ident}/audit", json={}).json()

    async def no_rescan(*args):
        raise AssertionError("Saved-audit assertions must not rerun detectors")

    monkeypatch.setattr(module, "run_audit", no_rescan)
    spec = {"audit_id": report["audit_id"], "subject_equals": "Saved", "text_contains": ["Exact body"]}
    result = client.post(f"/v1/messages/{ident}/assert", json=spec).json()
    assert result["passed"] and result["audit_id"] == report["audit_id"]
    assert not client.post(f"/v1/messages/{ident}/assert", json={**spec, "subject_equals": "Wrong"}).json()["passed"]
    assert not client.post(f"/v1/messages/{ident}/assert", json={**spec, "require_rspamd": True}).json()["passed"]
    assert not client.post(f"/v1/messages/{ident}/assert", json={**spec, "required_models": ["missing"]}).json()["passed"]
    other = client.post("/v1/compose", json={"text": "Other capture"}).json()["id"]
    assert client.post(f"/v1/messages/{other}/assert", json=spec).status_code == 404
    assert client.post(f"/v1/messages/{ident}/assert", json={"audit_id": "missing"}).status_code == 404


def test_capture_preserves_mime_and_run_isolation(client):
    raw = b"From: a@example.test\r\nTo: b@example.test\r\nSubject: Original\r\n\r\nHello\r\n"
    created = client.post("/v1/messages?run_id=isolated", content=raw)
    assert created.status_code == 201
    ident = created.json()["id"]
    assert client.get(f"/v1/messages/{ident}/raw").content == raw
    assert client.get("/v1/messages?run_id=isolated").json()["items"][0]["id"] == ident
    assert client.get("/v1/messages?run_id=another").json()["items"] == []
    assert client.get(f"/v1/messages/{ident}").json()["text"] == "Hello\r\n"


def test_compose_assert_and_missing_scanner_fail_closed(client):
    ident = client.post("/v1/compose", json={"subject": "Welcome", "text": "Hello Ada", "run_id": "assertions"}).json()["id"]
    path = f"/v1/messages/{ident}/assert"
    assert client.post(path, json={"subject_equals": "Welcome", "text_contains": ["Ada"], "max_errors": 0}).json()["passed"]
    assert not client.post(path, json={"subject_equals": "Wrong"}).json()["passed"]
    assert not client.post(path, json={"require_rspamd": True}).json()["passed"]
    result = client.post(f"/v1/messages/{ident}/audit", json={}).json()
    assert result["gmail_spam_probability"] is None
    assert not result["gmail_prediction_available"]
    assert not result["rspamd"]["available"]
    assert result["content_spam_probability"] is None


def test_untrusted_auth_and_url_findings():
    raw = b'''From: a@example.test
Authentication-Results: attacker.test; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/html

<a href="https://evil.test/path">https://bank.test/login</a>
<a href="javascript:alert(1)">open</a><img src="https://tracker.test/a" width="1">
<div style="display:grid">layout</div><script>alert(1)</script>'''
    result = audit_local(parse(raw))
    codes = {f["code"] for f in result["findings"]}
    assert {"url.display_destination_mismatch", "url.unsafe_scheme", "image.tracker", "layout.modern", "html.active_content"} <= codes
    assert not result["reported_headers_trusted"]
    assert result["authentication"]["spf"]["status"] == "not_verified"
    assert all(not u["fetched"] for u in result["urls"])


def test_decorative_empty_alt_is_valid():
    report = audit_local(parse(b'Content-Type: text/html\n\n<img alt=""><img>'))
    assert sum(f["code"] == "image.missing_alt" for f in report["findings"]) == 1


def test_preview_removes_active_content_and_network_sources(client):
    ident = client.post("/v1/compose", json={"html": '<script>bad()</script><img src="http://127.0.0.1/private" onerror="bad()"><a href="javascript:bad()">Link</a><iframe srcdoc="bad"></iframe>'}).json()["id"]
    response = client.get(f"/v1/messages/{ident}/preview")
    assert response.status_code == 200
    assert "sandbox" in response.headers["content-security-policy"]
    assert "<script" not in response.text
    assert "onerror" not in response.text
    assert "127.0.0.1" not in response.text
    assert "javascript:" not in response.text
    assert client.get(f"/v1/messages/{ident}/preview?profile=made-up").status_code == 422


def test_gmail_profiles_drop_web_fonts_and_resolve_stacks():
    from email_ghost.analysis import gmail_css
    css = "@font-face{font-family:'Brand';src:url(x.woff2)} @import url(y.css); p{font-family:'Brand', 'Helvetica Neue', Arial, sans-serif;font-weight:400}"
    android = gmail_css(css, "gmail-android")
    assert "@font-face" not in android and "@import" not in android
    assert "font-family:Roboto, sans-serif" in android and "font-weight:400" in android
    assert "Arial, Helvetica" in gmail_css("p{font-family:'Brand', sans-serif}", "gmail-web")
    assert "monospace" in gmail_css("code{font-family:'JetBrains Mono', Menlo, monospace}", "gmail-android")
    assert "serif" in gmail_css("h1{font-family:Georgia, serif}", "gmail-android")
    html = '<html><head><style>@font-face{font-family:B;src:url(f)} .t{font-family:B, Arial}</style></head><body><p style="font-family:B, Arial">Hi</p></body></html>'
    page = preview({"html": html, "text": ""}, "gmail-android")
    assert "@font-face" not in page and "font-family:Roboto, sans-serif" in page
    assert "@font-face" in preview({"html": html, "text": ""}, "browser")  # other profiles untouched


def test_preview_shows_the_messages_own_cid_images_only():
    from email_ghost.analysis import inline_images
    msg = EmailMessage()
    msg["Subject"] = "Inline"
    msg.set_content("x")
    msg.add_alternative('<img src="cid:boo@x" alt="Boo"><img src="https://tracker.example/p.png" alt="">', subtype="html")
    msg.get_payload()[1].add_related(b"\x89PNG\r\n\x1a\nfake", "image", "png", cid="<boo@x>")
    raw = msg.as_bytes()
    found = inline_images(raw)
    assert list(found) == ["boo@x"] and found["boo@x"].startswith("data:image/png;base64,")
    page = preview(parse(raw), "gmail-android", inline=found)
    assert 'src="data:image/png;base64,' in page and "tracker.example" not in page


def test_attachment_exact_bytes_and_download_safety(client):
    msg = EmailMessage()
    msg["Subject"] = "File"
    msg.set_content("See attached")
    msg.add_attachment(b"payload\x00\xff", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    ident = client.post("/v1/messages", content=msg.as_bytes()).json()["id"]
    info = client.get(f"/v1/messages/{ident}").json()
    assert info["attachments"][0]["size"] == 9
    response = client.get(f"/v1/messages/{ident}/attachments/0")
    assert response.content == b"payload\x00\xff"
    assert response.headers["content-type"] == "application/octet-stream"
    assert "attachment" in response.headers["content-disposition"]
    assert client.get(f"/v1/messages/{ident}/attachments/-1").status_code == 404
    audit = client.post(f"/v1/messages/{ident}/audit", json={}).json()
    assert any(f["code"] == "attachment.executable" for f in audit["findings"])


def test_persistence_deletion_and_events(tmp_path):
    first = Store(tmp_path)
    ident = first.add(b"Subject: persisted\n\nhello", "persist")
    reopened = Store(tmp_path)
    assert reopened.get(ident)["raw"] == b"Subject: persisted\n\nhello"
    reopened.feedback(ident, "gmail", "spam", "owned seed account")
    reopened.delete(ident)
    assert reopened.list("persist") == []
    assert {e["action"] for e in reopened.events()} == {"message.captured", "feedback.recorded", "message.deleted"}


def test_token_and_validation(client, monkeypatch):
    monkeypatch.setenv("GHOST_API_TOKEN", "test-secret")
    assert client.get("/v1/capabilities").status_code == 401
    assert client.get("/v1/capabilities", headers={"Authorization": "Bearer test-secret"}).status_code == 200
    monkeypatch.delenv("GHOST_API_TOKEN")
    assert client.post("/v1/messages", content=b"").status_code == 400
    assert client.post("/v1/compose", json={"subject": "hello\r\nInjected: bad"}).status_code == 422
    assert client.get("/v1/messages?limit=999999").status_code == 422
    assert client.post("/v1/messages", content=b"a" * (10 * 1024 * 1024 + 1)).status_code == 413
    assert client.get("/v1/messages/absent").status_code == 404


def test_rspamd_adapter_passes_real_context_and_reports_failures(monkeypatch):
    import asyncio
    import httpx
    from email_ghost import engines
    real_client = httpx.AsyncClient
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"score": 7, "required_score": 6, "action": "add header", "symbols": {"TEST": {"score": 7}}})

    monkeypatch.setenv("GHOST_RSPAMD_URL", "http://scanner.test")
    monkeypatch.setattr(engines.httpx, "AsyncClient", lambda **kwargs: real_client(transport=httpx.MockTransport(handler)))
    result = asyncio.run(engines.scan_rspamd(b"Subject: test\n\nhello", {"sender_ip": "203.0.113.1", "mail_from": "sender@example.test"}))
    assert result["available"] and result["score"] == 7
    assert requests[0].headers["IP"] == "203.0.113.1"
    assert requests[0].url.path == "/checkv2"
    assert requests[0].content == b"Subject: test\n\nhello"


def test_image_comparison(tmp_path):
    from PIL import Image
    from email_ghost.render import compare_images
    a, b, diff = tmp_path / "a.png", tmp_path / "b.png", tmp_path / "diff.png"
    Image.new("RGB", (10, 10), "white").save(a)
    Image.new("RGB", (10, 10), "white").save(b)
    assert compare_images(a, b, diff)["changed_pixel_ratio"] == 0
    Image.new("RGB", (10, 10), "black").save(b)
    assert compare_images(a, b, diff)["changed_pixel_ratio"] == 1
    Image.new("RGB", (20, 10), "black").save(b)
    assert compare_images(a, b, diff)["dimensions_changed"]
