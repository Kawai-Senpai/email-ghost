"""End-to-end Docker verification. Uses only the Python standard library."""
import argparse
import json
import os
import smtplib
import time
import urllib.request
import uuid
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8030")
    parser.add_argument("--smtp-host", default="127.0.0.1")
    parser.add_argument("--smtp-port", type=int, default=1025)
    parser.add_argument("--screenshots", action="store_true")
    parser.add_argument("--require-scanner", action="store_true")
    parser.add_argument("--engine", choices=["chromium", "firefox", "webkit"], default="chromium")
    parser.add_argument("--matrix", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", default="reports/smoke.json")
    args = parser.parse_args()

    def api(path, body=None):
        headers = {"Content-Type": "application/json"}
        if os.getenv("GHOST_API_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["GHOST_API_TOKEN"]
        req = urllib.request.Request(args.url + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)

    assert api("/healthz")["service"] == "email-ghost"
    run = "smoke-" + uuid.uuid4().hex[:12]
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "sender@example.test", "recipient@example.test", "Sandbox smoke test"
    msg["Date"], msg["Message-ID"], msg["X-Ghost-Run-ID"] = formatdate(), make_msgid(domain="example.test"), run
    msg.set_content("Hello Ada. Your order #123 is confirmed.")
    msg.add_alternative('<html><body style="font-family:Arial"><h1>Order confirmed</h1><p>Hello Ada. Your order #123 is confirmed.</p><a href="https://example.test/order/123">View order</a></body></html>', subtype="html")
    msg.add_attachment(b"Sandbox attachment", maintype="application", subtype="pdf", filename="invoice.pdf")
    with smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=15) as smtp:
        smtp.send_message(msg)
    deadline = time.monotonic() + 15
    while True:
        matches = api("/v1/messages?run_id=" + run)["items"]
        if matches:
            break
        assert time.monotonic() < deadline, "SMTP capture not found"
        time.sleep(.25)
    ident = matches[0]["id"]
    inspected = api("/v1/messages/" + ident)
    assert inspected["attachments"][0]["filename"] == "invoice.pdf"
    audit = api(f"/v1/messages/{ident}/audit", {})
    if args.require_scanner:
        assert audit["rspamd"]["available"], audit["rspamd"]
        test_message = api("/v1/compose", {"subject": "GTUBE installation check", "text": "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X", "run_id": run})
        spam = api(f'/v1/messages/{test_message["id"]}/spam', {})
        assert spam["rspamd"]["available"], spam
        assert "GTUBE" in spam["rspamd"]["symbols"], spam
        assert spam["verdict"] == "high_risk", spam
    assertions = api(f"/v1/messages/{ident}/assert", {"subject_equals": "Sandbox smoke test", "text_contains": ["Ada", "#123"], "attachment_count": 1, "max_errors": 0, "require_rspamd": args.require_scanner})
    assert assertions["passed"], assertions
    report = {"run_id": run, "id": ident, "audit": audit, "assertions": assertions}
    if args.require_scanner:
        report["spam_detector_installation_test"] = spam
    if args.screenshots:
        job = api(f"/v1/messages/{ident}/captures", {"engine": args.engine, "matrix": args.matrix})
        deadline = time.monotonic() + 300
        while True:
            job = api("/v1/captures/" + job["id"])
            if job["status"] in ("completed", "failed"):
                break
            assert time.monotonic() < deadline, "Capture timed out"
            time.sleep(1)
        assert job["status"] == "completed", job
        assert len(job["manifest"]["variants"]) == (112 if args.matrix == "full" else 16)
        report["capture"] = job
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"passed": True, "run_id": run, "message_id": ident, "report": str(path)}))


if __name__ == "__main__":
    main()
