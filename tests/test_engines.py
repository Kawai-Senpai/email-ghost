import asyncio

import httpx

from email_ghost import engines


def test_scanner_failure_does_not_produce_score(monkeypatch):
    real_client = httpx.AsyncClient
    monkeypatch.setenv("GHOST_RSPAMD_URL", "http://scanner.test")
    monkeypatch.setattr(engines.httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(lambda req: httpx.Response(503))))
    result = asyncio.run(engines.scan_rspamd(b"test", {}))
    assert not result["available"]
    assert "score" not in result


def test_learning_requires_explicit_configuration(monkeypatch):
    monkeypatch.delenv("GHOST_RSPAMD_CONTROLLER_URL", raising=False)
    result = asyncio.run(engines.learn_rspamd(b"test", "spam"))
    assert not result["learned"]


def test_gtube_skip_is_definitive_but_other_skips_are_not():
    result = {"available": True, "is_skipped": True, "action": "reject", "symbols": {"GTUBE": {}}, "passthrough_module": "GTUBE"}
    assert engines.scanner_has_result(result)
    result["passthrough_module"] = "settings"
    assert not engines.scanner_has_result(result)


def test_authentication_uses_symbols_and_production_context():
    scan = {"available": True, "symbols": {"R_SPF_ALLOW": {"score": -1}, "R_DKIM_REJECT": {"score": 1}}}
    without_ip = engines.authentication_from_symbols(scan, None)
    assert "spf" not in without_ip
    assert without_ip["dkim"]["status"] == "fail"
    assert engines.authentication_from_symbols(scan, "203.0.113.1")["spf"]["status"] == "pass"
    scan["is_skipped"] = True
    assert engines.authentication_from_symbols(scan, "203.0.113.1") == {}


def test_suite_preserves_failure_and_exports_junit(client, tmp_path):
    import json
    import xml.etree.ElementTree as ET
    from email_ghost.suite import run_suite
    spec = tmp_path / "suite.json"
    spec.write_text(json.dumps({"cases": [{"name": "Mismatch", "message": {"subject": "actual"}, "assertions": {"subject_equals": "expected"}}]}))
    result = run_suite(client, spec, tmp_path / "results", "suite-failure")
    assert not result["passed"]
    assert result["cases"][0]["message_id"]
    assert ET.parse(tmp_path / "results" / "junit.xml").getroot().attrib["failures"] == "1"


def test_plain_text_links_are_audited():
    from email_ghost.analysis import audit_local, parse
    report = audit_local(parse(b"Content-Type: text/plain\n\nSee https://bank.test@evil.test/confirm and http://192.0.2.1/login"))
    codes = {f["code"] for f in report["findings"]}
    assert "url.embedded_credentials" in codes
    assert "url.literal_ip_destination" in codes
    assert len(report["urls"]) == 2
