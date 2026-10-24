"""Repeatable fixture suites with JSON and JUnit output for CI agents."""
import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path


def run_suite(client, filename, output, run_id):
    path = Path(filename)
    spec = json.loads(path.read_text(encoding="utf-8"))
    cases = spec.get("cases", [])
    if not isinstance(cases, list) or not cases:
        raise ValueError("Suite must contain a nonempty cases array")
    results = []
    for case in cases:
        started = time.monotonic()
        result = {"name": case["name"], "passed": False}
        try:
            if "eml" in case:
                response = client.post("/v1/messages", params={"run_id": run_id},
                                       content=(path.parent / case["eml"]).read_bytes(), headers={"Content-Type": "message/rfc822"})
            else:
                response = client.post("/v1/compose", json={**case["message"], "run_id": run_id})
            response.raise_for_status()
            ident = response.json()["id"]
            response = client.post(f"/v1/messages/{ident}/assert", json=case.get("assertions", {}))
            response.raise_for_status()
            result.update(response.json())
        except Exception as exc:
            result["error"] = str(exc)
        result["seconds"] = round(time.monotonic() - started, 3)
        results.append(result)
    report = {"run_id": run_id, "passed": all(r["passed"] for r in results), "cases": results}
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    root = ET.Element("testsuite", name=spec.get("name", "email-ghost"), tests=str(len(results)),
                      failures=str(sum(not r["passed"] for r in results)))
    for result in results:
        child = ET.SubElement(root, "testcase", name=result["name"], time=str(result["seconds"]))
        if not result["passed"]:
            ET.SubElement(child, "failure", message=result.get("error", "Email assertions failed")).text = json.dumps(result, indent=2)
    ET.ElementTree(root).write(directory / "junit.xml", encoding="utf-8", xml_declaration=True)
    return report
