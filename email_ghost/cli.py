"""JSON-first agent CLI. Assertion failures exit 1; transport failures exit 2."""
import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

import httpx


def main():
    parser = argparse.ArgumentParser(description="Operate the Email Ghost local testing sandbox")
    parser.add_argument("--url", default=os.getenv("GHOST_URL", "http://127.0.0.1:8030"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities")
    suite = sub.add_parser("test")
    suite.add_argument("suite")
    suite.add_argument("--output", default="reports/suite")
    suite.add_argument("--run-id", default=None)
    ingest = sub.add_parser("ingest")
    ingest.add_argument("file")
    ingest.add_argument("--run-id", default="default")
    listing = sub.add_parser("list")
    listing.add_argument("--run-id")
    for name in ("get", "audit", "assert", "capture", "delete"):
        child = sub.add_parser(name)
        child.add_argument("id")
        if name == "assert":
            child.add_argument("--spec", required=True, help="JSON assertion file")
        if name == "capture":
            child.add_argument("--engine", choices=["chromium", "firefox", "webkit"], default="chromium")
            child.add_argument("--matrix", choices=["quick", "full"], default="quick")
    report = sub.add_parser("report")
    report.add_argument("run_id")
    wait = sub.add_parser("wait")
    wait.add_argument("--run-id", required=True)
    wait.add_argument("--subject")
    wait.add_argument("--timeout", type=float, default=30)
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8030)
    train = sub.add_parser("train-model", help="Fine-tune from authorized chronological, campaign-separated corpora")
    train.add_argument("--train-file", required=True)
    train.add_argument("--validation-file", required=True)
    train.add_argument("--base-model", default="answerdotai/ModernBERT-base")
    train.add_argument("--output", default="models/spam")
    train.add_argument("--max-length", type=int, choices=[512, 1024, 2048, 4096, 8192], default=4096)
    train.add_argument("--epochs", type=int, choices=range(1, 21), default=3)
    train.add_argument("--cpu", action="store_true")
    train.add_argument("--allow-small-dataset", action="store_true")
    calibrate = sub.add_parser("train-calibration", help="Fit optional local/Gmail probabilities from three independent labeled report splits")
    calibrate.add_argument("--task", choices=["local_spam", "gmail_placement"], required=True)
    for split in ("train", "calibration", "test"):
        calibrate.add_argument("--" + split + "-file", required=True)
    calibrate.add_argument("--features", default="rspamd_score")
    calibrate.add_argument("--sender-domains", default="")
    calibrate.add_argument("--output", required=True)
    calibrate.add_argument("--max-false-positive-rate", type=float, default=.01)
    calibrate.add_argument("--allow-small-dataset", action="store_true")
    args = parser.parse_args()
    if args.command == "train-calibration":
        from .calibration import fit
        try:
            if not 0 <= args.max_false_positive_rate <= 1:
                raise ValueError("False positive rate must be between zero and one")
            if not fit(args):
                sys.exit(1)
        except (ImportError, ValueError, OSError, KeyError) as exc:
            print(json.dumps({"error": "calibration_failed", "message": str(exc)}), file=sys.stderr)
            sys.exit(2)
        return
    if args.command == "train-model":
        from .training import train_model
        try:
            train_model(args)
        except (ImportError, ValueError, OSError, KeyError) as exc:
            print(json.dumps({"error": "training_failed", "message": str(exc)}), file=sys.stderr)
            sys.exit(2)
        return
    if args.command == "serve":
        import uvicorn
        uvicorn.run("email_ghost.app:app", host=args.host, port=args.port)
        return
    headers = {}
    if os.getenv("GHOST_API_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GHOST_API_TOKEN"]
    try:
        with httpx.Client(base_url=args.url, headers=headers, timeout=120, trust_env=False) as client:
            command = args.command
            if command == "test":
                from .suite import run_suite
                result = run_suite(client, args.suite, args.output, args.run_id or "suite-" + uuid.uuid4().hex[:12])
                print(json.dumps(result, indent=2))
                if not result["passed"]:
                    sys.exit(1)
                return
            method, path, options = "GET", "/v1/capabilities", {}
            if command == "ingest":
                method, path = "POST", "/v1/messages"
                options = {"content": Path(args.file).read_bytes(), "params": {"run_id": args.run_id},
                           "headers": {"Content-Type": "message/rfc822"}}
            elif command == "list":
                path, options = "/v1/messages", {"params": {"run_id": args.run_id} if args.run_id else {}}
            elif command in ("get", "audit", "assert", "capture", "delete"):
                path = "/v1/messages/" + args.id
                if command == "delete":
                    method = "DELETE"
                elif command != "get":
                    method = "POST"
                    path += "/" + {"capture": "captures"}.get(command, command)
                    options["json"] = json.loads(Path(args.spec).read_text()) if command == "assert" else (
                        {"engine": args.engine, "matrix": args.matrix} if command == "capture" else {})
            elif command == "report":
                path = "/v1/runs/" + args.run_id + "/report"
            elif command == "wait":
                deadline = time.monotonic() + args.timeout
                while True:
                    response = client.get("/v1/messages", params={"run_id": args.run_id, "limit": 200})
                    response.raise_for_status()
                    matches = [m for m in response.json()["items"] if args.subject is None or m["subject"] == args.subject]
                    if matches:
                        print(json.dumps({"items": matches}, indent=2))
                        return
                    if time.monotonic() >= deadline:
                        print(json.dumps({"error": "wait_timeout", "run_id": args.run_id}))
                        sys.exit(1)
                    time.sleep(0.25)
            response = client.request(method, path, **options)
            response.raise_for_status()
            result = response.json()
            print(json.dumps(result, indent=2))
            if result.get("passed") is False:
                sys.exit(1)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        print(json.dumps({"error": "request_failed", "message": str(exc)}), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
