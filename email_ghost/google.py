"""Explicit, read-only Google adapters. Credentials are supplied by the operator."""
import base64
import json
import os
import re
from datetime import datetime, timezone

import httpx


async def request_google(url, token_variable, body=None):
    token = os.getenv(token_variable, "")
    if not token:
        return {"available": False, "reason": "access_token_not_configured"}
    try:
        async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
            async with client.stream("POST" if body is not None else "GET", url,
                    json=body, headers={"Authorization": "Bearer " + token}) as response:
                if response.status_code != 200:
                    return {"available": False, "reason": "google_api_error", "status_code": response.status_code}
                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    payload.extend(chunk)
                    if len(payload) > 15 * 1024 * 1024:
                        raise ValueError("Google response exceeds sandbox limit")
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("Expected Google JSON object")
        return {"available": True, "source": url, "observed_at": datetime.now(timezone.utc).isoformat(), "data": data}
    except (httpx.HTTPError, ValueError) as exc:
        return {"available": False, "reason": "google_request_failed", "error_type": type(exc).__name__}


async def gmail_message(ident):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", ident):
        raise ValueError("Invalid Gmail message ID")
    result = await request_google("https://gmail.googleapis.com/gmail/v1/users/me/messages/" + ident + "?format=raw", "GHOST_GMAIL_ACCESS_TOKEN")
    if not result["available"]:
        return result
    try:
        encoded = result["data"]["raw"]
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if not raw or len(raw) > 10 * 1024 * 1024:
            raise ValueError("Gmail message outside sandbox size limit")
        labels = result["data"].get("labelIds", [])
        if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
            raise ValueError("Invalid Gmail labels")
        label = "spam" if "SPAM" in labels else "inbox" if "INBOX" in labels else None
        return {"available": True, "raw": raw, "labels": labels, "observed_label": label,
                "source": result["source"], "observed_at": result["observed_at"]}
    except (KeyError, TypeError, ValueError):
        return {"available": False, "reason": "invalid_gmail_response"}


def domain_name(domain):
    domain = domain.encode("idna").decode("ascii").lower()
    if len(domain) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise ValueError("Invalid domain name")
    return domain


async def postmaster(domain, query=None):
    domain = domain_name(domain)
    suffix = "/complianceStatus" if query is None else "/domainStats:query"
    return await request_google("https://gmailpostmastertools.googleapis.com/v2/domains/" + domain + suffix,
                                "GHOST_POSTMASTER_ACCESS_TOKEN", query)
