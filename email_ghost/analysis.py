"""Evidence-based local checks. Scores are never marketed as probabilities."""
import hashlib
import ipaddress
import os
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

PROFILE_VERSION = "2026-11-19.1"
PROFILES = {
    "browser": "Browser baseline",
    "gmail-web": "Gmail web approximation",
    "gmail-android": "Gmail Android approximation",
    "gmail-ios": "Gmail iOS approximation",
    "outlook-web": "Outlook web approximation",
    "outlook-classic": "Outlook Classic stress approximation",
    "apple-mail": "Apple Mail approximation",
}


def parse(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    html, plain, attachments = [], [], []
    defects = [type(d).__name__ for d in msg.defects]
    for part in msg.walk():
        defects.extend(type(d).__name__ for d in part.defects)
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        if part.get_content_disposition() == "attachment" or part.get_filename() or part.get("Content-ID"):
            attachments.append({"index": len(attachments), "filename": part.get_filename() or "inline",
                                "content_type": part.get_content_type(), "size": len(payload),
                                "content_id": (part.get("Content-ID") or "").strip("<>"),
                                "sha256": hashlib.sha256(payload).hexdigest()})
        if part.get_content_disposition() == "attachment":
            continue
        try:
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            text = payload.decode("utf-8", errors="replace")
        if part.get_content_type() == "text/html":
            html.append(text)
        elif part.get_content_type() == "text/plain":
            plain.append(text)
    source = "\n".join(html)
    soup = BeautifulSoup(source, "html.parser")
    for node in soup(["script", "style", "head", "noscript"]):
        node.decompose()
    visible = soup.get_text(" ", strip=True)
    return {"subject": str(msg.get("Subject", "")), "from": str(msg.get("From", "")),
            "to": str(msg.get("To", "")), "headers": list(msg.raw_items()),
            "html": source, "text": "\n".join(plain), "visible_text": visible,
            "attachments": attachments, "mime_defects": sorted(set(defects))}


INLINE_IMAGE_MAX = 2 * 1024 * 1024
INLINE_IMAGE_TYPES = ("image/png", "image/jpeg", "image/gif", "image/webp")


def inline_images(raw):
    """The message's own Content-ID images as data URIs, so a preview shows
    what a client shows for cid: references without loading anything remote.
    Raster types only, each capped; anything else stays blank."""
    import base64
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    found = {}
    for part in msg.walk():
        cid = (part.get("Content-ID") or "").strip().strip("<>")
        if not cid or part.is_multipart() or part.get_content_type() not in INLINE_IMAGE_TYPES:
            continue
        payload = part.get_payload(decode=True) or b""
        if 0 < len(payload) <= INLINE_IMAGE_MAX:
            found[cid] = "data:" + part.get_content_type() + ";base64," + base64.b64encode(payload).decode()
    return found


def attachment(raw, index):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parts = [p for p in msg.walk() if not p.is_multipart() and
             (p.get_content_disposition() == "attachment" or p.get_filename() or p.get("Content-ID"))]
    return parts[index].get_payload(decode=True) or b""


def audit_local(message):
    findings = []

    def add(code, category, severity, evidence, action):
        findings.append(dict(code=code, category=category, severity=severity,
                             evidence=evidence, recommended_action=action))

    headers = {}
    for key, value in message["headers"]:
        headers.setdefault(key.lower(), []).append(value)
    for name in ("from", "date", "message-id"):
        if name not in headers:
            add("header.missing." + name, "message", "warning", name, "Add a valid " + name + " header.")
        elif len(headers[name]) > 1:
            add("header.duplicate." + name, "message", "error", name, "Remove duplicate singleton headers.")
    for defect in message["mime_defects"]:
        add("mime.defect", "message", "warning", defect, "Repair the MIME structure.")
    if message["html"] and not message["text"]:
        add("mime.no_plain_text", "accessibility", "warning", "HTML-only message", "Include a text/plain alternative.")
    html = message["html"]
    soup = BeautifulSoup(html, "html.parser")
    css = "\n".join(n.get_text() for n in soup.find_all("style")) + "\n" + "\n".join(
        n.get("style", "") for n in soup.find_all(style=True))
    checks = [(r"display\s*:\s*(?:inline-)?(?:flex|grid)", "layout.modern", "Use presentation tables for critical cross-client layout."),
              (r"@font-face|font-family\s*:[^;}]*(?:Google|Roboto|Inter)", "font.external", "Provide system font fallbacks."),
              (r"position\s*:\s*(?:fixed|absolute)", "layout.position", "Avoid positioned elements in critical email content."),
              (r"(?:animation|transition)\s*:", "css.animation", "Ensure content is readable without animation."),
              (r"background-image\s*:", "css.background_image", "Provide a background color and Outlook fallback."),
              (r"var\s*\(", "css.variables", "Inline concrete fallback values.")]
    for pattern, code, action in checks:
        match = re.search(pattern, css, re.I)
        if match:
            add(code, "compatibility", "warning", match.group(0), action)
    if len(html.encode()) > 102400:
        add("gmail.clipping_risk", "compatibility", "warning", "HTML exceeds 100 KiB", "Reduce HTML size; verify clipping in actual Gmail.")
    for tag in soup.find_all(["script", "iframe", "form", "object", "embed"]):
        add("html.active_content", "security", "error", tag.name, "Remove active content; it is blocked in previews.")
    for tag in soup.find_all(style=True):
        if re.search(r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?(?:;|$))", tag["style"], re.I) and tag.get_text(strip=True):
            add("content.hidden_text", "content", "info", tag.get_text(" ", strip=True)[:200], "Review hidden text; short inbox preheaders may be intentional.")
    if re.search(r"[\u200b\u200c\u200d\u2060\ufeff]", message["text"] + message["visible_text"]):
        add("content.invisible_unicode", "content", "info", "Zero-width Unicode characters detected", "Review character obfuscation; some languages legitimately use joiners.")
    for img in soup.find_all("img"):
        if not img.has_attr("alt"):
            add("image.missing_alt", "accessibility", "warning", str(img)[:180], "Add meaningful alt text, or empty alt for decorative images.")
        if str(img.get("width")) == "1" or str(img.get("height")) == "1":
            add("image.tracker", "privacy", "warning", img.get("src", "")[:180], "Remove tracking pixels in privacy-sensitive mail.")
    urls = []
    for anchor in soup.find_all("a", href=True):
        target = anchor["href"]
        try:
            url = urlsplit(target)
            host = url.hostname or ""
        except ValueError:
            add("url.invalid", "security", "error", target[:200], "Repair malformed URL.")
            continue
        signals = []
        if url.scheme.lower() not in ("https", "http", "mailto", "tel", "cid", ""):
            signals.append("unsafe_scheme")
        if url.username or url.password:
            signals.append("embedded_credentials")
        if "xn--" in host:
            signals.append("punycode_domain_review")
        try:
            ipaddress.ip_address(host)
            signals.append("literal_ip_destination")
        except ValueError:
            pass
        label = anchor.get_text(" ", strip=True)
        if re.match(r"https?://", label, re.I):
            try:
                if urlsplit(label).hostname != host:
                    signals.append("display_destination_mismatch")
            except ValueError:
                signals.append("invalid_display_url")
        urls.append({"url": target, "domain": host, "label": label, "signals": signals, "fetched": False})
        for signal in signals:
            add("url." + signal, "security", "error" if signal in ("unsafe_scheme", "embedded_credentials", "display_destination_mismatch") else "warning",
                target[:200], "Review destination and use a clear, trustworthy HTTPS link.")
    html_urls = {item["url"] for item in urls}
    for target in re.findall(r"https?://[^\s<>\"']+", message["text"], re.I):
        target = target.rstrip(".,;!?)")
        if target in html_urls:
            continue
        try:
            url = urlsplit(target)
            host = url.hostname or ""
        except ValueError:
            add("url.invalid", "security", "error", target[:200], "Repair malformed URL.")
            continue
        signals = []
        if url.username or url.password:
            signals.append("embedded_credentials")
        if "xn--" in host:
            signals.append("punycode_domain_review")
        try:
            ipaddress.ip_address(host)
            signals.append("literal_ip_destination")
        except ValueError:
            pass
        urls.append({"url": target, "domain": host, "label": target, "signals": signals, "fetched": False, "source": "text/plain"})
        for signal in signals:
            add("url." + signal, "security", "error" if signal == "embedded_credentials" else "warning", target[:200], "Review destination and use a clear, trustworthy HTTPS link.")
    for item in message["attachments"]:
        if re.search(r"\.(?:exe|scr|js|vbs|bat|cmd|ps1|hta|lnk|iso)(?:\s*)$", item["filename"], re.I):
            add("attachment.executable", "security", "error", item["filename"], "Remove executable attachments.")
    if "list-unsubscribe" in headers and "list-unsubscribe-post" not in headers:
        add("unsubscribe.no_one_click", "deliverability", "warning", "List-Unsubscribe without List-Unsubscribe-Post", "For bulk marketing, implement RFC 8058 one-click unsubscribe.")
    if "list-unsubscribe-post" in headers and not any("https://" in h.lower() for h in headers.get("list-unsubscribe", [])):
        add("unsubscribe.no_https", "deliverability", "error", "One-click header without HTTPS unsubscribe URL", "Add List-Unsubscribe with an HTTPS endpoint.")
    auth = {name: {"status": "not_verified", "reason": "Requires trusted scanner and sending context"} for name in ("spf", "dkim", "dmarc")}
    return {"findings": findings, "urls": urls, "authentication": auth,
            "reported_authentication_headers": headers.get("authentication-results", []),
            "reported_headers_trusted": False,
            "summary": {level: sum(f["severity"] == level for f in findings) for level in ("error", "warning", "info")}}


# How each Gmail app resolves a font-family stack. Gmail removes @font-face
# and remote stylesheets, so web fonts never load; a family the device lacks
# is skipped and the stack ends on the platform face. Android aliases arial,
# helvetica, verdana and tahoma to sans-serif, which is Roboto, so any sans
# stack lands on Roboto, and Roboto at weight 400 reads lighter than most
# brand sans faces. Approximations of documented behaviour, not Google's
# sanitizer.
GMAIL_FONTS = {
    "gmail-android": {"sans": "Roboto, sans-serif", "serif": "'Noto Serif', serif", "mono": "'Droid Sans Mono', 'DejaVu Sans Mono', monospace"},
    "gmail-ios": {"sans": "Helvetica, Arial, sans-serif", "serif": "Georgia, serif", "mono": "Menlo, Courier, monospace"},
    "gmail-web": {"sans": "Arial, Helvetica, sans-serif", "serif": "'Times New Roman', serif", "mono": "'Courier New', monospace"},
}
_FONT_DECL = re.compile(r"(font-family\s*:\s*)([^;}\"]+)", re.I)

# The phone the gmail-android profile models, read once from the environment
# (calibrate against a real screenshot: see docs).
#   GHOST_PHONE_TEXT_ZOOM    the phone's font-size setting in percent; Gmail
#                            Android scales email text by it, not the layout
#   GHOST_PHONE_MARGIN       px of Gmail's own frame around the message
#   GHOST_PHONE_WEIGHT_SHIFT added to every font weight; some phones draw the
#                            system face a step lighter than declared (-100
#                            turns 400 into Roboto Light)
def _env_int(name, default, low, high):
    try:
        return max(low, min(high, int(os.getenv(name, "") or default)))
    except ValueError:
        return default


PHONE_TEXT_ZOOM = _env_int("GHOST_PHONE_TEXT_ZOOM", 100, 50, 200)
PHONE_MARGIN = _env_int("GHOST_PHONE_MARGIN", 16, 0, 64)
PHONE_WEIGHT_SHIFT = _env_int("GHOST_PHONE_WEIGHT_SHIFT", 0, -300, 300)
_WEIGHT = re.compile(r"(font-weight\s*:\s*)(\d{3}|bold|normal|bolder|lighter)", re.I)
_NAMED_WEIGHT = {"normal": 400, "bold": 700, "bolder": 700, "lighter": 300}


def _shift_weights(css, shift):
    def one(m):
        raw = m.group(2).lower()
        value = _NAMED_WEIGHT.get(raw) or int(raw)
        return m.group(1) + str(max(100, min(900, value + shift)))
    return _WEIGHT.sub(one, css)


def _gmail_family(stack, fonts):
    if re.search(r"mono|courier|consolas|menlo", stack, re.I):
        return fonts["mono"]
    if re.search(r"(?<!sans-)serif|georgia|times", stack, re.I) and not re.search(r"sans-serif", stack, re.I):
        return fonts["serif"]
    return fonts["sans"]


def gmail_css(css, profile):
    """CSS as a Gmail app would apply it: no web fonts, families resolved."""
    fonts = GMAIL_FONTS[profile]
    css = re.sub(r"@font-face\s*\{[^}]*\}", "", css, flags=re.I)
    css = re.sub(r"@import[^;]*;", "", css, flags=re.I)
    if profile == "gmail-android" and PHONE_WEIGHT_SHIFT:
        css = _shift_weights(css, PHONE_WEIGHT_SHIFT)
    return _FONT_DECL.sub(lambda m: m.group(1) + _gmail_family(m.group(2), fonts), css)


def preview(message, profile="browser", dark=False, fallback=False, inline=None):
    """Sanitize and approximate profiles; CSP and network denial enforce isolation.

    inline maps Content-IDs to data URIs (inline_images): cid: images are the
    message's own bytes, so they are shown; every other source is removed.
    """
    soup = BeautifulSoup(message["html"] or "<pre></pre>", "html.parser")
    if not message["html"]:
        soup.pre.string = message["text"]
    for node in soup(["script", "iframe", "object", "embed", "form", "input", "button", "meta", "base", "link", "svg", "math", "video", "audio"]):
        node.decompose()
    gmail = profile in GMAIL_FONTS
    if gmail:
        for node in soup.find_all("style"):
            node.string = gmail_css(node.get_text(), profile)
    for node in soup.find_all(True):
        for attr in list(node.attrs):
            if attr.lower().startswith("on") or attr.lower() in ("srcdoc", "srcset", "action", "formaction", "background", "ping"):
                del node[attr]
        own = None
        if node.name == "img" and inline and str(node.get("src", "")).lower().startswith("cid:"):
            own = inline.get(str(node["src"])[4:].strip().strip("<>"))
        for attr in ("href", "src"):
            if node.has_attr(attr):
                # No navigation or remote loading, including encoded protocol tricks.
                del node[attr]
        if own:
            node["src"] = own
        if profile == "outlook-classic" and node.get("style"):
            node["style"] = re.sub(r"(?:display\s*:\s*(?:flex|grid)|border-radius\s*:[^;]+|box-shadow\s*:[^;]+|position\s*:[^;]+);?", "", node["style"], flags=re.I)
        if gmail and node.get("style"):
            node["style"] = gmail_css(node["style"], profile)
        if inline and node.get("style") and "cid:" in node["style"].lower():
            # Background images that point at the message's own parts.
            node["style"] = re.sub(r"url\(\s*['\"]?cid:([^'\")\s]+)['\"]?\s*\)",
                                   lambda m: "url('" + inline[m.group(1).strip("<>")] + "')" if m.group(1).strip("<>") in inline else "none",
                                   node["style"], flags=re.I)
    extra = "*{font-family:Arial,sans-serif!important}" if fallback else ""
    if gmail and not fallback:
        # Text with no family of its own gets the app's default face.
        extra += "body{font-family:" + GMAIL_FONTS[profile]["sans"] + "}"
        if profile == "gmail-android" and PHONE_WEIGHT_SHIFT:
            # Elements whose weight comes from the browser's defaults.
            regular, bold = (max(100, min(900, w + PHONE_WEIGHT_SHIFT)) for w in (400, 700))
            extra += f"body{{font-weight:{regular}}}b,strong,h1,h2,h3,h4,h5,h6,th{{font-weight:{bold}}}"
    if dark:
        extra += "html{background:#151923;color:#eee}body{background:#151923;color:#eee}"
    csp = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; base-uri 'none'; form-action 'none'"
    # The viewport meta matters on phone captures: without it mobile Chrome
    # lays the page out at 980 px and inflates some text, which no mail app
    # does. Gmail Android fits the email to the screen with a narrow frame.
    # Gmail Android honours the phone's font-size setting (a text zoom that
    # scales type, not layout); GHOST_PHONE_TEXT_ZOOM sets it, in percent.
    phone = profile == "gmail-android"
    zoom = str(PHONE_TEXT_ZOOM if phone else 100) + "%"
    # Gmail's frame sits outside the message, so it is a wrapper the email's
    # own <body style="margin:0"> cannot cancel (it merges into this body).
    frame = '<div style="padding:0 ' + str(PHONE_MARGIN) + 'px">' if phone else "<div>"
    return ('<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="' + csp + '"><style>html{-webkit-text-size-adjust:' + zoom + ';text-size-adjust:' + zoom + '}'
            'body{margin:' + ("0" if phone else "16px") + ';overflow-wrap:break-word}img{max-width:100%}' + extra + '</style></head><body>' + frame + str(soup) + '</div></body></html>')
