import asyncio
import html
import json
import os
from pathlib import Path

from .analysis import PROFILE_VERSION, PROFILES, preview

RENDER_LOCK = asyncio.Semaphore(1)


async def capture(message, directory, engine="chromium", full=False):
    from playwright.async_api import async_playwright
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    variants = []
    profiles = list(PROFILES) if full else ["browser", "outlook-classic"]
    widths = [390, 700, 1024, 1440] if full else [390, 700]
    async with RENDER_LOCK, async_playwright() as pw:
        executable = os.getenv("GHOST_" + engine.upper() + "_EXECUTABLE")
        browser = await getattr(pw, engine).launch(**({"executable_path": executable} if executable else {}))
        browser_version = browser.version
        try:
            context = await browser.new_context(java_script_enabled=False, service_workers="block")
            await context.route("**/*", lambda route: route.abort())
            page = await context.new_page()
            for profile in profiles:
                for width in widths:
                    for dark in (False, True):
                        for fallback in (False, True):
                            name = f"{profile}-{width}-{'dark' if dark else 'light'}-{'fallback' if fallback else 'original'}.png"
                            await page.set_viewport_size({"width": width, "height": 900})
                            await page.emulate_media(color_scheme="dark" if dark else "light", reduced_motion="reduce")
                            await page.set_content(preview(message, profile, dark, fallback), wait_until="load", timeout=10000)
                            # Bound malicious or accidentally enormous email layouts.
                            height = min(12000, max(900, await page.locator("body").evaluate("el => el.scrollHeight")))
                            await page.screenshot(path=str(directory / name), clip={"x": 0, "y": 0, "width": width, "height": height}, timeout=15000)
                            variants.append({"file": name, "profile": profile, "width": width, "dark": dark,
                                             "fallback_fonts": fallback, "height": height, "max_height": 12000})
        finally:
            await browser.close()
    manifest = {"engine": engine, "browser_version": browser_version, "profile_version": PROFILE_VERSION, "simulation": True,
                "remote_resources": "blocked", "variants": variants}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    cards = "".join('<figure><a href="' + v["file"] + '"><img loading="lazy" width="300" src="' + v["file"] + '"></a><figcaption>' + html.escape(v["file"]) + '</figcaption></figure>' for v in variants)
    (directory / "index.html").write_text('<!doctype html><meta charset="utf-8"><title>Email Ghost capture</title><h1>Browser simulations</h1><p>Remote resources blocked. Profiles are approximations, not actual Gmail or Outlook.</p><main style="display:flex;flex-wrap:wrap">' + cards + '</main>', encoding="utf-8")
    return manifest


def compare_images(before, after, output):
    from PIL import Image, ImageChops
    a, b = Image.open(before).convert("RGB"), Image.open(after).convert("RGB")
    width, height = max(a.width, b.width), max(a.height, b.height)
    canvases = []
    for source in (a, b):
        canvas = Image.new("RGB", (width, height), "white")
        canvas.paste(source, (0, 0))
        canvases.append(canvas)
    diff = ImageChops.difference(*canvases)
    # Union of thresholded channels: count pixels rather than channel samples.
    mask = diff.getchannel("R").point(lambda value: 255 if value > 16 else 0)
    for channel in ("G", "B"):
        mask = ImageChops.lighter(mask, diff.getchannel(channel).point(lambda value: 255 if value > 16 else 0))
    changed = mask.histogram()[255]
    diff.save(output)
    return {"changed_pixel_ratio": changed / (width * height), "dimensions_changed": a.size != b.size,
            "threshold_per_channel": 16, "width": width, "height": height}
