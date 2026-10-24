import os
import urllib.request

request = urllib.request.Request("http://127.0.0.1:8030/healthz")
if os.getenv("GHOST_API_TOKEN"):
    request.add_header("Authorization", "Bearer " + os.environ["GHOST_API_TOKEN"])
with urllib.request.urlopen(request, timeout=4) as response:
    if response.status != 200:
        raise SystemExit(1)
