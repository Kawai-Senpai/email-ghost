import os
import tempfile

os.environ["GHOST_DATA_DIR"] = tempfile.mkdtemp(prefix="email-ghost-tests-")
os.environ["GHOST_SMTP_ENABLED"] = "0"
os.environ.pop("GHOST_RSPAMD_URL", None)

import pytest
from fastapi.testclient import TestClient
from email_ghost.app import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
