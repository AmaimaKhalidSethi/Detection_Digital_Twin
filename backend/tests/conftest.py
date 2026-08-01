import os
import tempfile
import uuid
from pathlib import Path

import pytest


# This must be set before importing app.main, which builds its module-level
# engine at import time. Every pytest run gets a separate disposable SQLite
# file, never backend/ddt.db used by the application and seed scripts.
TEST_DATABASE_PATH = Path(tempfile.gettempdir()) / f"detection-digital-twin-pytest-{uuid.uuid4()}.db"
os.environ["DDT_DATABASE_URL"] = f"sqlite:///{TEST_DATABASE_PATH.as_posix()}"

from app.models.db import Base
from app.main import engine


@pytest.fixture(autouse=True)
def _reset_db():
    """Every test starts with an empty, isolated test database."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def pytest_sessionfinish(session, exitstatus):
    engine.dispose()
    TEST_DATABASE_PATH.unlink(missing_ok=True)
