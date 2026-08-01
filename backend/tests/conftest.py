import pytest

from app.models.db import Base
from app.main import engine


@pytest.fixture(autouse=True)
def _reset_db():
    """Every test starts with an empty database. Without this, rules
    uploaded in one test file persist into the next (they share the same
    module-level `engine`/`ddt.db`), which produced a real false failure
    during development: an unrelated test's leftover rule caused an
    off-by-one in alerts_generated for a later test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
