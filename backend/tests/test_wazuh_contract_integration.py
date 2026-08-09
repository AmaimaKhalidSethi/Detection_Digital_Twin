"""Optional real-Wazuh contract check; excluded unless explicitly enabled."""
import os

import pytest

from app.wazuh.client import WazuhClient


pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    os.getenv("DDT_RUN_WAZUH_CONTRACT_TEST") != "true",
    reason="Set DDT_RUN_WAZUH_CONTRACT_TEST=true with WAZUH_* credentials for a lab manager.",
)
def test_real_wazuh_logtest_contract():
    log_input = os.getenv("DDT_WAZUH_CONTRACT_LOG")
    if not log_input:
        pytest.skip("DDT_WAZUH_CONTRACT_LOG must contain a safe representative Wazuh log line")
    client = WazuhClient()
    assert client.get_manager_info() is not None
    result = client.run_logtest(log_input)
    assert isinstance(result, dict)
    assert "matched" in result, "Update WazuhClient normalization for this manager's logtest response shape"
