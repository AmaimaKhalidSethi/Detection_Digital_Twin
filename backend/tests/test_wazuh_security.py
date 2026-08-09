from app.wazuh.client import WazuhClient


def test_wazuh_tls_verification_is_enabled_by_default(monkeypatch):
    monkeypatch.delenv("WAZUH_INSECURE_SKIP_TLS_VERIFY", raising=False)
    monkeypatch.delenv("WAZUH_CA_BUNDLE", raising=False)
    assert WazuhClient().verify_tls is True


def test_wazuh_insecure_tls_requires_explicit_lab_override(monkeypatch):
    monkeypatch.setenv("WAZUH_INSECURE_SKIP_TLS_VERIFY", "true")
    assert WazuhClient().verify_tls is False


def test_wazuh_accepts_an_explicit_ca_bundle(monkeypatch):
    monkeypatch.delenv("WAZUH_INSECURE_SKIP_TLS_VERIFY", raising=False)
    monkeypatch.setenv("WAZUH_CA_BUNDLE", "C:/certs/wazuh-ca.pem")
    assert WazuhClient().verify_tls == "C:/certs/wazuh-ca.pem"
