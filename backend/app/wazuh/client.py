from __future__ import annotations

import logging
import os
import time

import requests
import urllib3
from dotenv import load_dotenv

# Suppress unverified HTTPS request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"))

logger = logging.getLogger(__name__)


class WazuhClient:
    """Small, failure-tolerant client for the Wazuh manager API."""

    def __init__(self) -> None:
        self.base_url = os.getenv("WAZUH_BASE_URL")
        self.username = os.getenv("WAZUH_USERNAME")
        self.password = os.getenv("WAZUH_PASSWORD")
        self._token: str | None = None
        self._token_expires_at: float | None = None

    def _authenticate(self) -> str | None:
        if not self.base_url or not self.username or not self.password:
            logger.warning("Wazuh configuration missing in environment variables.")
            return None

        url = f"{self.base_url.rstrip('/')}/security/user/authenticate?raw=true"

        try:
            # 1. Attempt Basic Auth
            response = requests.post(
                url,
                auth=(self.username, self.password),
                verify=False,
                timeout=10,
            )
            
            # 2. Fall back to JSON authentication body if 401 Unauthorized occurs
            if response.status_code == 401:
                response = requests.post(
                    url,
                    json={"username": self.username, "password": self.password},
                    verify=False,
                    timeout=10,
                )

            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            logger.warning("Wazuh authentication request failed: %s", exc)
            return None

        self._token = response.text.strip()
        self._token_expires_at = time.time() + 840
        return self._token

    def get_token(self) -> str | None:
        if self._token and self._token_expires_at and time.time() < self._token_expires_at:
            return self._token
        return self._authenticate()

    def get_manager_info(self) -> dict | None:
        token = self.get_token()
        if token is None:
            return None

        try:
            response = requests.get(
                f"{self.base_url.rstrip('/')}/manager/info",
                headers={"Authorization": f"Bearer {token}"},
                verify=False,
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as exc:
            logger.warning("Wazuh manager-info request failed: %s", exc)
            return None
        except ValueError as exc:
            logger.warning("Wazuh manager-info response was not valid JSON: %s", exc)
            return None

        if not isinstance(data, dict):
            logger.warning("Wazuh manager-info response had an unexpected shape")
            return None
        return data

    def get_active_technique_ids(self) -> set[str] | None:
        """Return MITRE technique IDs referenced by enabled Wazuh rules."""
        token = self.get_token()
        if token is None:
            return None

        technique_ids: set[str] = set()
        offset = 0
        limit = 500
        total_affected_items: int | None = None

        while total_affected_items is None or offset < total_affected_items:
            try:
                response = requests.get(
                    f"{self.base_url.rstrip('/')}/rules",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"status": "enabled", "limit": limit, "offset": offset},
                    verify=False,
                    timeout=10,
                )
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as exc:
                logger.warning("Wazuh rules request failed: %s", exc)
                return None
            except ValueError as exc:
                logger.warning("Wazuh rules response was not valid JSON: %s", exc)
                return None

            try:
                response_data = data["data"]
                affected_items = response_data["affected_items"]
                if total_affected_items is None:
                    total_affected_items = response_data["total_affected_items"]
            except (KeyError, TypeError) as exc:
                logger.warning("Wazuh rules response had an unexpected shape: %s", exc)
                return None

            for rule in affected_items:
                mitre = rule.get("mitre") if isinstance(rule, dict) else None
                ids = mitre.get("id") if isinstance(mitre, dict) else None
                if isinstance(ids, list):
                    technique_ids.update(technique_id for technique_id in ids if isinstance(technique_id, str))

            offset += limit

        return technique_ids
