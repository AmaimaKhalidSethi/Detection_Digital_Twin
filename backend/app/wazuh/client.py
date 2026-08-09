from __future__ import annotations

import logging
import os
import re
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

    def run_logtest(self, log_input: str) -> dict | None:
        """Send a log sample to the Wazuh manager logtest endpoint and return a normalized result."""
        if not isinstance(log_input, str):
            raise TypeError("log_input must be a string")

        token = self.get_token()
        if token is None:
            raise RuntimeError("Wazuh authentication unavailable")
        if not self.base_url:
            raise RuntimeError("Wazuh base URL is not configured")

        url = f"{self.base_url.rstrip('/')}/logtest"
        candidate_payloads = [
            {"log": log_input},
            {"event": log_input},
            {"message": log_input},
            {"input": log_input},
        ]
        last_error: Exception | None = None

        for payload in candidate_payloads:
            try:
                response = requests.post(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    json=payload,
                    verify=False,
                    timeout=10,
                )
                if response.status_code == 401:
                    raise RuntimeError("Wazuh authentication failed")
                response.raise_for_status()

                if not response.content:
                    return {"matched": False}

                try:
                    data = response.json()
                except ValueError:
                    return {"matched": False, "message": response.text.strip() or "empty response"}

                if isinstance(data, dict):
                    if "data" in data and isinstance(data["data"], dict):
                        return data["data"]
                    return data

                return {"matched": bool(data)}
            except requests.exceptions.RequestException as exc:
                last_error = exc
            except RuntimeError as exc:
                last_error = exc

        raise RuntimeError("Wazuh logtest request failed") from last_error

    def _paged_request(self, path: str, params: dict[str, int | str] | None = None) -> list[dict] | None:
        token = self.get_token()
        if token is None:
            return None

        items: list[dict] = []
        offset = 0
        limit = 500
        total_affected_items: int | None = None
        params = params.copy() if params else {}

        while total_affected_items is None or offset < total_affected_items:
            params.update({"limit": limit, "offset": offset})
            try:
                response = requests.get(
                    f"{self.base_url.rstrip('/')}/{path.lstrip('/')}",
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                    verify=False,
                    timeout=10,
                )
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as exc:
                logger.warning("Wazuh %s request failed: %s", path, exc)
                return None
            except ValueError as exc:
                logger.warning("Wazuh %s response was not valid JSON: %s", path, exc)
                return None

            if isinstance(data, dict) and "data" in data:
                response_data = data["data"]
            else:
                response_data = data

            if isinstance(response_data, dict) and "affected_items" in response_data:
                batch = response_data.get("affected_items") or []
                total_affected_items = response_data.get("total_affected_items")
            elif isinstance(response_data, list):
                batch = response_data
                total_affected_items = len(batch)
            else:
                logger.warning("Wazuh %s response had an unexpected shape", path)
                return None

            if not isinstance(batch, list):
                logger.warning("Wazuh %s response batch was not a list", path)
                return None

            for item in batch:
                if isinstance(item, dict):
                    items.append(item)

            if total_affected_items is None:
                break
            offset += limit

        return items

    def get_agents(self) -> list[dict] | None:
        """Return the inventory of Wazuh agents."""
        return self._paged_request("agents")

    def get_rules(self) -> list[dict] | None:
        """Return the inventory of Wazuh rules."""
        return self._paged_request("rules")

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
                if isinstance(mitre, list):
                    technique_ids.update(
                        technique_id for technique_id in mitre
                        if isinstance(technique_id, str) and re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id)
                    )

            offset += limit

        return technique_ids
